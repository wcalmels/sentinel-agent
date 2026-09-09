"""
Sentinel-Agent Completo — Integrado con Efficient Orchestrator
==============================================================
Sistema de seguridad autónomo con orquestación inteligente.

Flujo completo:
  1. NetworkProfiler aprende el baseline del cliente (7 días)
  2. ThreatAnalyzer detecta anomalías vs ese baseline
  3. EfficientOrchestrator decide la respuesta:
       Nivel 0: phi gate         (0 tokens, <0.01ms)
       Nivel 1: reglas           (0 tokens, <1ms)
       Cache:   decisión similar (0 tokens, <0.1ms)
       Nivel 2: LLM Haiku/DS    (tokens, solo 5%)
  4. ResponseEngine ejecuta la acción
  5. SentinelMemory aprende con Nemosine

El LLM solo se usa para el ~5% de casos ambiguos.
El 95% se resuelve sin gastar un solo token.

Uso:
  # Demo (sin LLM real)
  python sentinel_agent_complete.py --demo

  # Con Claude Haiku (producción — modelo barato)
  ANTHROPIC_API_KEY=sk-... \\
  python sentinel_agent_complete.py --provider anthropic

  # Con Deepseek (alternativa barata)
  DEEPSEEK_API_KEY=... \\
  python sentinel_agent_complete.py --provider deepseek

  # Con Ollama (gratis, local)
  python sentinel_agent_complete.py --provider ollama

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, json, time, math, threading, hashlib, socket
import urllib.request
from datetime import datetime, timezone
from collections import deque, defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phi47_base import PhiField, Welford, PHI, PHI_MIN, VERSION
from efficient_orchestrator import EfficientOrchestrator, Decision
from ecosystem_connector import EcosystemConnector

PORT = int(os.environ.get("PORT", 5070))


# ══════════════════════════════════════════════════
# NETWORK PROFILER
# ══════════════════════════════════════════════════

class NetworkProfiler:
    """Aprende el baseline de tráfico específico del cliente."""

    LEARNING_DAYS   = 7
    MAX_TRUSTED_IPS = 500

    def __init__(self, client_id: str, phi: PhiField):
        self.client_id   = client_id
        self._phi        = phi
        self._raw        = deque(maxlen=10000)
        self._hourly     = defaultdict(list)
        self._trusted    : List[str] = []
        self._ports      : List[int] = []
        self._welford    = Welford()
        self._lock       = threading.Lock()
        self._ready      = False
        self._days       = 0

    def observe(self, ip: str, port: int, bytes_conn: int,
                ts: float = None):
        ts = ts or time.time()
        hour = datetime.fromtimestamp(ts).hour
        with self._lock:
            self._raw.append({"ip": ip, "port": port,
                              "bytes": bytes_conn, "ts": ts, "hour": hour})
            self._hourly[hour].append(1)
            self._welford.update(bytes_conn)
            # Aprender IPs de confianza
            if ip not in self._trusted:
                count = sum(1 for d in self._raw if d["ip"] == ip)
                if count >= 10:
                    self._trusted.append(ip)
                    if len(self._trusted) > self.MAX_TRUSTED_IPS:
                        self._trusted.pop(0)
            # Aprender puertos normales
            if port not in self._ports:
                count = sum(1 for d in self._raw if d["port"] == port)
                if count >= 5:
                    self._ports.append(port)

    def refresh(self):
        """Actualiza métricas estadísticas del perfil."""
        with self._lock:
            if not self._raw:
                return
            first = self._raw[0]["ts"]
            last  = self._raw[-1]["ts"]
            self._days  = (last - first) / 86400
            self._ready = self._days >= self.LEARNING_DAYS

    def is_anomalous(self, ip: str, port: int,
                     bytes_conn: int, hour: int
                     ) -> Tuple[bool, float, str]:
        if not self._ready:
            return False, 0.0, "learning"

        reasons = []
        score   = 0.0

        if ip not in self._trusted:
            score += 0.25; reasons.append(f"IP desconocida:{ip}")
        if port not in self._ports:
            score += 0.20; reasons.append(f"Puerto inusual:{port}")
        if 2 <= hour <= 5:
            score += 0.15; reasons.append(f"Madrugada:{hour}h")

        # Bytes anómalos (Welford)
        mean = self._welford.mean
        std  = self._welford.std
        if mean > 0 and bytes_conn > mean + 3 * std:
            score += 0.25; reasons.append(f"Bytes anómalos:{bytes_conn}")

        is_anom = score >= 0.35
        return is_anom, round(score, 3), " | ".join(reasons) or "normal"

    @property
    def ready(self) -> bool: return self._ready

    def status(self) -> Dict:
        return {
            "client_id":   self.client_id,
            "ready":       self._ready,
            "days":        round(self._days, 1),
            "trusted_ips": len(self._trusted),
            "ports":       len(self._ports),
            "observations":len(self._raw),
            "avg_bytes":   round(self._welford.mean, 1),
        }


# ══════════════════════════════════════════════════
# THREAT ANALYZER
# ══════════════════════════════════════════════════

@dataclass
class ThreatEvent:
    event_id:      str
    ts:            str
    client_id:     str
    threat_type:   str
    severity:      str
    ip:            str
    port:          int
    details:       Dict
    anomaly_score: float
    phi_at_event:  float
    pattern:       str = ""


class ThreatAnalyzer:
    """Detecta amenazas combinando IOCs + anomalías + comportamiento."""

    IOC_RANGES = [
        "5.199.174.", "37.120.131.", "45.63.49.",
        "185.220.101.", "94.23.247.", "103.116.52.",
        "194.165.16.", "45.153.243.",
    ]
    MALICIOUS_PORTS = {4444, 1337, 31337, 6667, 9001, 9030}

    def __init__(self, profiler: NetworkProfiler, phi: PhiField):
        self._profiler = profiler
        self._phi      = phi
        self._events   = deque(maxlen=1000)
        self._ip_hist  : Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100))

    def analyze(self, ip: str, port: int,
                bytes_conn: int, direction: str = "out"
                ) -> Optional[ThreatEvent]:
        ts   = datetime.now(timezone.utc).isoformat()
        hour = datetime.now().hour

        # Registrar en historial de IP
        self._ip_hist[ip].append({
            "ts": time.time(), "port": port, "bytes": bytes_conn
        })

        # 1. IOC conocido
        ioc = self._check_ioc(ip, port)
        if ioc:
            ev = self._make("IOC", "CRITICAL", ip, port,
                           {"ioc": ioc}, 1.0, "", ts)
            self._phi.degrade(0.20)
            self._events.appendleft(ev)
            return ev

        # 2. Anomalía vs baseline
        is_anom, score, reason = self._profiler.is_anomalous(
            ip, port, bytes_conn, hour)
        if is_anom:
            sev    = ("CRITICAL" if score > 0.8 else
                      "HIGH"     if score > 0.6 else
                      "MEDIUM"   if score > 0.4 else "LOW")
            impact = {"CRITICAL":0.15,"HIGH":0.10,"MEDIUM":0.05,"LOW":0.02}[sev]
            ev = self._make("ANOMALY", sev, ip, port,
                           {"reason": reason, "score": score}, score, "", ts)
            self._phi.degrade(impact)
            self._events.appendleft(ev)
            return ev

        # 3. Patrón de comportamiento
        pattern = self._check_pattern(ip)
        if pattern:
            ev = self._make("BEHAVIORAL", "HIGH", ip, port,
                           {"pattern": pattern}, 0.75, pattern, ts)
            self._phi.degrade(0.08)
            self._events.appendleft(ev)
            return ev

        # Normal — aprender
        self._profiler.observe(ip, port, bytes_conn)
        self._phi.boost(0.001)
        return None

    def _check_ioc(self, ip: str, port: int) -> Optional[str]:
        for prefix in self.IOC_RANGES:
            if ip.startswith(prefix):
                return f"ip_range:{prefix}"
        if port in self.MALICIOUS_PORTS:
            return f"malicious_port:{port}"
        return None

    def _check_pattern(self, ip: str) -> Optional[str]:
        hist = list(self._ip_hist[ip])
        if len(hist) < 3:
            return None
        intervals = [hist[i]["ts"]-hist[i-1]["ts"] for i in range(1,len(hist))]
        avg_int   = sum(intervals)/len(intervals)
        avg_bytes = sum(h["bytes"] for h in hist)/len(hist)
        if 30 <= avg_int <= 120 and avg_bytes < 1024:
            return "c2_beacon"
        if avg_bytes > 500*1024:
            return "data_exfil"
        win_ports = len(set(h["port"] for h in hist
                           if h["ts"] > time.time()-60))
        if win_ports > 20:
            return "port_scan"
        return None

    def _make(self, threat_type, severity, ip, port,
              details, score, pattern, ts) -> ThreatEvent:
        return ThreatEvent(
            event_id=hashlib.md5(f"{ts}{ip}{port}".encode()).hexdigest()[:12],
            ts=ts, client_id=self._profiler.client_id,
            threat_type=threat_type, severity=severity,
            ip=ip, port=port, details=details,
            anomaly_score=score, phi_at_event=round(self._phi.phi_global,4),
            pattern=pattern,
        )

    def recent(self, n=20, severity=None) -> List[Dict]:
        evs = list(self._events)
        if severity:
            evs = [e for e in evs if e.severity == severity]
        return [asdict(e) for e in evs[:n]]

    def stats(self) -> Dict:
        evs = list(self._events)
        return {
            "total":    len(evs),
            "critical": sum(1 for e in evs if e.severity=="CRITICAL"),
            "high":     sum(1 for e in evs if e.severity=="HIGH"),
            "medium":   sum(1 for e in evs if e.severity=="MEDIUM"),
        }


# ══════════════════════════════════════════════════
# SENTINEL MEMORY
# ══════════════════════════════════════════════════

class SentinelMemory:
    """Nemosine especializada en seguridad."""

    def __init__(self, client_id: str):
        self._client = client_id
        self._nem    = None
        self._fb     = deque(maxlen=500)
        # Buscar nemosine.py en el mismo directorio que este archivo
        _here = os.path.dirname(os.path.abspath(__file__))
        if _here not in sys.path:
            sys.path.insert(0, _here)
        try:
            from nemosine import Nemosine
            db = str(Path.home() / f"phi47_sentinel_{client_id}.db")
            self._nem = Nemosine(agent_id=f"sentinel_{client_id}", db_path=db)
            self._nem.begin_episode(f"session_{client_id}")
            print(f"  Nemosine: {self._nem.tier} | {self._nem.n_episodes} ep.")
        except Exception as e:
            print(f"  Nemosine: no disponible ({e.__class__.__name__}) — memoria volátil")

    def remember(self, event: ThreatEvent, action: str, phi: float):
        content = (f"{event.threat_type} {event.ip}:{event.port} "
                   f"sev={event.severity} score={event.anomaly_score:.2f} "
                   f"→{action}")
        if self._nem:
            self._nem.remember(content, phi=phi, mem_type="episodic",
                              tags=["threat", action.lower()])
        else:
            self._fb.append({"ts": event.ts, "content": content})

    def recall(self, ip: str, port: int) -> List[str]:
        if not self._nem:
            return []
        return [r["content"] for r in
                self._nem.recall(f"amenaza {ip} {port}", n=3)]

    def was_fp(self, ip: str) -> bool:
        if not self._nem:
            return False
        res = self._nem.recall(f"falso positivo {ip}", n=1,
                               mem_type="semantic")
        return bool(res and ip in res[0]["content"])

    def mark_fp(self, ip: str, context: str, phi: float):
        if self._nem:
            self._nem.remember(f"Falso positivo: {ip} — {context}",
                              phi=phi, mem_type="semantic",
                              tags=["false_positive"])

    def close(self, phi_end: float, lessons: List[str]):
        if self._nem:
            self._nem.end_episode("SUCCESS", phi_end=phi_end,
                                 lessons=lessons)

    def status(self) -> Dict:
        if self._nem:
            return self._nem.status()
        return {"mode": "volatile", "n": len(self._fb)}


# ══════════════════════════════════════════════════
# SENTINEL AGENT COMPLETO
# ══════════════════════════════════════════════════

class SentinelAgentComplete:
    """
    Agente de seguridad autónomo con orquestación inteligente.

    Integra:
      NetworkProfiler   → aprende baseline del cliente
      ThreatAnalyzer    → detecta anomalías
      EfficientOrch     → decide con mínimo costo LLM
      SentinelMemory    → Nemosine aprende y mejora

    El LLM solo se usa para el ~5% de casos ambiguos.
    """

    def __init__(self, client_id:   str = "demo_client",
                 provider:    str = "demo",
                 model:       str = None,
                 api_key:     str = None):
        self.client_id = client_id
        self._phi      = PhiField(n=12)
        self._profiler = NetworkProfiler(client_id, self._phi)
        self._analyzer = ThreatAnalyzer(self._profiler, self._phi)
        self._orch     = EfficientOrchestrator(
            self._phi, provider, model, api_key)
        self._memory   = SentinelMemory(client_id)
        self._blocked  : set = set()
        self._alerts   = deque(maxlen=500)
        self._start    = time.time()
        self._n_conn   = 0
        self._n_threat = 0
        self._n_block  = 0

        # Ecosystem connector — sincroniza con Railway
        self._ecosystem = EcosystemConnector(self)

        print(f"\n[SentinelAgent] Cliente: {client_id}")
        print(f"  Provider:  {provider} | Modelo: {model or 'default'}")
        print(f"  phi_global:{round(self._phi.phi_global,4)}")
        print(f"  Baseline:  {'listo' if self._profiler.ready else 'aprendiendo'}")

    def start(self):
        """Arranca el agente y conecta con el ecosistema phi47."""
        self._ecosystem.start()
        return self

    def process(self, ip: str, port: int,
                bytes_conn: int = 0,
                direction: str = "out") -> Optional[Dict]:
        """
        Procesa una conexión.
        Retorna alerta si es amenaza, None si es normal.
        """
        self._n_conn += 1

        # ¿IP previamente marcada como falso positivo?
        if self._memory.was_fp(ip):
            self._profiler.observe(ip, port, bytes_conn)
            return None

        # ¿IP bloqueada?
        if ip in self._blocked:
            return self._make_alert({
                "severity": "INFO",
                "threat_type": "BLOCKED_IP",
                "ip": ip, "port": port,
                "anomaly_score": 1.0,
                "pattern": "",
            }, "BLOCKED", "IP en blocklist", 0.99)

        # Analizar
        event = self._analyzer.analyze(ip, port, bytes_conn, direction)
        if not event:
            # Actualizar perfil periódicamente
            if self._n_conn % 200 == 0:
                self._profiler.refresh()
            return None

        self._n_threat += 1

        # Construir evento para el orquestador
        orch_event = {
            "event_id":     event.event_id,
            "severity":     event.severity,
            "threat_type":  event.threat_type,
            "ip":           event.ip,
            "port":         event.port,
            "anomaly_score":event.anomaly_score,
            "pattern":      event.pattern,
            "phi_global":   event.phi_at_event,
        }

        # Orquestar — 3 niveles, mínimo costo
        decision = self._orch.decide(orch_event)

        # Ejecutar acción
        if decision.action == "BLOCK":
            self._blocked.add(ip)
            self._n_block += 1
            self._call_firewall(ip)

        # Aprender en Nemosine
        self._memory.remember(event, decision.action,
                             self._phi.phi_global)

        # Construir alerta
        alert = self._make_alert(orch_event, decision.action,
                                decision.reason, decision.confidence,
                                level=decision.level,
                                tokens=decision.tokens_used,
                                latency=decision.latency_ms)
        self._alerts.appendleft(alert)
        self._print_alert(alert)
        return alert

    def _make_alert(self, event: Dict, action: str, reason: str,
                    confidence: float, level: int = 1,
                    tokens: int = 0, latency: float = 0.0) -> Dict:
        return {
            "ts":          datetime.now(timezone.utc).isoformat(),
            "event_id":    event.get("event_id", ""),
            "severity":    event.get("severity", ""),
            "threat_type": event.get("threat_type", ""),
            "ip":          event.get("ip", ""),
            "port":        event.get("port", 0),
            "score":       event.get("anomaly_score", 0),
            "action":      action,
            "reason":      reason,
            "confidence":  confidence,
            "orch_level":  level,
            "tokens_used": tokens,
            "latency_ms":  latency,
            "phi":         round(self._phi.phi_global, 4),
        }

    def _print_alert(self, a: Dict):
        icons = {"CRITICAL":"🚨","HIGH":"⚠","MEDIUM":"ℹ","LOW":"·","INFO":"·"}
        icon  = icons.get(a["severity"], "•")
        lvl   = {0:"φ",1:"R",2:"LLM"}.get(a["orch_level"],"?")
        ts    = a["ts"][-8:]
        print(f"  [{ts}][{lvl}] {icon} {a['severity']:8} "
              f"{a['ip']:20}:{a['port']:<5} → {a['action']:7} "
              f"conf={a['confidence']:.2f} "
              f"tokens={a['tokens_used']} "
              f"lat={a['latency_ms']:.1f}ms")

    def _call_firewall(self, ip: str):
        fw = os.environ.get("FIREWALL_URL", "http://localhost:5053")
        try:
            data = json.dumps({"ip":ip,"reason":"sentinel"}).encode()
            req  = urllib.request.Request(
                fw+"/block", data=data,
                headers={"Content-Type":"application/json"})
            urllib.request.urlopen(req, timeout=2)
        except Exception:
            pass

    def mark_false_positive(self, event_id: str,
                             ip: str = "", context: str = "") -> bool:
        self._memory.mark_fp(ip, context, self._phi.phi_global)
        self._blocked.discard(ip)
        return True

    def simulate(self, n: int = 100) -> List[Dict]:
        """Simula tráfico mezclando normal con amenazas."""
        import random; random.seed(42)
        normal_ips   = [f"10.0.{i//20}.{i%20+1}" for i in range(40)]
        normal_ips  += ["8.8.8.8","1.1.1.1","8.8.4.4"]
        normal_ports = [80, 443, 22, 3306, 5432, 8080, 8443]
        bad_ips      = ["5.199.174.88","185.220.101.55","94.23.247.10"]

        alerts = []
        for _ in range(n):
            if random.random() < 0.05:
                ip   = random.choice(bad_ips)
                port = random.choice([4444,1337,6667,443])
            else:
                ip   = random.choice(normal_ips)
                port = random.choice(normal_ports)
            alert = self.process(ip, port, random.randint(100,100000))
            if alert:
                alerts.append(alert)

        self._profiler.refresh()
        return alerts

    def report(self) -> Dict:
        """Informe completo del agente."""
        phi_hist  = list(self._phi.history)[-168:]
        avg_phi   = sum(phi_hist)/len(phi_hist) if phi_hist else PHI_MIN
        eff       = self._orch.efficiency()
        lessons   = []
        if self._n_threat > 0:
            llm_pct = eff["llm_pct"]
            lessons.append(
                f"{self._n_conn} conexiones | "
                f"{self._n_threat} amenazas | "
                f"{self._n_block} bloqueadas | "
                f"LLM usado en {llm_pct}% de casos")
        self._memory.close(self._phi.phi_global, lessons)
        return {
            "client_id":      self.client_id,
            "phi_avg":        round(avg_phi, 4),
            "phi_current":    round(self._phi.phi_global, 4),
            "connections":    self._n_conn,
            "threats":        self._n_threat,
            "blocked":        self._n_block,
            "blocked_ips":    list(self._blocked),
            "analyzer":       self._analyzer.stats(),
            "orchestrator":   eff,
            "profiler":       self._profiler.status(),
            "memory":         self._memory.status(),
            "lessons":        lessons,
        }

    def status(self) -> Dict:
        phi = self._phi.phi_global
        eff = self._orch.efficiency()
        return {
            "version":     VERSION,
            "client_id":   self.client_id,
            "phi_global":  round(phi, 4),
            "health":      round(self._phi.health, 4),
            "coherent":    phi > PHI_MIN,
            "uptime_s":    round(time.time()-self._start, 1),
            "connections": self._n_conn,
            "threats":     self._n_threat,
            "blocked":     self._n_block,
            "baseline":    self._profiler.ready,
            "blocked_ips": list(self._blocked)[:10],
            "orch_efficiency": {
                "llm_pct":     eff["llm_pct"],
                "target_met":  eff["target_met"],
                "tokens_total":eff["tokens_total"],
            },
            "phi_history": [round(h,4) for h in
                           list(self._phi.history)[-50:]],
            "ecosystem":   self._ecosystem.status(),
        }


# ══════════════════════════════════════════════════
# FLASK API
# ══════════════════════════════════════════════════

def create_api(agent: SentinelAgentComplete):
    from flask import Flask, jsonify, request, Response
    from flask_cors import CORS
    import json as _j

    app = Flask(__name__)
    CORS(app)

    # Start ecosystem connector
    agent._ecosystem.start()

    @app.route('/')
    def root():
        return jsonify({
            "system":    "phi47 Sentinel-Agent",
            "version":   VERSION,
            "client":    agent.client_id,
            "phi":       round(agent._phi.phi_global, 4),
            "ecosystem": agent._ecosystem.status()["online"],
        })

    @app.route('/health')
    def health():
        phi = agent._phi.phi_global
        return jsonify({
            "ok": True, "phi": round(phi,4),
            "coherent": phi > PHI_MIN,
            "baseline": agent._profiler.ready,
        })

    @app.route('/status')
    def status():
        return jsonify(agent.status())

    @app.route('/analyze', methods=['POST'])
    def analyze():
        d   = request.get_json() or {}
        ip  = d.get('ip','')
        if not ip:
            return jsonify({"error":"ip required"}), 400
        alert = agent.process(
            ip, int(d.get('port',0)),
            int(d.get('bytes',0)),
            d.get('direction','out'),
        )
        return jsonify({
            "alert": alert,
            "phi":   round(agent._phi.phi_global, 4),
        })

    @app.route('/alerts')
    def alerts():
        n   = min(int(request.args.get('n',20)), 100)
        sev = request.args.get('severity')
        return jsonify({
            "alerts": agent._analyzer.recent(n, sev),
            "total":  agent._n_threat,
        })

    @app.route('/simulate', methods=['POST'])
    def simulate():
        d = request.get_json() or {}
        n = min(int(d.get('n', 100)), 1000)
        alerts = agent.simulate(n)
        eff    = agent._orch.efficiency()
        return jsonify({
            "simulated":    n,
            "threats":      len(alerts),
            "alerts":       alerts[:5],
            "phi":          round(agent._phi.phi_global, 4),
            "llm_pct":      eff["llm_pct"],
            "target_met":   eff["target_met"],
            "tokens_used":  eff["tokens_total"],
        })

    @app.route('/block', methods=['POST'])
    def block():
        d  = request.get_json() or {}
        ip = d.get('ip','')
        if not ip: return jsonify({"error":"ip required"}), 400
        agent._blocked.add(ip)
        return jsonify({"ok":True,"ip":ip})

    @app.route('/unblock', methods=['POST'])
    def unblock():
        d  = request.get_json() or {}
        ip = d.get('ip','')
        agent._blocked.discard(ip)
        return jsonify({"ok":True,"ip":ip})

    @app.route('/false-positive', methods=['POST'])
    def false_positive():
        d = request.get_json() or {}
        ok = agent.mark_false_positive(
            d.get('event_id',''), d.get('ip',''), d.get('context',''))
        return jsonify({"ok": ok})

    @app.route('/report')
    def report():
        return jsonify(agent.report())

    @app.route('/efficiency')
    def efficiency():
        return jsonify(agent._orch.efficiency())

    @app.route('/profile')
    def profile():
        return jsonify({
            **agent._profiler.status(),
            "trusted_sample": agent._profiler._trusted[:10],
            "ports":          agent._profiler._ports[:20],
        })

    @app.route('/ecosystem')
    def ecosystem():
        return jsonify(agent._ecosystem.status())

    @app.route('/stream')
    def stream():
        def gen():
            last = 0.0
            while True:
                new = [a for a in list(agent._alerts)
                       if _j.loads(a["ts"]
                          if isinstance(a["ts"],str) else 'null') or
                       True]
                data = {
                    "phi":     round(agent._phi.phi_global, 4),
                    "threats": agent._n_threat,
                    "blocked": agent._n_block,
                    "alerts":  list(agent._alerts)[:3],
                    "orch_eff":agent._orch.efficiency()["llm_pct"],
                }
                yield f"data: {_j.dumps(data)}\n\n"
                time.sleep(2)
        return Response(gen(), mimetype='text/event-stream',
                       headers={"Cache-Control":"no-cache"})

    return app


# ── Main ──────────────────────────────────────────
if __name__ == "__main__":
    import argparse, signal

    parser = argparse.ArgumentParser(
        description="phi47 Sentinel-Agent — Seguridad autónoma con LLM eficiente"
    )
    parser.add_argument("--client",   default="demo_client")
    parser.add_argument("--provider", default="demo",
                        choices=["anthropic","openai","deepseek","ollama","demo"])
    parser.add_argument("--model",    default=None,
                        help="Dejar vacío para usar el modelo más barato disponible")
    parser.add_argument("--api-key",  default=None)
    parser.add_argument("--port",     type=int, default=PORT)
    parser.add_argument("--demo",     action="store_true",
                        help="Simular 200 conexiones y mostrar reporte")
    args = parser.parse_args()

    agent = SentinelAgentComplete(
        client_id=args.client,
        provider=args.provider,
        model=args.model,
        api_key=args.api_key,
    )

    if args.demo:
        print("\n── Simulando 200 conexiones ──\n")
        alerts = agent.simulate(200)
        rep    = agent.report()
        eff    = rep["orchestrator"]
        print(f"\n{'═'*55}")
        print(f"  REPORTE — {args.client}")
        print(f"{'═'*55}")
        print(f"  Conexiones:    {rep['connections']}")
        print(f"  Amenazas:      {rep['threats']}")
        print(f"  Bloqueadas:    {rep['blocked']}")
        print(f"  phi_global:    {rep['phi_current']}")
        print(f"{'─'*55}")
        print(f"  ORQUESTADOR — eficiencia")
        print(f"  phi-gate:      {eff['level_0']} eventos")
        print(f"  reglas:        {eff['level_1']} eventos")
        print(f"  cache:         {eff['cached']} eventos")
        print(f"  LLM:           {eff['level_2_llm']} eventos ({eff['llm_pct']}%)")
        print(f"  Tokens totales:{eff['tokens_total']}")
        print(f"  Objetivo < 5%: {'✓ CUMPLIDO' if eff['target_met'] else '✗'}")
        print(f"{'═'*55}")
        sys.exit(0)

    def shutdown(sig, frame):
        print("\n[SentinelAgent] Cerrando sesión...")
        rep = agent.report()
        print(f"  Conexiones: {rep['connections']} | "
              f"Amenazas: {rep['threats']} | "
              f"LLM: {rep['orchestrator']['llm_pct']}%")
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)

    app = create_api(agent)
    print(f"\nAPI: http://127.0.0.1:{args.port}")
    print(f"  POST /analyze  {{'ip':'1.2.3.4','port':443}}")
    print(f"  POST /simulate {{'n':200}}")
    print(f"  GET  /efficiency")
    print(f"  GET  /report\n")
    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)
