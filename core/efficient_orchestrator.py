"""
Efficient Orchestrator — Módulo standalone
==========================================
Orquestador de 3 niveles integrable en Sentinel-Agent.
El LLM frontera solo se usa para el ~5% de casos ambiguos.

Importar:
    from efficient_orchestrator import EfficientOrchestrator

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, json, time, hashlib, re
import urllib.request
from collections import deque
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from phi47_base import PhiField, PHI, PHI_MIN, VERSION


# ── Decision ─────────────────────────────────────
@dataclass
class Decision:
    action:      str      # BLOCK / ALERT / MONITOR / NOTIFY / IGNORE
    reason:      str
    confidence:  float
    level:       int      # 0=phi_gate 1=rules 2=llm
    tokens_used: int   = 0
    latency_ms:  float = 0.0
    cached:      bool  = False


# ── Nivel 0: Phi Gate ─────────────────────────────
class PhiGate:
    """Primer filtro usando el campo phi. Costo: 0 tokens."""

    def __init__(self, phi_field: PhiField):
        self._phi = phi_field

    def evaluate(self, severity: str) -> Optional[Decision]:
        """
        Retorna decisión directa si el phi y la severidad
        permiten una respuesta sin más análisis.
        """
        phi = self._phi.phi_global

        # phi muy alto + severidad baja → ignorar, sistema sano
        if phi > PHI_MIN + 0.5 and severity == "LOW":
            return Decision(
                action="MONITOR",
                reason=f"phi_healthy:{phi:.3f}",
                confidence=0.75, level=0,
            )

        # phi coherente + INFO → ignorar
        if phi > PHI_MIN and severity == "INFO":
            return Decision(
                action="IGNORE",
                reason=f"phi_coherent_info:{phi:.3f}",
                confidence=0.85, level=0,
            )
        return None

    def should_use_llm(self, severity: str) -> bool:
        """¿El estado phi justifica usar el LLM?"""
        phi = self._phi.phi_global
        # Solo usar LLM si phi está degradado O severidad es alta
        return phi < PHI_MIN or severity in ("CRITICAL", "HIGH")


# ── Nivel 1: Reglas ───────────────────────────────
class RuleEngine:
    """Reglas deterministas. Costo: 0 tokens, <1ms."""

    KNOWN_IOC_RANGES = [
        "5.199.174.", "37.120.131.", "45.63.49.",
        "185.220.101.", "94.23.247.", "103.116.52.",
        "194.165.16.", "45.153.243.",
    ]

    MALICIOUS_PORTS = {
        4444: ("Meterpreter",    0.95),
        1337: ("Backdoor",       0.93),
        31337:("Elite backdoor", 0.95),
        6667: ("IRC botnet",     0.90),
        9001: ("Tor",            0.88),
        9030: ("Tor",            0.88),
    }

    def evaluate(self, event: Dict) -> Optional[Decision]:
        t0 = time.perf_counter()

        ip      = event.get("ip", "")
        port    = int(event.get("port", 0))
        pattern = event.get("pattern", "")
        sev     = event.get("severity", "")
        score   = float(event.get("anomaly_score", 0))

        # R1: IP en rango IOC conocido → BLOCK siempre
        for prefix in self.KNOWN_IOC_RANGES:
            if ip.startswith(prefix):
                return self._d("BLOCK",
                               f"IOC: rango {prefix}", 0.98, t0)

        # R2: Puerto malicioso conocido → BLOCK
        if port in self.MALICIOUS_PORTS:
            name, conf = self.MALICIOUS_PORTS[port]
            return self._d("BLOCK", f"Puerto malicioso: {port} ({name})",
                           conf, t0)

        # R3: Comportamientos de malware confirmados → BLOCK
        if pattern == "c2_beacon":
            return self._d("BLOCK", "C&C beacon", 0.92, t0)
        if pattern == "data_exfil":
            return self._d("BLOCK", "Exfiltración de datos", 0.90, t0)

        # R4: Port scan → ALERT (no bloquear aún)
        if pattern == "port_scan":
            return self._d("ALERT", "Port scan detectado", 0.88, t0)

        # R5: Anomalía crítica con score alto → BLOCK
        if sev == "CRITICAL" and score > 0.85:
            return self._d("BLOCK",
                           f"Anomalía crítica score={score:.2f}", 0.87, t0)

        # R6: Anomalía baja confirmada → MONITOR silencioso
        if sev == "LOW" and score < 0.30:
            return self._d("MONITOR", "Anomalía baja", 0.85, t0)

        # Sin regla aplicable — escalar
        return None

    def _d(self, action, reason, conf, t0) -> Decision:
        return Decision(
            action=action, reason=reason, confidence=conf, level=1,
            latency_ms=round((time.perf_counter() - t0) * 1000, 3),
        )


# ── Decision Cache ────────────────────────────────
class DecisionCache:
    """Cache de decisiones LLM. TTL: 1 hora."""

    TTL      = 3600
    MAX_SIZE = 500

    def __init__(self):
        self._store: Dict[str, Tuple[Decision, float]] = {}
        self.hits = 0; self.misses = 0

    def _key(self, event: Dict) -> str:
        port = int(event.get("port", 0))
        sig  = {
            "type":     event.get("threat_type", ""),
            "severity": event.get("severity", ""),
            "pattern":  event.get("pattern", ""),
            "port_cat": ("high" if port < 1024 else
                         "reg"  if port < 49152 else "dyn"),
        }
        return hashlib.md5(
            json.dumps(sig, sort_keys=True).encode()
        ).hexdigest()[:16]

    def get(self, event: Dict) -> Optional[Decision]:
        k = self._key(event)
        if k in self._store:
            d, ts = self._store[k]
            if time.time() - ts < self.TTL:
                self.hits += 1
                return Decision(
                    action=d.action,
                    reason=d.reason + " [cached]",
                    confidence=round(d.confidence * 0.95, 3),
                    level=d.level, tokens_used=0,
                    latency_ms=0.01, cached=True,
                )
            del self._store[k]
        self.misses += 1
        return None

    def set(self, event: Dict, decision: Decision):
        if len(self._store) >= self.MAX_SIZE:
            oldest = min(self._store.items(), key=lambda x: x[1][1])
            del self._store[oldest[0]]
        self._store[self._key(event)] = (decision, time.time())

    def stats(self) -> Dict:
        total = max(1, self.hits + self.misses)
        return {
            "size":     len(self._store),
            "hits":     self.hits,
            "misses":   self.misses,
            "hit_rate": round(self.hits / total, 3),
        }


# ── Nivel 2: LLM Frontera ─────────────────────────
class FrontierLLM:
    """
    LLM para casos ambiguos.
    Por defecto usa el modelo más barato disponible.
    """

    # Modelos optimizados para costo — suficientes para decisiones binarias
    DEFAULT_MODELS = {
        "anthropic": "claude-haiku-4-5",   # $0.25/M — 12x más barato que Sonnet
        "openai":    "gpt-4o-mini",         # $0.15/M
        "ollama":    "llama3.2:3b",         # $0 — local
        "deepseek":  "deepseek-chat",       # $0.27/M
    }

    # Prompt ultra-compacto — minimiza tokens de entrada
    PROMPT = (
        "Orquestador de seguridad phi47. "
        "Evento: tipo={type} severidad={sev} "
        "score={score:.2f} patrón={pattern} "
        "phi={phi:.3f}. "
        "Decidí: BLOCK/ALERT/MONITOR/IGNORE. "
        'JSON: {{"a":"ACCION","r":"razon","c":0.0-1.0}}'
    )

    def __init__(self, provider: str = "demo",
                 model: str = None,
                 api_key: str = None):
        self.provider = provider
        self.model    = model or self.DEFAULT_MODELS.get(provider, "")
        self.api_key  = (api_key or
                         os.environ.get("ANTHROPIC_API_KEY") or
                         os.environ.get("OPENAI_API_KEY") or
                         os.environ.get("DEEPSEEK_API_KEY", ""))
        self._calls   = 0
        self._tokens  = 0
        self._errors  = 0

    def decide(self, event: Dict,
               phi: float) -> Tuple[Decision, int]:
        t0     = time.perf_counter()
        prompt = self.PROMPT.format(
            type=event.get("threat_type", "?"),
            sev=event.get("severity", "?"),
            score=float(event.get("anomaly_score", 0)),
            pattern=event.get("pattern", "none"),
            phi=phi,
        )

        if self.provider == "demo":
            return self._demo(event, t0)

        try:
            raw    = self._call(prompt)
            tokens = raw.get("tokens", 0)
            self._calls  += 1
            self._tokens += tokens
            parsed = self._parse(raw.get("content", ""))
            return Decision(
                action=parsed.get("a", "MONITOR"),
                reason=parsed.get("r", "llm"),
                confidence=float(parsed.get("c", 0.75)),
                level=2, tokens_used=tokens,
                latency_ms=round((time.perf_counter()-t0)*1000, 1),
            ), tokens
        except Exception as e:
            self._errors += 1
            return Decision(
                action="ALERT",
                reason=f"llm_error_fallback:{str(e)[:30]}",
                confidence=0.55, level=2,
                latency_ms=round((time.perf_counter()-t0)*1000, 1),
            ), 0

    def _call(self, prompt: str) -> Dict:
        if self.provider == "anthropic":
            return self._anthropic(prompt)
        if self.provider == "openai":
            return self._openai(prompt)
        if self.provider == "deepseek":
            return self._deepseek(prompt)
        if self.provider == "ollama":
            return self._ollama(prompt)
        return {"content": "", "tokens": 0}

    def _anthropic(self, prompt: str) -> Dict:
        data = json.dumps({
            "model":      self.model,
            "max_tokens": 80,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=data,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
            })
        with urllib.request.urlopen(req, timeout=8) as r:
            b = json.loads(r.read())
        u = b.get("usage", {})
        return {
            "content": b["content"][0]["text"],
            "tokens":  u.get("input_tokens", 0) + u.get("output_tokens", 0),
        }

    def _openai(self, prompt: str) -> Dict:
        data = json.dumps({
            "model":      self.model,
            "max_tokens": 80,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions", data=data,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self.api_key}",
            })
        with urllib.request.urlopen(req, timeout=8) as r:
            b = json.loads(r.read())
        return {
            "content": b["choices"][0]["message"]["content"],
            "tokens":  b.get("usage", {}).get("total_tokens", 0),
        }

    def _deepseek(self, prompt: str) -> Dict:
        data = json.dumps({
            "model":      self.model,
            "max_tokens": 80,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.deepseek.com/v1/chat/completions", data=data,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self.api_key}",
            })
        with urllib.request.urlopen(req, timeout=10) as r:
            b = json.loads(r.read())
        return {
            "content": b["choices"][0]["message"]["content"],
            "tokens":  b.get("usage", {}).get("total_tokens", 0),
        }

    def _ollama(self, prompt: str) -> Dict:
        data = json.dumps({
            "model":   self.model,
            "messages":[{"role": "user", "content": prompt}],
            "stream":  False,
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/chat", data=data,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            b = json.loads(r.read())
        return {
            "content": b["message"]["content"],
            "tokens":  b.get("eval_count", 0),
        }

    def _demo(self, event: Dict, t0: float) -> Tuple[Decision, int]:
        sev   = event.get("severity", "LOW")
        score = float(event.get("anomaly_score", 0))
        action = ("BLOCK"   if sev == "CRITICAL" or score > 0.80 else
                  "ALERT"   if sev in ("HIGH", "MEDIUM") else
                  "MONITOR")
        return Decision(
            action=action,
            reason=f"demo:sev={sev},score={score:.2f}",
            confidence=0.70, level=2,
            latency_ms=round((time.perf_counter()-t0)*1000, 1),
        ), 0

    def _parse(self, content: str) -> Dict:
        for m in re.findall(r'\{[^}]+\}', content):
            try:
                return json.loads(m)
            except Exception:
                pass
        return {"a": "MONITOR", "r": "parse_error", "c": 0.60}

    def stats(self) -> Dict:
        # Costo estimado según provider
        costs = {
            "anthropic": (0.00025, 0.00125),  # haiku $/K tokens
            "openai":    (0.00015, 0.00060),  # gpt-4o-mini
            "deepseek":  (0.00027, 0.00110),
            "ollama":    (0.0,     0.0),
        }
        inp_rate, out_rate = costs.get(self.provider, (0.001, 0.002))
        return {
            "provider":    self.provider,
            "model":       self.model,
            "calls":       self._calls,
            "tokens":      self._tokens,
            "errors":      self._errors,
            "cost_usd_est":round(
                self._tokens * (inp_rate + out_rate) / 2, 6),
        }


# ── Efficient Orchestrator ─────────────────────────
class EfficientOrchestrator:
    """
    Orquestador de 3 niveles.
    Integrable directamente en SentinelAgent.
    """

    def __init__(self, phi_field: PhiField,
                 provider:  str = "demo",
                 model:     str = None,
                 api_key:   str = None):
        self.phi_field = phi_field
        self._gate     = PhiGate(phi_field)
        self._rules    = RuleEngine()
        self._cache    = DecisionCache()
        self._llm      = FrontierLLM(provider, model, api_key)
        self._history  = deque(maxlen=500)
        self._stats    = {
            "total": 0, "l0": 0, "l1": 0,
            "l2": 0, "cached": 0, "tokens": 0,
        }

    def decide(self, event: Dict) -> Decision:
        """Procesa un evento por los 3 niveles."""
        t0 = time.perf_counter()
        self._stats["total"] += 1
        severity = event.get("severity", "LOW")

        # Nivel 0 — phi gate
        d = self._gate.evaluate(severity)
        if d:
            self._stats["l0"] += 1
            return self._finalize(d, event, t0)

        # Nivel 1 — reglas
        d = self._rules.evaluate(event)
        if d:
            self._stats["l1"] += 1
            return self._finalize(d, event, t0)

        # Cache
        d = self._cache.get(event)
        if d:
            self._stats["cached"] += 1
            return self._finalize(d, event, t0)

        # Nivel 2 — LLM (solo casos verdaderamente ambiguos)
        self._stats["l2"] += 1
        d, tokens = self._llm.decide(event, self.phi_field.phi_global)
        self._stats["tokens"] += tokens
        self._cache.set(event, d)
        return self._finalize(d, event, t0)

    def _finalize(self, d: Decision,
                  event: Dict, t0: float) -> Decision:
        d.latency_ms = round((time.perf_counter()-t0)*1000, 3)
        self._history.appendleft({
            "ts":         __import__('datetime').datetime.utcnow().isoformat(),
            "event_id":   event.get("event_id", ""),
            "severity":   event.get("severity", ""),
            "action":     d.action,
            "confidence": d.confidence,
            "level":      d.level,
            "tokens":     d.tokens_used,
            "cached":     d.cached,
            "latency_ms": d.latency_ms,
        })
        return d

    def efficiency(self) -> Dict:
        total = max(1, self._stats["total"])
        llm_pct = round(self._stats["l2"] / total * 100, 1)
        return {
            "total":         self._stats["total"],
            "level_0":       self._stats["l0"],
            "level_1":       self._stats["l1"],
            "cached":        self._stats["cached"],
            "level_2_llm":   self._stats["l2"],
            "llm_pct":       llm_pct,
            "target_met":    llm_pct <= 5.0,
            "tokens_total":  self._stats["tokens"],
            "cache":         self._cache.stats(),
            "llm":           self._llm.stats(),
        }
