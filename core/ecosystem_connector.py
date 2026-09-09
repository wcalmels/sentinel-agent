"""
Ecosystem Connector — Integración con el ecosistema phi47
==========================================================
Conecta el Sentinel-Agent con los sistemas en Railway:
  - Colmena:   lee phi_global y dominios
  - Sentinel:  sincroniza alertas y campo phi
  - Orchestrator: reporta eventos para coordinación

También expone el campo phi del Sentinel-Agent
al ecosistema para que el dashboard lo muestre.

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, json, time, threading
import urllib.request
from datetime import datetime, timezone
from collections import deque
from typing import Dict, Optional

# URLs del ecosistema — Railway en producción, localhost en dev
ECOSYSTEM = {
    "colmena":      os.environ.get("COLMENA_URL",
                    "https://web-production-3491b.up.railway.app"),
    "sentinel_api": os.environ.get("SENTINEL_URL",
                    "https://web-production-b6d8.up.railway.app"),
    "orchestrator": os.environ.get("ORCH_URL",
                    "http://localhost:5000"),
    "llm_orch":     os.environ.get("LLM_ORCH_URL",
                    "http://localhost:5001"),
}

POLL_INTERVAL = 30   # segundos entre polls
TIMEOUT       = 4    # segundos timeout por request


class EcosystemConnector:
    """
    Conecta el Sentinel-Agent al ecosistema phi47.
    Corre en background — no bloquea el agente.
    """

    def __init__(self, agent):
        self._agent   = agent
        self._online  = {k: False for k in ECOSYSTEM}
        self._phi_ext = {}     # phi de sistemas externos
        self._events  = deque(maxlen=100)
        self._thread  = None
        self._running = False

    def start(self):
        """Arranca la sincronización en background."""
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True)
        self._thread.start()
        print(f"[EcosystemConnector] Conectando con ecosistema phi47...")
        print(f"  Colmena:  {ECOSYSTEM['colmena']}")
        print(f"  Sentinel: {ECOSYSTEM['sentinel_api']}")

    def stop(self):
        self._running = False

    def _loop(self):
        """Loop de polling en background."""
        while self._running:
            self._poll_colmena()
            self._poll_sentinel_api()
            self._broadcast_phi()
            self._report_threats()
            time.sleep(POLL_INTERVAL)

    def _poll_colmena(self):
        """Lee el estado de Colmena."""
        data = self._get("colmena", "/health")
        if data:
            self._phi_ext["colmena"] = data.get(
                "global_phi", data.get("phi", 0))
            self._online["colmena"]  = True
        else:
            self._online["colmena"]  = False

    def _poll_sentinel_api(self):
        """Lee el estado del Sentinel en Railway."""
        data = self._get("sentinel_api", "/health")
        if data:
            self._phi_ext["sentinel_api"] = data.get("phi", 0)
            self._online["sentinel_api"]  = True

            # Si el Sentinel Railway tiene alertas nuevas,
            # las incorporamos a nuestra memoria
            alerts = self._get("sentinel_api", "/alerts?n=3")
            if alerts and alerts.get("alerts"):
                for alert in alerts["alerts"]:
                    level = alert.get("level","")
                    if level in ("CRITICAL","HIGH"):
                        self._agent._phi.degrade(0.02)
        else:
            self._online["sentinel_api"] = False

    def _broadcast_phi(self):
        """
        Reporta el phi del Sentinel-Agent al Orchestrator.
        Así el dashboard unificado puede mostrar todos los sistemas.
        """
        phi = self._agent._phi.phi_global
        self._post("orchestrator", "/phi", {
            "phi":     round(phi, 4),
            "system":  "sentinel_agent",
            "client":  self._agent.client_id,
        })

    def _report_threats(self):
        """
        Reporta amenazas recientes al LLM Orchestrator
        para que las incluya en su contexto de decisión.
        """
        recent = list(self._agent._alerts)[:3]
        if not recent:
            return
        critical = [a for a in recent if a.get("severity") == "CRITICAL"]
        if critical:
            self._post("llm_orch", "/decide", {
                "event_type": "SENTINEL_CRITICAL",
                "severity":   "CRITICAL",
                "threat_type":"IOC",
                "anomaly_score": 1.0,
                "source":     "sentinel_agent",
                "client":     self._agent.client_id,
                "phi_global": round(self._agent._phi.phi_global, 4),
            })

    def _get(self, system: str, path: str) -> Optional[Dict]:
        url = ECOSYSTEM.get(system, "") + path
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "phi47-sentinel-agent/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def _post(self, system: str, path: str, body: Dict) -> Optional[Dict]:
        url = ECOSYSTEM.get(system, "") + path
        try:
            data = json.dumps(body).encode()
            req  = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json",
                         "User-Agent": "phi47-sentinel-agent/1.0"},
                method="POST")
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def status(self) -> Dict:
        return {
            "online":   self._online,
            "phi_ext":  {k: round(v, 4) for k, v in self._phi_ext.items()},
            "urls":     ECOSYSTEM,
        }
