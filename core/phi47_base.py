"""
phi47 Base — Constantes y componentes compartidos
==================================================
Módulo base que todos los componentes del sistema importan.
Evita duplicación de PhiField, constantes y Welford.

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import math, time, threading
from collections import deque
from typing import List, Optional

# ── Constantes phi47 ─────────────────────────────
PHI     = 1.6180339887498948
PHI_MIN = 0.618
GAMMA   = 89.44
VERSION = "1.0.0"


# ── Welford online statistics ────────────────────
class Welford:
    """Media y varianza online sin guardar todos los valores."""
    def __init__(self):
        self.n = 0; self.mean = 0.0; self.m2 = 0.0

    def update(self, x: float):
        self.n += 1
        d = x - self.mean; self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / self.n if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


# ── PhiField compartido ──────────────────────────
class PhiField:
    """
    Campo phi coherente.
    Usado por todos los componentes del sistema.
    """
    def __init__(self, n: int = 12):
        self.n       = n
        self.nodes   = [0.75] * n
        self.t       = 0.0
        self.history = deque(maxlen=500)
        self._lock   = threading.Lock()

    def tick(self, dt: float = 1.0) -> float:
        with self._lock:
            self.t += dt
            for i in range(self.n):
                base = 0.5 + 0.35 * math.sin(
                    GAMMA * self.t / 100 + i * 2 * math.pi * PHI / self.n)
                self.nodes[i] = 0.85 * self.nodes[i] + 0.15 * base
            phi = self._compute()
            self.history.append(phi)
            return phi

    def degrade(self, amount: float = 0.10,
                nodes: Optional[List[int]] = None):
        with self._lock:
            targets = nodes if nodes is not None else range(self.n)
            for i in targets:
                self.nodes[i] = max(0.05, self.nodes[i] - amount)

    def boost(self, amount: float = 0.03,
              nodes: Optional[List[int]] = None):
        with self._lock:
            targets = nodes if nodes is not None else range(self.n)
            for i in targets:
                self.nodes[i] = min(0.97, self.nodes[i] + amount)

    def _compute(self) -> float:
        mean = sum(self.nodes) / self.n
        if mean < 1e-9:
            return PHI_MIN
        var = sum((x - mean) ** 2 for x in self.nodes) / self.n
        return max(PHI_MIN - 0.2,
                   min(PHI, PHI_MIN + (1 - var / mean) * (PHI - PHI_MIN)))

    @property
    def phi_global(self) -> float:
        with self._lock:
            return self._compute()

    @property
    def health(self) -> float:
        return max(0.0, self.phi_global - PHI_MIN)

    @property
    def is_coherent(self) -> bool:
        return self.phi_global > PHI_MIN

    def snapshot(self) -> dict:
        phi = self.phi_global
        return {
            "phi_global": round(phi, 4),
            "health":     round(max(0, phi - PHI_MIN), 4),
            "coherent":   phi > PHI_MIN,
            "nodes":      [round(n, 4) for n in self.nodes],
            "history_50": [round(h, 4) for h in list(self.history)[-50:]],
        }
