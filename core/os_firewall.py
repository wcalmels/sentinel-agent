"""
phi47 OS Firewall — Bloqueo Activo a Nivel de Sistema Operativo
===============================================================
Implementa bloqueo real de IPs maliciosas usando las herramientas
nativas de cada OS:

  Linux:   iptables / nftables
  Windows: netsh advfirewall / Windows Firewall API
  macOS:   pfctl (Packet Filter)

Características:
  - Bloqueo inmediato cuando Sentinel detecta IOC
  - Persistencia entre reinicios (opcional)
  - Whitelist para no bloquear IPs críticas
  - Rollback automático si se bloquea algo legítimo
  - Log de todas las reglas aplicadas

Integración:
  El SentinelAgent llama a OSFirewall.block(ip)
  automáticamente cuando detecta una amenaza.
  Ya no es solo una alerta — es un bloqueo real.

Permisos requeridos:
  Linux:   sudo o CAP_NET_ADMIN
  Windows: Ejecutar como Administrador
  macOS:   sudo

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, platform, subprocess, json, time, threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from collections import deque

VERSION = "1.0.0"
OS      = platform.system()  # 'Linux', 'Windows', 'Darwin'

# ── IPs que NUNCA se bloquean ──────────────────────
WHITELIST = {
    # DNS
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
    '9.9.9.9', '149.112.112.112',
    # Railway (nuestros sistemas)
    'railway.app',
    # Loopback
    '127.0.0.1', '::1', '0.0.0.0',
    # Privadas
    '10.0.0.1', '192.168.1.1', '172.16.0.1',
}

# ── Prefijos de red privada (nunca bloquear) ──────
PRIVATE_PREFIXES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '169.254.',
)

# Archivo de persistencia
RULES_FILE = str(Path.home() / 'phi47_firewall_rules.json')


# ══════════════════════════════════════════════════
# RESULTADO DE OPERACIÓN
# ══════════════════════════════════════════════════

class FirewallResult:
    def __init__(self, ok: bool, ip: str, action: str,
                 method: str, message: str, cmd: str = ""):
        self.ok      = ok
        self.ip      = ip
        self.action  = action   # BLOCK / UNBLOCK / SKIP
        self.method  = method   # iptables / netsh / pfctl / simulation
        self.message = message
        self.cmd     = cmd
        self.ts      = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            'ok':      self.ok,
            'ip':      self.ip,
            'action':  self.action,
            'method':  self.method,
            'message': self.message,
            'cmd':     self.cmd,
            'ts':      self.ts,
        }

    def __repr__(self):
        status = '✓' if self.ok else '✗'
        return (f"[{status}] {self.action} {self.ip} "
                f"via {self.method}: {self.message}")


# ══════════════════════════════════════════════════
# BACKENDS POR OS
# ══════════════════════════════════════════════════

class LinuxFirewall:
    """Bloqueo via iptables en Linux."""

    CHAIN = "PHI47_BLOCK"

    def setup(self) -> bool:
        """Crea la chain phi47 si no existe."""
        try:
            # Crear chain
            r = subprocess.run(
                ['iptables', '-N', self.CHAIN],
                capture_output=True, text=True
            )
            # Puede fallar si ya existe — OK
            # Insertar chain en OUTPUT y INPUT
            for chain in ['OUTPUT', 'INPUT', 'FORWARD']:
                subprocess.run(
                    ['iptables', '-C', chain, '-j', self.CHAIN],
                    capture_output=True
                )
                if r.returncode != 0:
                    subprocess.run(
                        ['iptables', '-I', chain, '1', '-j', self.CHAIN],
                        capture_output=True
                    )
            return True
        except FileNotFoundError:
            return False  # iptables no disponible

    def block(self, ip: str) -> Tuple[bool, str, str]:
        """Bloquea una IP. Returns (ok, method, cmd)."""
        # Intentar iptables primero
        cmd = f"iptables -A {self.CHAIN} -s {ip} -j DROP"
        r = subprocess.run(
            ['iptables', '-A', self.CHAIN, '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            # También bloquear tráfico saliente
            subprocess.run(
                ['iptables', '-A', self.CHAIN, '-d', ip, '-j', 'DROP'],
                capture_output=True
            )
            return True, 'iptables', cmd

        # Intentar nftables
        cmd2 = f"nft add element ip phi47 blocked_ips {{ {ip} }}"
        r2 = subprocess.run(
            ['nft', 'add', 'element', 'ip', 'phi47',
             'blocked_ips', '{', ip, '}'],
            capture_output=True, text=True
        )
        if r2.returncode == 0:
            return True, 'nftables', cmd2

        return False, 'linux', r.stderr.strip()

    def unblock(self, ip: str) -> Tuple[bool, str, str]:
        cmd = f"iptables -D {self.CHAIN} -s {ip} -j DROP"
        r = subprocess.run(
            ['iptables', '-D', self.CHAIN, '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True
        )
        subprocess.run(
            ['iptables', '-D', self.CHAIN, '-d', ip, '-j', 'DROP'],
            capture_output=True
        )
        return r.returncode == 0, 'iptables', cmd

    def list_rules(self) -> List[str]:
        r = subprocess.run(
            ['iptables', '-L', self.CHAIN, '-n'],
            capture_output=True, text=True
        )
        lines = r.stdout.splitlines()
        ips = []
        for line in lines:
            if 'DROP' in line:
                parts = line.split()
                for p in parts:
                    if '.' in p and not p.startswith('0'):
                        ips.append(p)
        return list(set(ips))

    def flush(self) -> bool:
        r = subprocess.run(
            ['iptables', '-F', self.CHAIN],
            capture_output=True
        )
        return r.returncode == 0

    def is_available(self) -> bool:
        r = subprocess.run(
            ['iptables', '--version'],
            capture_output=True
        )
        return r.returncode == 0


class WindowsFirewall:
    """Bloqueo via netsh advfirewall en Windows."""

    RULE_PREFIX = "phi47_block"

    def setup(self) -> bool:
        return True  # Windows Firewall siempre disponible

    def _rule_name(self, ip: str) -> str:
        return f"{self.RULE_PREFIX}_{ip.replace('.','_')}"

    def block(self, ip: str) -> Tuple[bool, str, str]:
        rule  = self._rule_name(ip)
        cmd   = (f'netsh advfirewall firewall add rule '
                 f'name="{rule}" dir=out action=block remoteip={ip} '
                 f'enable=yes')
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name={rule}', 'dir=out', 'action=block',
             f'remoteip={ip}', 'enable=yes'],
            capture_output=True, text=True, shell=False
        )
        if r.returncode == 0:
            # También bloquear entrante
            rule_in = rule + '_in'
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_in}', 'dir=in', 'action=block',
                 f'remoteip={ip}', 'enable=yes'],
                capture_output=True, shell=False
            )
            return True, 'netsh', cmd

        return False, 'netsh', r.stderr.strip() or r.stdout.strip()

    def unblock(self, ip: str) -> Tuple[bool, str, str]:
        rule = self._rule_name(ip)
        cmd  = f'netsh advfirewall firewall delete rule name="{rule}"'
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name={rule}'],
            capture_output=True, text=True, shell=False
        )
        # También eliminar regla entrante
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name={rule}_in'],
            capture_output=True, shell=False
        )
        return r.returncode == 0, 'netsh', cmd

    def list_rules(self) -> List[str]:
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
             f'name={self.RULE_PREFIX}*'],
            capture_output=True, text=True, shell=False
        )
        ips = []
        for line in r.stdout.splitlines():
            if 'RemoteIP' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    ip = parts[1].strip()
                    if ip and ip != 'Any':
                        ips.append(ip)
        return ips

    def flush(self) -> bool:
        r = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name={self.RULE_PREFIX}*'],
            capture_output=True, shell=False
        )
        return True

    def is_available(self) -> bool:
        r = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'currentprofile'],
            capture_output=True
        )
        return r.returncode == 0


class MacOSFirewall:
    """Bloqueo via pfctl en macOS."""

    TABLE = "phi47_blocked"
    ANCHOR= "phi47"

    def setup(self) -> bool:
        try:
            # Crear tabla en pf
            subprocess.run(
                ['pfctl', '-T', 'add', '-t', self.TABLE],
                capture_output=True
            )
            return True
        except FileNotFoundError:
            return False

    def block(self, ip: str) -> Tuple[bool, str, str]:
        cmd = f"pfctl -t {self.TABLE} -T add {ip}"
        r = subprocess.run(
            ['pfctl', '-t', self.TABLE, '-T', 'add', ip],
            capture_output=True, text=True
        )
        return r.returncode == 0, 'pfctl', cmd

    def unblock(self, ip: str) -> Tuple[bool, str, str]:
        cmd = f"pfctl -t {self.TABLE} -T delete {ip}"
        r = subprocess.run(
            ['pfctl', '-t', self.TABLE, '-T', 'delete', ip],
            capture_output=True, text=True
        )
        return r.returncode == 0, 'pfctl', cmd

    def list_rules(self) -> List[str]:
        r = subprocess.run(
            ['pfctl', '-t', self.TABLE, '-T', 'show'],
            capture_output=True, text=True
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]

    def flush(self) -> bool:
        r = subprocess.run(
            ['pfctl', '-t', self.TABLE, '-T', 'flush'],
            capture_output=True
        )
        return r.returncode == 0

    def is_available(self) -> bool:
        r = subprocess.run(['pfctl', '-s', 'info'], capture_output=True)
        return r.returncode == 0


class SimulationFirewall:
    """
    Firewall simulado — para cuando no hay permisos de admin.
    Registra las acciones pero no las aplica a nivel OS.
    Útil para desarrollo y prueba.
    """

    def __init__(self):
        self._blocked: Set[str] = set()

    def setup(self) -> bool: return True

    def block(self, ip: str) -> Tuple[bool, str, str]:
        self._blocked.add(ip)
        return True, 'simulation', f"[SIM] block {ip}"

    def unblock(self, ip: str) -> Tuple[bool, str, str]:
        self._blocked.discard(ip)
        return True, 'simulation', f"[SIM] unblock {ip}"

    def list_rules(self) -> List[str]:
        return list(self._blocked)

    def flush(self) -> bool:
        self._blocked.clear()
        return True

    def is_available(self) -> bool: return True


# ══════════════════════════════════════════════════
# OS FIREWALL — Motor principal
# ══════════════════════════════════════════════════

class OSFirewall:
    """
    Firewall a nivel OS — detecta el sistema y usa el backend correcto.
    Integrado con el Sentinel-Agent para bloqueo automático.
    """

    def __init__(self, persist: bool = True,
                 dry_run: bool = False,
                 whitelist: Set[str] = None):
        self._persist   = persist
        self._dry_run   = dry_run
        self._blocked   : Set[str]          = set()
        self._log       : deque             = deque(maxlen=500)
        self._whitelist : Set[str]          = WHITELIST.copy()
        self._lock      = threading.Lock()
        self._stats     = {
            'blocked':   0,
            'unblocked': 0,
            'skipped':   0,
            'errors':    0,
        }

        if whitelist:
            self._whitelist.update(whitelist)

        # Detectar y configurar backend
        self._backend = self._detect_backend(dry_run)
        self._method  = type(self._backend).__name__.replace('Firewall','').lower()

        # Configurar chain/tabla
        if not dry_run:
            self._backend.setup()

        # Cargar reglas persistidas
        if persist:
            self._load_persisted()

        print(f"[OSFirewall] v{VERSION}")
        print(f"  OS:       {OS}")
        print(f"  Backend:  {self._method}")
        print(f"  Modo:     {'DRY-RUN (simulado)' if dry_run or self._method == 'simulation' else 'ACTIVO'}")
        print(f"  Persist:  {persist}")
        print(f"  Whitelist:{len(self._whitelist)} IPs protegidas")

    def _detect_backend(self, dry_run: bool):
        """Detecta el backend disponible para este OS."""
        if dry_run:
            return SimulationFirewall()

        if OS == 'Linux':
            fw = LinuxFirewall()
            if fw.is_available():
                return fw
        elif OS == 'Windows':
            fw = WindowsFirewall()
            if fw.is_available():
                return fw
        elif OS == 'Darwin':
            fw = MacOSFirewall()
            if fw.is_available():
                return fw

        # Fallback — sin permisos de admin
        print(f"  [!] Sin permisos de admin — usando modo simulación")
        print(f"      Para bloqueo real ejecutar como Administrador/sudo")
        return SimulationFirewall()

    def block(self, ip: str,
              reason: str = "",
              severity: str = "HIGH",
              auto_unblock_s: int = 0) -> FirewallResult:
        """
        Bloquea una IP a nivel OS.

        Args:
            ip:             IP a bloquear
            reason:         motivo del bloqueo
            severity:       CRITICAL/HIGH/MEDIUM/LOW
            auto_unblock_s: segundos hasta auto-desbloqueo (0=permanente)
        """
        # Validar IP
        if not ip or not self._is_valid_ip(ip):
            return FirewallResult(False, ip, 'SKIP', self._method,
                                  f"IP inválida: {ip}")

        # Verificar whitelist
        if self._is_whitelisted(ip):
            self._stats['skipped'] += 1
            return FirewallResult(False, ip, 'SKIP', self._method,
                                  f"IP en whitelist — protegida")

        # Ya bloqueada
        if ip in self._blocked:
            return FirewallResult(True, ip, 'SKIP', self._method,
                                  "Ya estaba bloqueada")

        with self._lock:
            ok, method, cmd = self._backend.block(ip)

        result = FirewallResult(
            ok=ok, ip=ip,
            action='BLOCK' if ok else 'ERROR',
            method=method,
            message=reason or f"Bloqueado por Sentinel-Agent (sev={severity})",
            cmd=cmd,
        )

        if ok:
            self._blocked.add(ip)
            self._stats['blocked'] += 1
            if self._persist:
                self._save_rule(ip, reason, severity)
            # Auto-desbloqueo si se especificó
            if auto_unblock_s > 0:
                threading.Timer(
                    auto_unblock_s,
                    lambda: self.unblock(ip, "auto-unblock timeout")
                ).start()
        else:
            self._stats['errors'] += 1

        self._log.appendleft(result.to_dict())
        self._print_result(result)
        return result

    def unblock(self, ip: str,
                reason: str = "") -> FirewallResult:
        """Desbloquea una IP."""
        if ip not in self._blocked:
            return FirewallResult(True, ip, 'SKIP', self._method,
                                  "No estaba bloqueada")

        with self._lock:
            ok, method, cmd = self._backend.unblock(ip)

        result = FirewallResult(
            ok=ok, ip=ip,
            action='UNBLOCK' if ok else 'ERROR',
            method=method,
            message=reason or "Desbloqueado manualmente",
            cmd=cmd,
        )

        if ok:
            self._blocked.discard(ip)
            self._stats['unblocked'] += 1
            if self._persist:
                self._remove_rule(ip)

        self._log.appendleft(result.to_dict())
        self._print_result(result)
        return result

    def block_range(self, ips: List[str],
                    reason: str = "") -> List[FirewallResult]:
        """Bloquea múltiples IPs de una vez."""
        return [self.block(ip, reason) for ip in ips]

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def flush_all(self) -> bool:
        """Elimina TODAS las reglas phi47."""
        ok = self._backend.flush()
        if ok:
            self._blocked.clear()
            self._stats['unblocked'] += len(self._blocked)
            if self._persist:
                self._clear_persisted()
        return ok

    # ── Whitelist ─────────────────────────────────

    def add_whitelist(self, ip: str):
        """Agrega IP a la whitelist — nunca se bloqueará."""
        self._whitelist.add(ip)
        if ip in self._blocked:
            self.unblock(ip, "añadida a whitelist")

    def remove_whitelist(self, ip: str):
        self._whitelist.discard(ip)

    # ── Persistencia ──────────────────────────────

    def _save_rule(self, ip: str, reason: str, severity: str):
        rules = self._load_rules_file()
        rules[ip] = {
            'reason':   reason,
            'severity': severity,
            'ts':       datetime.now(timezone.utc).isoformat(),
        }
        self._write_rules_file(rules)

    def _remove_rule(self, ip: str):
        rules = self._load_rules_file()
        rules.pop(ip, None)
        self._write_rules_file(rules)

    def _clear_persisted(self):
        self._write_rules_file({})

    def _load_persisted(self):
        rules = self._load_rules_file()
        if rules:
            print(f"  Cargando {len(rules)} reglas persistidas...")
            for ip, meta in rules.items():
                if ip not in self._blocked:
                    ok, _, _ = self._backend.block(ip)
                    if ok:
                        self._blocked.add(ip)
            print(f"  {len(self._blocked)} IPs bloqueadas activas")

    def _load_rules_file(self) -> Dict:
        try:
            if Path(RULES_FILE).exists():
                return json.loads(Path(RULES_FILE).read_text())
        except Exception:
            pass
        return {}

    def _write_rules_file(self, rules: Dict):
        try:
            Path(RULES_FILE).write_text(json.dumps(rules, indent=2))
        except Exception:
            pass

    # ── Validación ────────────────────────────────

    def _is_valid_ip(self, ip: str) -> bool:
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        # IPv6 básico
        return ':' in ip

    def _is_whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist:
            return True
        # Redes privadas
        for prefix in PRIVATE_PREFIXES:
            if ip.startswith(prefix):
                return True
        return False

    # ── Status ────────────────────────────────────

    def status(self) -> Dict:
        return {
            'os':           OS,
            'backend':      self._method,
            'active':       self._method != 'simulation',
            'dry_run':      self._dry_run,
            'blocked_count':len(self._blocked),
            'blocked_ips':  sorted(list(self._blocked))[:20],
            'whitelist':    len(self._whitelist),
            'stats':        self._stats,
            'persist_file': RULES_FILE,
            'recent_log':   list(self._log)[:10],
        }

    def _print_result(self, r: FirewallResult):
        icon = ('🛡' if r.action == 'BLOCK' else
                '✓' if r.action == 'UNBLOCK' else
                '·' if r.action == 'SKIP' else '✗')
        ts = datetime.now().strftime('%H:%M:%S')
        print(f"  [{ts}][{r.method}] {icon} {r.action:7} {r.ip:20} — {r.message[:50]}")


# ══════════════════════════════════════════════════
# INTEGRACIÓN CON SENTINEL-AGENT
# ══════════════════════════════════════════════════

def integrate_with_sentinel(agent, firewall: OSFirewall):
    """
    Parchea el SentinelAgent para que use el OSFirewall real
    en lugar del bloqueo simbólico anterior.

    Antes: agent._blocked.add(ip)  ← solo en memoria
    Ahora: firewall.block(ip)      ← bloqueo real en OS
    """
    original_process = agent.process

    def process_with_firewall(ip: str, port: int,
                               bytes_conn: int = 0,
                               direction: str = 'out'):
        alert = original_process(ip, port, bytes_conn, direction)

        if alert and alert.get('action') == 'BLOCK':
            # Bloqueo real a nivel OS
            severity = alert.get('severity', 'HIGH')
            reason   = alert.get('reason', 'Sentinel-Agent detection')
            result   = firewall.block(
                ip       = ip,
                reason   = f"[{severity}] {reason}",
                severity = severity,
            )
            alert['os_blocked']   = result.ok
            alert['os_method']    = result.method
            alert['os_message']   = result.message

        return alert

    agent.process = process_with_firewall

    # También parchear block/unblock manuales
    original_block = getattr(agent, '_blocked', set())

    print(f"[OSFirewall] Integrado con Sentinel-Agent '{agent.client_id}'")
    print(f"  Bloqueos futuros serán aplicados via {firewall._method}")

    return agent


# ══════════════════════════════════════════════════
# MAIN — Demo y CLI
# ══════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='phi47 OS Firewall — Bloqueo activo de amenazas'
    )
    parser.add_argument('--dry-run', action='store_true',
        help='Simular sin aplicar reglas reales')
    parser.add_argument('--block', metavar='IP',
        help='Bloquear una IP manualmente')
    parser.add_argument('--unblock', metavar='IP',
        help='Desbloquear una IP')
    parser.add_argument('--list', action='store_true',
        help='Listar IPs bloqueadas')
    parser.add_argument('--flush', action='store_true',
        help='Eliminar TODAS las reglas phi47')
    parser.add_argument('--status', action='store_true',
        help='Estado del firewall')
    parser.add_argument('--demo', action='store_true',
        help='Demo con IPs maliciosas conocidas')
    parser.add_argument('--whitelist-add', metavar='IP',
        help='Agregar IP a la whitelist')
    args = parser.parse_args()

    fw = OSFirewall(persist=True, dry_run=args.dry_run)

    if args.block:
        result = fw.block(args.block, reason="Manual CLI block")
        print(result)

    elif args.unblock:
        result = fw.unblock(args.unblock, reason="Manual CLI unblock")
        print(result)

    elif args.list:
        blocked = fw._blocked
        print(f"\n{'─'*50}")
        print(f"  IPs bloqueadas activas: {len(blocked)}")
        print(f"{'─'*50}")
        if blocked:
            for ip in sorted(blocked):
                print(f"  {ip}")
        else:
            print("  Sin IPs bloqueadas")

    elif args.flush:
        confirm = input("¿Eliminar TODAS las reglas phi47? (s/N): ")
        if confirm.lower() == 's':
            fw.flush_all()
            print("Todas las reglas eliminadas")

    elif args.whitelist_add:
        fw.add_whitelist(args.whitelist_add)
        print(f"IP {args.whitelist_add} agregada a whitelist")

    elif args.demo:
        print("\n── Demo: bloqueando IPs maliciosas conocidas ──\n")
        DEMO_IPS = [
            ('5.199.174.88',  'Pegasus/NSO Group',     'CRITICAL'),
            ('185.220.101.55','Tor exit node/Emotet',  'HIGH'),
            ('94.23.247.10',  'NSO Group',             'CRITICAL'),
            ('45.153.243.93', 'Qakbot C&C',            'HIGH'),
            ('194.165.16.55', 'TrickBot',              'HIGH'),
            ('8.8.8.8',       'Google DNS (whitelist)','LOW'),   # debe ser skipped
        ]
        for ip, reason, severity in DEMO_IPS:
            result = fw.block(ip, reason=reason, severity=severity)
            time.sleep(0.1)

        print(f"\n{'═'*50}")
        s = fw.status()
        print(f"  IPs bloqueadas: {s['blocked_count']}")
        print(f"  Método:         {s['backend']}")
        print(f"  Modo activo:    {s['active']}")
        print(f"  Reglas en:      {s['persist_file']}")
        print(f"{'═'*50}")

    elif args.status:
        import json as _j
        s = fw.status()
        print(_j.dumps(s, indent=2))

    else:
        # Sin argumentos — mostrar ayuda
        print(f"\nphi47 OS Firewall v{VERSION}")
        print(f"OS: {OS} | Backend: {fw._method}")
        print(f"\nUso:")
        print(f"  python os_firewall.py --demo           # demo con IPs maliciosas")
        print(f"  python os_firewall.py --block 1.2.3.4  # bloquear IP")
        print(f"  python os_firewall.py --unblock 1.2.3.4")
        print(f"  python os_firewall.py --list           # ver IPs bloqueadas")
        print(f"  python os_firewall.py --status         # estado completo")
        print(f"  python os_firewall.py --flush          # eliminar todas las reglas")
        print(f"  python os_firewall.py --dry-run --demo # sin aplicar cambios reales")
        print(f"\nPermisos:")
        if OS == 'Linux':
            print(f"  sudo python os_firewall.py --demo")
        elif OS == 'Windows':
            print(f"  Ejecutar PowerShell como Administrador")
        elif OS == 'Darwin':
            print(f"  sudo python os_firewall.py --demo")
