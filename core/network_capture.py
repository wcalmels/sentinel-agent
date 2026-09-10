"""
Network Capture — Monitor de Red Real con psutil
=================================================
Lee conexiones reales de la NIC del PC y las alimenta
al Sentinel-Agent para análisis.

Modos de operación:
  1. Local: alimenta directamente al SentinelAgentComplete
  2. Remote: envía conexiones al Sentinel-Agent en Railway via API

Lo que captura por conexión:
  - IP remota y puerto
  - Proceso dueño de la conexión (Chrome, Zoom, etc.)
  - Bytes enviados/recibidos (via psutil.net_io_counters)
  - Dirección (entrante/saliente)
  - Estado (ESTABLISHED, LISTEN, TIME_WAIT, etc.)

Lo que hace con cada conexión:
  - La pasa al analizador phi47
  - Si es amenaza: alerta + intento de bloqueo
  - Si es normal: aprende el baseline

Diferencia con la simulación:
  Simulación:  IPs inventadas, bytes random
  Este módulo: IPs reales de tu red, procesos reales

Instalación:
  pip install psutil

Uso:
  # Integrado con agente local
  python network_capture.py

  # Reportar a Railway
  python network_capture.py --remote https://sentinel-agent-production-0577.up.railway.app

  # Solo monitorear, sin análisis (debug)
  python network_capture.py --dry-run

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, sys, time, json, socket, threading, hashlib
import urllib.request
from datetime import datetime, timezone
from collections import deque, defaultdict
from typing import Dict, List, Optional, Set, Tuple

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    psutil = None
    PSUTIL_OK = False
    print("[NetworkCapture] psutil no disponible — captura desactivada")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Configuración ─────────────────────────────────
POLL_INTERVAL   = 10    # segundos entre capturas
BYTES_WINDOW    = 30    # segundos para calcular bytes/s
MAX_LOG         = 1000  # conexiones en memoria
IGNORE_PORTS    = {53, 67, 68, 5353, 5355}   # DNS, DHCP, mDNS
IGNORE_IPS      = {'127.0.0.1', '::1', '0.0.0.0'}  # loopback

# Procesos del sistema que son siempre confiables
SYSTEM_PROCS = {
    'svchost.exe', 'system', 'lsass.exe', 'winlogon.exe',
    'services.exe', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'ntoskrnl.exe', 'systemd', 'kernel', 'kworker',
}


# ══════════════════════════════════════════════════
# NETWORK PROFILER REAL
# ══════════════════════════════════════════════════

class ConnectionRecord:
    """Una conexión de red capturada."""
    __slots__ = ['ip','port','pid','process','direction',
                 'status','bytes_s','ts','event_id']

    def __init__(self, ip, port, pid, process, direction,
                 status, bytes_s=0):
        self.ip        = ip
        self.port      = port
        self.pid       = pid
        self.process   = process
        self.direction = direction
        self.status    = status
        self.bytes_s   = bytes_s
        self.ts        = datetime.now(timezone.utc).isoformat()
        self.event_id  = hashlib.md5(
            f"{ip}{port}{pid}{self.ts}".encode()
        ).hexdigest()[:10]

    def to_dict(self) -> Dict:
        return {
            'ip':        self.ip,
            'port':      self.port,
            'pid':       self.pid,
            'process':   self.process,
            'direction': self.direction,
            'status':    self.status,
            'bytes_s':   self.bytes_s,
            'ts':        self.ts,
            'event_id':  self.event_id,
        }


class NetworkCapture:
    """
    Captura conexiones reales de la NIC usando psutil.
    Las alimenta al Sentinel-Agent para análisis phi47.
    """

    def __init__(self, agent=None, remote_url: str = None,
                 dry_run: bool = False, api_key: str = None):
        self._agent      = agent       # SentinelAgentComplete (local)
        self._remote     = remote_url  # URL del Sentinel-Agent en Railway
        self._dry_run    = dry_run
        self._api_key    = api_key
        self._running    = False
        self._seen       = set()       # conexiones ya vistas en este poll
        self._log        = deque(maxlen=MAX_LOG)
        self._alerts     = deque(maxlen=200)
        self._n_captured = 0
        self._n_sent     = 0
        self._n_alerts   = 0
        self._start      = time.time()

        # Historial de bytes por interfaz (para calcular bytes/s)
        self._prev_io    = psutil.net_io_counters(pernic=True) if PSUTIL_OK else {}
        self._prev_ts    = time.time()

        # Cache de nombre de proceso por PID
        self._proc_cache : Dict[int, str] = {}

        print(f"[NetworkCapture] Iniciando...")
        print(f"  Modo:     {'DRY-RUN' if dry_run else 'ACTIVO'}")
        if remote_url:
            print(f"  Remote:   {remote_url}")
        elif agent:
            print(f"  Local:    SentinelAgent '{agent.client_id}'")
        print(f"  Intervalo:{POLL_INTERVAL}s")

    def start(self):
        """Arranca la captura en background."""
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("[NetworkCapture] Captura iniciada en background")
        return self

    def stop(self):
        self._running = False
        print("[NetworkCapture] Captura detenida")

    def _loop(self):
        """Loop principal de captura."""
        while self._running:
            try:
                self._poll()
            except Exception as e:
                print(f"[NetworkCapture] Error en poll: {e}")
            time.sleep(POLL_INTERVAL)

    def _poll(self):
        """Una captura de todas las conexiones activas."""
        if not PSUTIL_OK:
            return
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            # En Windows puede requerir admin
            try:
                connections = psutil.net_connections(kind='inet4')
            except Exception:
                return

        # Calcular bytes/s de las interfaces
        bytes_rate = self._calc_bytes_rate()

        new_conns = []
        seen_now  = set()

        for conn in connections:
            # Solo conexiones con IP remota establecidas
            if not conn.raddr:
                continue
            remote_ip   = conn.raddr.ip
            remote_port = conn.raddr.port

            # Filtrar loopback y puertos de sistema
            if remote_ip in IGNORE_IPS:
                continue
            if remote_port in IGNORE_PORTS:
                continue
            if remote_ip.startswith('169.254.'):  # APIPA
                continue

            # Determinar dirección
            direction = 'out'
            if conn.laddr and conn.laddr.port < 1024:
                direction = 'in'  # servidor recibiendo

            # Nombre del proceso
            proc_name = self._get_process(conn.pid)

            # Procesos del sistema → ignorar
            if proc_name.lower() in SYSTEM_PROCS:
                continue

            # Key única para esta conexión
            key = f"{remote_ip}:{remote_port}:{proc_name}"
            seen_now.add(key)

            # Solo procesar conexiones nuevas o cerradas
            if key not in self._seen:
                rec = ConnectionRecord(
                    ip=remote_ip,
                    port=remote_port,
                    pid=conn.pid or 0,
                    process=proc_name,
                    direction=direction,
                    status=conn.status or 'UNKNOWN',
                    bytes_s=bytes_rate,
                )
                new_conns.append(rec)
                self._log.appendleft(rec)
                self._n_captured += 1

        self._seen = seen_now

        # Enviar nuevas conexiones al agente
        for conn in new_conns:
            self._analyze(conn)

    def _analyze(self, conn: ConnectionRecord):
        """Envía una conexión al Sentinel-Agent para análisis."""
        if self._dry_run:
            print(f"  [DRY] {conn.process:20} → {conn.ip}:{conn.port}")
            return

        alert = None

        if self._agent:
            # Análisis local
            alert = self._agent.process(
                ip=conn.ip,
                port=conn.port,
                bytes_conn=int(conn.bytes_s),
                direction=conn.direction,
            )
            self._n_sent += 1

        elif self._remote:
            # Análisis remoto via API
            alert = self._send_remote(conn)
            self._n_sent += 1

        if alert:
            self._n_alerts += 1
            self._alerts.appendleft({**alert, 'process': conn.process})
            self._print_alert(conn, alert)

    def _send_remote(self, conn: ConnectionRecord) -> Optional[Dict]:
        """Envía la conexión al Sentinel-Agent remoto."""
        try:
            payload = json.dumps({
                'ip':        conn.ip,
                'port':      conn.port,
                'bytes':     int(conn.bytes_s),
                'direction': conn.direction,
            }).encode()

            headers = {'Content-Type': 'application/json'}
            if self._api_key:
                headers['Authorization'] = f'Bearer {self._api_key}'

            req = urllib.request.Request(
                self._remote + '/analyze',
                data=payload,
                headers=headers,
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
                return data.get('alert')
        except Exception:
            return None

    def _get_process(self, pid: Optional[int]) -> str:
        """Obtiene el nombre del proceso por PID con cache."""
        if not pid:
            return 'unknown'
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        if not PSUTIL_OK:
            return 'unknown'
        try:
            name = psutil.Process(pid).name()
            self._proc_cache[pid] = name
            # Limpiar cache si es muy grande
            if len(self._proc_cache) > 500:
                oldest = list(self._proc_cache.keys())[:100]
                for k in oldest:
                    del self._proc_cache[k]
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 'unknown'

    def _calc_bytes_rate(self) -> float:
        """Calcula bytes/s total de todas las interfaces."""
        if not PSUTIL_OK:
            return 0.0
        try:
            now_io = psutil.net_io_counters()
            now_ts = time.time()
            dt     = now_ts - self._prev_ts

            if dt > 0 and hasattr(self, '_prev_total'):
                total_now  = now_io.bytes_sent + now_io.bytes_recv
                rate       = (total_now - self._prev_total) / dt
                self._prev_total = total_now
                self._prev_ts    = now_ts
                return max(0.0, rate)

            total = now_io.bytes_sent + now_io.bytes_recv
            self._prev_total = total
            self._prev_ts    = now_ts
            return 0.0
        except Exception:
            return 0.0

    def _print_alert(self, conn: ConnectionRecord, alert: Dict):
        icons = {'CRITICAL':'🚨','HIGH':'⚠','MEDIUM':'ℹ','LOW':'·'}
        sev   = alert.get('severity','?')
        icon  = icons.get(sev, '•')
        ts    = datetime.now().strftime('%H:%M:%S')
        print(f"  [{ts}] {icon} {sev:8} "
              f"{conn.process:15} → {conn.ip}:{conn.port} "
              f"→ {alert.get('action','?')} "
              f"(score={alert.get('score',0):.2f})")

    def top_processes(self, n=10) -> List[Dict]:
        """Procesos con más conexiones externas."""
        counts = defaultdict(int)
        for rec in self._log:
            counts[rec.process] += 1
        return sorted(
            [{'process':k,'connections':v} for k,v in counts.items()],
            key=lambda x: x['connections'], reverse=True
        )[:n]

    def top_destinations(self, n=10) -> List[Dict]:
        """IPs más contactadas."""
        counts = defaultdict(int)
        for rec in self._log:
            counts[rec.ip] += 1
        return sorted(
            [{'ip':k,'count':v} for k,v in counts.items()],
            key=lambda x: x['count'], reverse=True
        )[:n]

    def recent_connections(self, n=20) -> List[Dict]:
        return [r.to_dict() for r in list(self._log)[:n]]

    def status(self) -> Dict:
        return {
            'running':       self._running,
            'uptime_s':      round(time.time()-self._start, 1),
            'captured':      self._n_captured,
            'sent_to_agent': self._n_sent,
            'alerts':        self._n_alerts,
            'mode':          'dry_run' if self._dry_run else
                             ('remote' if self._remote else 'local'),
            'remote_url':    self._remote,
            'recent_alerts': list(self._alerts)[:5],
            'top_processes': self.top_processes(5),
            'top_destinations': self.top_destinations(5),
        }

    def single_capture(self) -> List[Dict]:
        """
        Captura única síncrona — útil para debug.
        Retorna todas las conexiones activas en este momento.
        """
        if not PSUTIL_OK:
            return []
        try:
            connections = psutil.net_connections(kind='inet')
        except Exception:
            return []

        result = []
        for conn in connections:
            if not conn.raddr:
                continue
            ip   = conn.raddr.ip
            port = conn.raddr.port
            if ip in IGNORE_IPS or port in IGNORE_PORTS:
                continue
            proc = self._get_process(conn.pid)
            if proc.lower() in SYSTEM_PROCS:
                continue
            result.append({
                'ip':      ip,
                'port':    port,
                'process': proc,
                'status':  conn.status or 'UNKNOWN',
                'pid':     conn.pid,
            })

        return result


# ══════════════════════════════════════════════════
# FLASK API PARA EL CAPTURADOR
# ══════════════════════════════════════════════════

def create_capture_api(capture: NetworkCapture):
    """Expone el capturador como API REST."""
    from flask import Flask, jsonify, request
    from flask_cors import CORS

    app = Flask(__name__)
    CORS(app)

    @app.route('/')
    def root():
        return jsonify({
            'system':  'phi47 NetworkCapture',
            'version': '1.0.0',
            'running': capture._running,
        })

    @app.route('/status')
    def status():
        return jsonify(capture.status())

    @app.route('/connections')
    def connections():
        n = min(int(request.args.get('n', 20)), 100)
        return jsonify({
            'connections': capture.recent_connections(n),
            'total':       capture._n_captured,
        })

    @app.route('/connections/live')
    def live():
        """Captura síncrona en tiempo real."""
        return jsonify({
            'connections': capture.single_capture(),
            'ts':          datetime.now(timezone.utc).isoformat(),
        })

    @app.route('/top/processes')
    def top_procs():
        return jsonify({'processes': capture.top_processes(10)})

    @app.route('/top/destinations')
    def top_dests():
        return jsonify({'destinations': capture.top_destinations(10)})

    @app.route('/alerts')
    def alerts():
        return jsonify({
            'alerts': list(capture._alerts)[:20],
            'total':  capture._n_alerts,
        })

    return app


# ══════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse, signal

    parser = argparse.ArgumentParser(
        description='phi47 NetworkCapture — Monitor de Red Real'
    )
    parser.add_argument('--remote', default=None,
        help='URL del Sentinel-Agent remoto (Railway)')
    parser.add_argument('--api-key', default=None,
        help='API key del Sentinel-Agent')
    parser.add_argument('--dry-run', action='store_true',
        help='Solo mostrar conexiones, sin análisis')
    parser.add_argument('--local', action='store_true',
        help='Usar Sentinel-Agent local (importar)')
    parser.add_argument('--port', type=int, default=5080,
        help='Puerto de la API del capturador (default: 5080)')
    parser.add_argument('--interval', type=int, default=POLL_INTERVAL,
        help=f'Segundos entre capturas (default: {POLL_INTERVAL})')
    parser.add_argument('--scan', action='store_true',
        help='Mostrar conexiones actuales y salir')
    args = parser.parse_args()

    # ── Scan mode ──────────────────────────────
    if args.scan:
        cap = NetworkCapture(dry_run=True)
        conns = cap.single_capture()
        print(f"\n{'─'*60}")
        print(f"  Conexiones activas en este momento: {len(conns)}")
        print(f"{'─'*60}")
        if not conns:
            print("  Sin conexiones externas activas")
        else:
            print(f"  {'Proceso':20} {'IP':20} {'Puerto':7} {'Estado'}")
            print(f"  {'─'*20} {'─'*20} {'─'*7} {'─'*12}")
            for c in conns:
                print(f"  {c['process']:20} {c['ip']:20} {c['port']:<7} {c['status']}")
        sys.exit(0)

    # ── Setup agent ────────────────────────────
    agent  = None
    remote = args.remote or os.environ.get('SENTINEL_AGENT_URL')

    if args.local and not remote:
        try:
            from sentinel_agent_complete import SentinelAgentComplete
            agent = SentinelAgentComplete(
                client_id='local_pc',
                provider='demo',
            )
            print("[NetworkCapture] Usando Sentinel-Agent local")
        except ImportError:
            print("[NetworkCapture] No se pudo importar sentinel_agent_complete")
            print("  Usando modo remoto o dry-run")

    if not agent and not remote and not args.dry_run:
        remote = 'https://sentinel-agent-production-0577.up.railway.app'
        print(f"[NetworkCapture] Sin agente local — usando Railway: {remote}")

    # ── Iniciar captura ────────────────────────
    POLL_INTERVAL = args.interval
    capture = NetworkCapture(
        agent=agent,
        remote_url=remote,
        dry_run=args.dry_run,
        api_key=args.api_key or os.environ.get('PHI47_API_KEY'),
    )
    capture.start()

    def shutdown(sig, frame):
        print('\n[NetworkCapture] Cerrando...')
        capture.stop()
        s = capture.status()
        print(f"  Capturadas:  {s['captured']}")
        print(f"  Analizadas:  {s['sent_to_agent']}")
        print(f"  Alertas:     {s['alerts']}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    # ── Arrancar API ───────────────────────────
    try:
        from flask import Flask
        from flask_cors import CORS
        app = create_capture_api(capture)
        print(f"\n[NetworkCapture] API disponible en http://127.0.0.1:{args.port}")
        print(f"  GET /connections/live  → conexiones ahora mismo")
        print(f"  GET /top/processes     → procesos con más conexiones")
        print(f"  GET /alerts            → alertas detectadas")
        print(f"  GET /status            → estado del capturador\n")
        app.run(host='127.0.0.1', port=args.port,
                debug=False, threaded=True, use_reloader=False)
    except ImportError:
        print("[NetworkCapture] Flask no disponible — solo captura background")
        print("Presioná Ctrl+C para detener")
        try:
            while True:
                time.sleep(5)
                s = capture.status()
                print(f"  capturadas={s['captured']} "
                      f"alertas={s['alerts']} "
                      f"uptime={s['uptime_s']:.0f}s")
        except KeyboardInterrupt:
            shutdown(None, None)
