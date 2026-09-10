"""
Entry point para Railway — sin argparse, solo variables de entorno.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel_agent_complete import SentinelAgentComplete, create_api

PORT     = int(os.environ.get("PORT", 5070))
CLIENT   = os.environ.get("CLIENT_ID", "demo_client")
PROVIDER = os.environ.get("LLM_PROVIDER", "demo")
API_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")

print(f"[phi47 Sentinel-Agent] Iniciando...")
print(f"  Cliente:  {CLIENT}")
print(f"  Provider: {PROVIDER}")
print(f"  Puerto:   {PORT}")

agent = SentinelAgentComplete(
    client_id=CLIENT,
    provider=PROVIDER,
    api_key=API_KEY if API_KEY else None,
)

app = create_api(agent)

# Serve dashboard HTML directly
from flask import send_file, Response, request as _req
import json as _json
import os as _os

@app.route('/proxy/orchestrator')
@app.route('/proxy/orchestrator/<path:subpath>')
def proxy_orchestrator(subpath=''):
    """Proxy para el Orchestrator — resuelve CORS entre dominios Railway."""
    import urllib.request as _ur
    orch_url = _os.environ.get('ORCH_URL',
        'https://web-production-84ffe.up.railway.app')
    url = orch_url + ('/' + subpath if subpath else '/')
    try:
        req = _ur.Request(url, headers={'User-Agent':'sentinel-proxy/1.0'})
        with _ur.urlopen(req, timeout=4) as r:
            data = r.read()
        return Response(data, mimetype='application/json',
                       headers={'Access-Control-Allow-Origin':'*'})
    except Exception as e:
        return Response(
            _json.dumps({'error':str(e),'online':False}),
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin':'*'})

@app.route('/dashboard')
def dashboard():
    """Sirve el dashboard desde el repo."""
    here = _os.path.dirname(_os.path.abspath(__file__))
    paths = [
        _os.path.join(here, '..', 'dashboard.html'),
        _os.path.join(here, 'dashboard.html'),
    ]
    for p in paths:
        if _os.path.exists(p):
            html = open(p, encoding='utf-8').read()
            # Solo parchear si estamos corriendo local (no en Railway)
            is_railway = _os.environ.get('RAILWAY_ENVIRONMENT') or _os.environ.get('RAILWAY_PROJECT_ID')
            if not is_railway:
                html = html.replace(
                    'sentinel-agent-production-0577.up.railway.app',
                    f'127.0.0.1:{PORT}'
                )
            return Response(html, mimetype='text/html')
    return Response("<h1>Dashboard no encontrado</h1>", mimetype='text/html')

if __name__ == "__main__":
    print(f"  Dashboard:  http://127.0.0.1:{PORT}/dashboard")
    print(f"  Conexiones: http://127.0.0.1:{PORT}/live-connections")

    # Arrancar captura real de red si psutil disponible
    try:
        from network_capture import NetworkCapture
        _capture = NetworkCapture(agent=agent, dry_run=False)
        _capture.start()
        print(f"  Monitor:    Capturando red real cada 10s")

        # Exponer endpoints de captura en la misma API
        from flask import jsonify as _jfy, request as _req

        @app.route('/live-connections')
        def live_connections():
            return _jfy({
                'connections': _capture.single_capture(),
                'ts': __import__('datetime').datetime.utcnow().isoformat(),
            })

        @app.route('/capture/status')
        def capture_status():
            return _jfy(_capture.status())

        @app.route('/capture/top-processes')
        def capture_top_procs():
            return _jfy({'processes': _capture.top_processes(10)})

        @app.route('/capture/top-destinations')
        def capture_top_dests():
            return _jfy({'destinations': _capture.top_destinations(10)})

        @app.route('/capture/alerts')
        def capture_alerts():
            return _jfy({
                'alerts': list(_capture._alerts)[:20],
                'total':  _capture._n_alerts,
            })

    except ImportError:
        print("  Monitor:    psutil no disponible (pip install psutil)")
    except Exception as e:
        print(f"  Monitor:    Error al iniciar captura: {e}")

    # Arrancar OS Firewall para bloqueo activo
    try:
        from os_firewall import OSFirewall, integrate_with_sentinel
        _firewall = OSFirewall(
            persist = True,
            dry_run = _os.environ.get('FIREWALL_DRY_RUN','0') == '1',
        )
        # Integrar con el agente — bloqueos reales desde ahora
        integrate_with_sentinel(agent, _firewall)

        # Endpoints del firewall
        @app.route('/firewall/status')
        def firewall_status():
            return _jfy(_firewall.status())

        @app.route('/firewall/block', methods=['POST'])
        def firewall_block():
            d   = _req.get_json() or {}
            ip  = d.get('ip','')
            if not ip: return _jfy({'error':'ip required'}), 400
            r = _firewall.block(ip, reason=d.get('reason','manual'), severity='HIGH')
            return _jfy(r.to_dict())

        @app.route('/firewall/unblock', methods=['POST'])
        def firewall_unblock():
            d  = _req.get_json() or {}
            ip = d.get('ip','')
            if not ip: return _jfy({'error':'ip required'}), 400
            r = _firewall.unblock(ip, reason='manual unblock')
            return _jfy(r.to_dict())

        @app.route('/firewall/list')
        def firewall_list():
            return _jfy({
                'blocked': sorted(list(_firewall._blocked)),
                'count':   len(_firewall._blocked),
                'method':  _firewall._method,
            })

        @app.route('/firewall/flush', methods=['POST'])
        def firewall_flush():
            ok = _firewall.flush_all()
            return _jfy({'ok': ok})

        print(f"  Firewall:   {_firewall._method} — bloqueo {'ACTIVO' if _firewall._method != 'simulation' else 'SIMULADO'}")

    except ImportError:
        print("  Firewall:   os_firewall no disponible")
    except Exception as e:
        print(f"  Firewall:   Error: {e}")

    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
