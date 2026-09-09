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
from flask import send_file, Response
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
    print(f"  Dashboard: http://127.0.0.1:{PORT}/dashboard")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
