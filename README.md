# phi47 Sentinel-Agent — Sistema Completo

Agente de seguridad autónomo integrado con orquestador eficiente.

## Arquitectura

```
Conexión entra
      │
      ▼
NetworkProfiler   (aprende baseline del cliente, 7 días)
      │
      ▼
ThreatAnalyzer    (IOCs + anomalías vs baseline + patrones)
      │
      ▼ si amenaza detectada
      │
EfficientOrchestrator
  │
  ├── Nivel 0: phi-gate    → 0 tokens, <0.01ms
  ├── Nivel 1: reglas      → 0 tokens, <1ms
  ├── Cache:  decisión     → 0 tokens, <0.1ms
  └── Nivel 2: LLM         → tokens,   solo ~5%
              │
         Haiku / Deepseek / Llama (modelos baratos)
              │
      ▼ Decision
      │
ResponseEngine    (BLOCK / ALERT / MONITOR)
      │
SentinelMemory    (Nemosine aprende y mejora)
```

## LLM por provider — costo en producción

| Provider | Modelo | $/M tokens | Costo/mes* |
|----------|--------|-----------|-----------|
| Anthropic | claude-haiku-4-5 | $0.25/$1.25 | ~$0.45 |
| OpenAI | gpt-4o-mini | $0.15/$0.60 | ~$0.25 |
| Deepseek | deepseek-chat | $0.27/$1.10 | ~$0.40 |
| Ollama | llama3.2:3b | $0 | $0 |

*Asumiendo 1000 eventos/día, 5% al LLM = 50 llamadas/día

## Uso

```bash
pip install flask flask-cors

# Demo — ver sistema completo en acción
python core/sentinel_agent_complete.py --demo

# Producción con Haiku (recomendado)
ANTHROPIC_API_KEY=sk-... \
python core/sentinel_agent_complete.py \
  --client empresa_xyz \
  --provider anthropic

# Con Deepseek
DEEPSEEK_API_KEY=... \
python core/sentinel_agent_complete.py \
  --provider deepseek

# Con Ollama (gratis, local)
python core/sentinel_agent_complete.py \
  --provider ollama

# Con modelo específico
python core/sentinel_agent_complete.py \
  --provider anthropic \
  --model claude-haiku-4-5
```

## API

```
POST /analyze    {"ip":"1.2.3.4","port":443}
POST /simulate   {"n":200}
POST /block      {"ip":"1.2.3.4"}
POST /unblock    {"ip":"1.2.3.4"}
POST /false-positive  {"event_id":"...","ip":"..."}
GET  /status
GET  /alerts
GET  /efficiency  → reporte de uso LLM y costo
GET  /report      → informe semanal
GET  /profile     → baseline aprendido
GET  /stream      → SSE tiempo real
```

## Estructura

```
core/
  phi47_base.py              ← PhiField + Welford compartidos
  efficient_orchestrator.py  ← Orquestador 3 niveles
  sentinel_agent_complete.py ← Sistema integrado
tests/
  test_complete.py           ← 41 tests
```

## Author

Walter Calmels Von dem Knesebeck
TUCH Systems Research Laboratory — Maipu Lab 2026
wcalmels@phi47.cl
