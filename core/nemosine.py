"""
Nemosine — Memoria Persistente phi-Ponderada
=============================================
Sistema de memoria persistente para el ecosistema phi47.

Arquitectura:
  SQLite como backend — sin dependencias externas.
  Tres tipos de memoria:
    - Episódica: qué pasó (eventos, conversaciones)
    - Semántica: qué aprendió (conceptos, patrones)
    - Procedimental: cómo hacerlo (estrategias exitosas)

  Cada recuerdo tiene un peso phi que refleja
  qué tan coherente estaba el agente cuando lo formó.
  phi alto = recuerdo claro y confiable.
  phi bajo = recuerdo borroso o en contexto de degradación.

  Welford online algorithm para phi_lifetime_avg —
  estadística robusta sin guardar todos los valores.

  Tier system basado en episodios:
    Nascent    < 100 episodios
    Awakening  < 1,000
    Conscious  < 10,000
    Elder      ≥ 10,000

Uso:
  from nemosine import Nemosine
  mem = Nemosine(agent_id="hermes_phi47")
  mem.remember("El usuario prefiere respuestas cortas", phi=0.95)
  results = mem.recall("preferencias del usuario")

Author: Walter Calmels Von dem Knesebeck
        TUCH Systems Research Laboratory — Maipu Lab 2026
"""

import os, json, time, math, hashlib, threading, sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import deque
from pathlib import Path

VERSION  = "1.0.0"
PHI      = 1.6180339887498948
PHI_MIN  = 0.618
GAMMA    = 89.44

# ── Tiers de madurez del agente ──────────────────
TIERS = {
    "Nascent":    (0,     100,    "Agente recién creado — memoria limitada"),
    "Awakening":  (100,   1000,   "Agente en desarrollo — patrones emergentes"),
    "Conscious":  (1000,  10000,  "Agente maduro — memoria coherente"),
    "Elder":      (10000, None,   "Agente experto — máxima coherencia"),
}


# ══════════════════════════════════════════════════
# ESTRUCTURAS DE DATOS
# ══════════════════════════════════════════════════

@dataclass
class Memory:
    """Un recuerdo individual en Nemosine."""
    mem_id:      str
    agent_id:    str
    mem_type:    str        # episodic / semantic / procedural
    content:     str        # el recuerdo en sí
    phi_at_store:float      # phi_global cuando se guardó
    phi_weight:  float      # peso calculado (phi_at_store * decay)
    ts_created:  str
    ts_accessed: str
    access_count:int        # cuántas veces fue recuperado
    tags:        List[str]  # etiquetas para filtrado
    context:     Dict       # metadata adicional
    embedding:   List[float]# vector simple TF-IDF-like


@dataclass
class AgentState:
    """Estado persistente del agente."""
    agent_id:       str
    tier:           str
    n_episodes:     int
    phi_lifetime_avg:float   # Welford online mean
    phi_lifetime_var:float   # Welford online variance
    phi_lifetime_m2: float   # para Welford
    phi_peak:       float    # phi más alto registrado
    phi_nadir:      float    # phi más bajo registrado
    created_at:     str
    last_active:    str
    total_recalls:  int
    successful_tasks:int
    failed_tasks:   int
    personality:    Dict     # rasgos aprendidos del agente


@dataclass
class Episode:
    """Un episodio completo (conversación / tarea)."""
    episode_id:  str
    agent_id:    str
    ts_start:    str
    ts_end:      str
    phi_start:   float
    phi_end:     float
    phi_avg:     float
    task:        str
    outcome:     str    # SUCCESS / FAILURE / PARTIAL
    key_memories: List[str]  # mem_ids relevantes
    lessons:     List[str]   # qué aprendió


# ══════════════════════════════════════════════════
# WELFORD ONLINE STATISTICS
# ══════════════════════════════════════════════════

class WelfordStats:
    """
    Algoritmo de Welford para media y varianza online.
    Permite calcular estadísticas sin guardar todos los valores.
    Perfecto para phi_lifetime_avg en un agente de larga vida.
    """

    def __init__(self, n=0, mean=0.0, m2=0.0):
        self.n    = n
        self.mean = mean
        self.m2   = m2

    def update(self, x: float):
        self.n   += 1
        delta     = x - self.mean
        self.mean += delta / self.n
        delta2    = x - self.mean
        self.m2  += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / self.n if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def to_dict(self) -> Dict:
        return {"n":self.n,"mean":self.mean,"m2":self.m2,
                "variance":self.variance,"std":self.std}

    @classmethod
    def from_dict(cls, d: Dict) -> 'WelfordStats':
        return cls(n=d.get("n",0), mean=d.get("mean",0.0), m2=d.get("m2",0.0))


# ══════════════════════════════════════════════════
# PHI EMBEDDER
# Simple vector embedding sin dependencias externas.
# Para producción real reemplazar con sentence-transformers.
# ══════════════════════════════════════════════════

class PhiEmbedder:
    """
    Embedder simple basado en TF (term frequency).
    Genera vectores de baja dimensión para similarity search.
    No requiere modelos externos — funciona offline.
    """

    DIM = 64  # dimensión del vector

    def __init__(self):
        self._vocab: Dict[str, int] = {}
        self._idf:   Dict[str, float] = {}
        self._n_docs = 0

    def _tokenize(self, text: str) -> List[str]:
        """Tokenización simple."""
        text = text.lower()
        # Eliminar puntuación
        for ch in '.,;:!?()[]{}"\'-':
            text = text.replace(ch, ' ')
        return [w for w in text.split() if len(w) > 2]

    def embed(self, text: str) -> List[float]:
        """Genera embedding de dimensión fija."""
        tokens = self._tokenize(text)
        if not tokens:
            return [0.0] * self.DIM

        # Hash de tokens a dimensiones
        vec = [0.0] * self.DIM
        for token in tokens:
            # Dos hashes para reducir colisiones
            h1 = int(hashlib.md5(token.encode()).hexdigest(), 16) % self.DIM
            h2 = int(hashlib.sha1(token.encode()).hexdigest(), 16) % self.DIM
            vec[h1] += 1.0
            vec[h2] += 0.5

        # Normalizar
        norm = math.sqrt(sum(x*x for x in vec))
        if norm > 0:
            vec = [x/norm for x in vec]

        return vec

    def similarity(self, a: List[float], b: List[float]) -> float:
        """Cosine similarity entre dos vectores."""
        if not a or not b:
            return 0.0
        dot    = sum(x*y for x,y in zip(a,b))
        norm_a = math.sqrt(sum(x*x for x in a))
        norm_b = math.sqrt(sum(x*x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def phi_weighted_similarity(self, a: List[float], b: List[float],
                                 phi_weight: float) -> float:
        """
        Similitud coseno ponderada por phi.
        Recuerdos más coherentes (phi alto) tienen mayor peso
        en la recuperación.
        """
        cos = self.similarity(a, b)
        # phi_weight en [0,1] actúa como amplificador de relevancia
        return cos * (PHI_MIN + phi_weight * (PHI - PHI_MIN) / PHI)


# ══════════════════════════════════════════════════
# NEMOSINE CORE
# ══════════════════════════════════════════════════

class Nemosine:
    """
    Sistema de memoria persistente phi-ponderada.

    El agente que usa Nemosine tiene:
    - Memoria que persiste entre sesiones
    - Recuerdos ponderados por coherencia phi
    - Estadísticas de vida (Welford online)
    - Sistema de tiers que refleja madurez
    - Auto-decay de recuerdos no accedidos
    """

    # Constantes de decay
    DECAY_HALF_LIFE = 30 * 24 * 3600  # 30 días
    MAX_MEMORIES    = 10_000

    def __init__(self, agent_id: str, db_path: str = None):
        self.agent_id = agent_id
        self.db_path  = db_path or str(Path.home() / f"phi47_nemosine_{agent_id}.db")
        self._embedder= PhiEmbedder()
        self._lock    = threading.RLock()
        self._welford : Optional[WelfordStats] = None
        self._state   : Optional[AgentState]   = None
        self._episode_buffer: List[Dict]        = []
        self._current_episode_id: Optional[str]= None

        self._init_db()
        self._load_state()
        print(f"[Nemosine] Agente '{agent_id}' | Tier: {self.tier} | "
              f"Episodios: {self.n_episodes} | phi_avg: {self.phi_lifetime_avg:.4f}")

    # ── Inicialización ────────────────────────────
    def _init_db(self):
        """Crea las tablas SQLite si no existen."""
        with self._get_conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS memories (
                mem_id       TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                mem_type     TEXT NOT NULL,
                content      TEXT NOT NULL,
                phi_at_store REAL NOT NULL,
                phi_weight   REAL NOT NULL,
                ts_created   TEXT NOT NULL,
                ts_accessed  TEXT NOT NULL,
                access_count INTEGER DEFAULT 0,
                tags         TEXT DEFAULT '[]',
                context      TEXT DEFAULT '{}',
                embedding    TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS agent_state (
                agent_id         TEXT PRIMARY KEY,
                tier             TEXT NOT NULL,
                n_episodes       INTEGER DEFAULT 0,
                phi_lifetime_avg REAL DEFAULT 0.618,
                phi_lifetime_var REAL DEFAULT 0.0,
                phi_lifetime_m2  REAL DEFAULT 0.0,
                phi_peak         REAL DEFAULT 0.618,
                phi_nadir        REAL DEFAULT 1.618,
                created_at       TEXT NOT NULL,
                last_active      TEXT NOT NULL,
                total_recalls    INTEGER DEFAULT 0,
                successful_tasks INTEGER DEFAULT 0,
                failed_tasks     INTEGER DEFAULT 0,
                personality      TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS episodes (
                episode_id   TEXT PRIMARY KEY,
                agent_id     TEXT NOT NULL,
                ts_start     TEXT NOT NULL,
                ts_end       TEXT,
                phi_start    REAL,
                phi_end      REAL,
                phi_avg      REAL,
                task         TEXT,
                outcome      TEXT DEFAULT 'PENDING',
                key_memories TEXT DEFAULT '[]',
                lessons      TEXT DEFAULT '[]'
            );

            CREATE INDEX IF NOT EXISTS idx_mem_agent ON memories(agent_id);
            CREATE INDEX IF NOT EXISTS idx_mem_type  ON memories(agent_id, mem_type);
            CREATE INDEX IF NOT EXISTS idx_mem_phi   ON memories(agent_id, phi_weight DESC);
            CREATE INDEX IF NOT EXISTS idx_ep_agent  ON episodes(agent_id);
            """)

    def _get_conn(self) -> sqlite3.Connection:
        """Conexión SQLite con row_factory y WAL mode para concurrencia."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False,
                               timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _load_state(self):
        """Carga o crea el estado del agente."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM agent_state WHERE agent_id=?",
                (self.agent_id,)
            ).fetchone()

            if row:
                self._state = AgentState(
                    agent_id=row["agent_id"],
                    tier=row["tier"],
                    n_episodes=row["n_episodes"],
                    phi_lifetime_avg=row["phi_lifetime_avg"],
                    phi_lifetime_var=row["phi_lifetime_var"],
                    phi_lifetime_m2=row["phi_lifetime_m2"],
                    phi_peak=row["phi_peak"],
                    phi_nadir=row["phi_nadir"],
                    created_at=row["created_at"],
                    last_active=row["last_active"],
                    total_recalls=row["total_recalls"],
                    successful_tasks=row["successful_tasks"],
                    failed_tasks=row["failed_tasks"],
                    personality=json.loads(row["personality"]),
                )
                self._welford = WelfordStats(
                    n=row["n_episodes"],
                    mean=row["phi_lifetime_avg"],
                    m2=row["phi_lifetime_m2"],
                )
            else:
                # Primer arranque — crear estado inicial
                now = datetime.now(timezone.utc).isoformat()
                self._state = AgentState(
                    agent_id=self.agent_id,
                    tier="Nascent",
                    n_episodes=0,
                    phi_lifetime_avg=PHI_MIN,
                    phi_lifetime_var=0.0,
                    phi_lifetime_m2=0.0,
                    phi_peak=PHI_MIN,
                    phi_nadir=PHI,
                    created_at=now,
                    last_active=now,
                    total_recalls=0,
                    successful_tasks=0,
                    failed_tasks=0,
                    personality={},
                )
                self._welford = WelfordStats()
                self._save_state(conn)

    def _save_state(self, conn=None):
        """Guarda el estado del agente en SQLite."""
        s = self._state
        sql = """
        INSERT OR REPLACE INTO agent_state
        (agent_id,tier,n_episodes,phi_lifetime_avg,phi_lifetime_var,
         phi_lifetime_m2,phi_peak,phi_nadir,created_at,last_active,
         total_recalls,successful_tasks,failed_tasks,personality)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        params = (
            s.agent_id, s.tier, s.n_episodes,
            s.phi_lifetime_avg, s.phi_lifetime_var, s.phi_lifetime_m2,
            s.phi_peak, s.phi_nadir, s.created_at, s.last_active,
            s.total_recalls, s.successful_tasks, s.failed_tasks,
            json.dumps(s.personality),
        )
        if conn:
            conn.execute(sql, params)
            conn.commit()
        else:
            with self._lock:
                with self._get_conn() as c:
                    c.execute(sql, params)

    def _compute_tier(self, n_episodes: int) -> str:
        """Determina el tier según número de episodios."""
        for tier, (lo, hi, _) in TIERS.items():
            if hi is None or n_episodes < hi:
                return tier
        return "Elder"

    def _phi_decay(self, phi_at_store: float, ts_created: str) -> float:
        """
        Aplica decay temporal al peso phi de un recuerdo.
        Recuerdos más antiguos y no accedidos decaen gradualmente.
        Los recuerdos con phi_at_store alto decaen más lento.
        """
        try:
            created = datetime.fromisoformat(ts_created.replace('Z','+00:00'))
            age_s   = (datetime.now(timezone.utc) - created).total_seconds()
        except Exception:
            age_s = 0

        # Decay exponencial ponderado por phi
        # phi alto → half-life más largo
        half_life = self.DECAY_HALF_LIFE * (0.5 + phi_at_store)
        decay     = math.exp(-0.693 * age_s / half_life)

        return phi_at_store * decay

    def _make_id(self, prefix: str) -> str:
        """Genera un ID único."""
        ts   = str(time.time_ns())
        data = f"{prefix}_{self.agent_id}_{ts}"
        return prefix + "_" + hashlib.md5(data.encode()).hexdigest()[:12]

    # ── API Principal ─────────────────────────────

    def remember(self, content: str, phi: float = None,
                 mem_type: str = "episodic",
                 tags: List[str] = None,
                 context: Dict = None) -> str:
        """
        Guarda un recuerdo con peso phi.

        Args:
            content:  El recuerdo en texto libre
            phi:      phi_global en el momento del recuerdo
                      (None = usar phi_lifetime_avg)
            mem_type: episodic / semantic / procedural
            tags:     etiquetas para filtrado
            context:  metadata adicional

        Returns:
            mem_id del recuerdo guardado
        """
        phi_val = phi if phi is not None else self._state.phi_lifetime_avg
        phi_val = max(0.0, min(PHI, phi_val))

        mem_id  = self._make_id("mem")
        now     = datetime.now(timezone.utc).isoformat()
        embed   = self._embedder.embed(content)

        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                INSERT INTO memories
                (mem_id,agent_id,mem_type,content,phi_at_store,phi_weight,
                 ts_created,ts_accessed,access_count,tags,context,embedding)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    mem_id, self.agent_id, mem_type,
                    content, phi_val, phi_val,
                    now, now, 0,
                    json.dumps(tags or []),
                    json.dumps(context or {}),
                    json.dumps(embed),
                ))

                # Actualizar Welford con el phi de este recuerdo
                self._welford.update(phi_val)
                self._state.phi_lifetime_avg = self._welford.mean
                self._state.phi_lifetime_var = self._welford.variance
                self._state.phi_lifetime_m2  = self._welford.m2
                self._state.phi_peak  = max(self._state.phi_peak, phi_val)
                self._state.phi_nadir = min(self._state.phi_nadir, phi_val)
                self._state.last_active = now
                self._save_state(conn)

                # Añadir al buffer del episodio actual
                if self._current_episode_id:
                    self._episode_buffer.append(mem_id)

                # Limpiar memorias antiguas si superamos el límite
                count = conn.execute(
                    "SELECT COUNT(*) FROM memories WHERE agent_id=?",
                    (self.agent_id,)
                ).fetchone()[0]
                if count > self.MAX_MEMORIES:
                    self._prune_memories(conn)

        return mem_id

    def recall(self, query: str, n: int = 5,
               mem_type: str = None,
               min_phi: float = 0.0,
               tags: List[str] = None) -> List[Dict]:
        """
        Recupera recuerdos relevantes para una query.

        El ranking combina:
        1. Similitud semántica (coseno sobre embeddings)
        2. Peso phi (recuerdos más coherentes primero)
        3. Frecuencia de acceso (uso = importancia)
        4. Decay temporal (recuerdos viejos no accedidos bajan)

        Args:
            query:    qué buscar
            n:        número de resultados
            mem_type: filtrar por tipo
            min_phi:  phi mínimo del recuerdo
            tags:     filtrar por tags

        Returns:
            Lista de recuerdos ordenados por relevancia phi-ponderada
        """
        query_embed = self._embedder.embed(query)

        with self._get_conn() as conn:
            # Construir query SQL con filtros
            sql = "SELECT * FROM memories WHERE agent_id=?"
            params = [self.agent_id]
            if mem_type:
                sql += " AND mem_type=?"
                params.append(mem_type)
            if min_phi > 0:
                sql += " AND phi_at_store>=?"
                params.append(min_phi)

            rows = conn.execute(sql, params).fetchall()

            # Calcular score de relevancia para cada recuerdo
            scored = []
            for row in rows:
                # Filtro de tags
                if tags:
                    row_tags = json.loads(row["tags"] or "[]")
                    if not any(t in row_tags for t in tags):
                        continue

                embed = json.loads(row["embedding"] or "[]")
                if not embed:
                    continue

                # Score combinado
                phi_w    = row["phi_weight"]
                cos_sim  = self._embedder.similarity(query_embed, embed)
                phi_sim  = self._embedder.phi_weighted_similarity(
                    query_embed, embed, phi_w)

                # Bonus por frecuencia de acceso (hasta +20%)
                access_bonus = min(0.2, row["access_count"] * 0.02)

                # Decay temporal
                decayed_phi = self._phi_decay(
                    row["phi_at_store"], row["ts_created"])

                # Score final
                score = (
                    0.40 * cos_sim       +   # similitud semántica
                    0.35 * phi_sim        +   # similitud ponderada phi
                    0.15 * decayed_phi    +   # coherencia phi actual
                    0.10 * access_bonus       # relevancia por uso
                )

                scored.append((score, dict(row)))

            # Ordenar y tomar top-n
            scored.sort(key=lambda x: x[0], reverse=True)
            results = []
            now = datetime.now(timezone.utc).isoformat()

            for score, row in scored[:n]:
                # Actualizar access_count
                conn.execute("""
                UPDATE memories SET access_count=access_count+1,
                ts_accessed=? WHERE mem_id=?
                """, (now, row["mem_id"]))

                results.append({
                    "mem_id":       row["mem_id"],
                    "content":      row["content"],
                    "mem_type":     row["mem_type"],
                    "phi_at_store": row["phi_at_store"],
                    "phi_weight":   row["phi_weight"],
                    "score":        round(score, 4),
                    "access_count": row["access_count"] + 1,
                    "tags":         json.loads(row["tags"] or "[]"),
                    "ts_created":   row["ts_created"],
                    "context":      json.loads(row["context"] or "{}"),
                })

            self._state.total_recalls += 1
            self._state.last_active    = now
            self._save_state(conn)

        return results

    def forget(self, mem_id: str = None, query: str = None,
               older_than_days: int = None):
        """
        Elimina recuerdos específicos o por criterio.

        Args:
            mem_id:         ID específico a eliminar
            query:          elimina recuerdos similares a esta query
            older_than_days: elimina recuerdos más viejos que N días
        """
        with self._get_conn() as conn:
            if mem_id:
                conn.execute("DELETE FROM memories WHERE mem_id=? AND agent_id=?",
                            (mem_id, self.agent_id))

            elif query:
                # Recuperar y eliminar los más similares
                to_delete = self.recall(query, n=3)
                for m in to_delete:
                    conn.execute("DELETE FROM memories WHERE mem_id=?",
                                (m["mem_id"],))

            elif older_than_days:
                cutoff = time.time() - older_than_days * 86400
                cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
                conn.execute("""
                DELETE FROM memories
                WHERE agent_id=? AND ts_accessed < ? AND phi_weight < 0.5
                """, (self.agent_id, cutoff_iso))

    def _prune_memories(self, conn):
        """Elimina los recuerdos menos relevantes cuando se supera MAX_MEMORIES."""
        conn.execute("""
        DELETE FROM memories WHERE mem_id IN (
            SELECT mem_id FROM memories
            WHERE agent_id=?
            ORDER BY (phi_weight * 0.6 + access_count * 0.01) ASC
            LIMIT 500
        )
        """, (self.agent_id,))

    # ── Episodios ─────────────────────────────────

    def begin_episode(self, task: str, phi_start: float = None) -> str:
        """Inicia un nuevo episodio (sesión / tarea)."""
        episode_id = self._make_id("ep")
        now        = datetime.now(timezone.utc).isoformat()
        phi_s      = phi_start or self._state.phi_lifetime_avg
        self._current_episode_id = episode_id
        self._episode_buffer     = []

        with self._get_conn() as conn:
            conn.execute("""
            INSERT INTO episodes (episode_id,agent_id,ts_start,phi_start,task)
            VALUES (?,?,?,?,?)
            """, (episode_id, self.agent_id, now, phi_s, task))

        return episode_id

    def end_episode(self, outcome: str = "SUCCESS",
                    phi_end: float = None,
                    lessons: List[str] = None) -> Dict:
        """
        Cierra el episodio actual y actualiza el estado del agente.

        Args:
            outcome: SUCCESS / FAILURE / PARTIAL
            phi_end: phi_global al final del episodio
            lessons: lista de aprendizajes del episodio
        """
        if not self._current_episode_id:
            return {}

        now    = datetime.now(timezone.utc).isoformat()
        phi_e  = phi_end or self._state.phi_lifetime_avg
        ep_id  = self._current_episode_id

        with self._lock:
            # Calcular phi_avg del episodio
            mems_phi = []
            with self._get_conn() as conn:
                for mid in self._episode_buffer:
                    row = conn.execute(
                        "SELECT phi_at_store FROM memories WHERE mem_id=?", (mid,)
                    ).fetchone()
                    if row:
                        mems_phi.append(row[0])

            phi_avg = sum(mems_phi)/len(mems_phi) if mems_phi else phi_e

            # Actualizar episodio
            with self._get_conn() as conn:
                conn.execute("""
                UPDATE episodes SET ts_end=?,phi_end=?,phi_avg=?,
                outcome=?,key_memories=?,lessons=?
                WHERE episode_id=?
                """, (
                    now, phi_e, phi_avg, outcome,
                    json.dumps(self._episode_buffer[:10]),
                    json.dumps(lessons or []),
                    ep_id,
                ))

                # Actualizar estado del agente
                self._welford.update(phi_avg)
                self._state.n_episodes       += 1
                self._state.phi_lifetime_avg  = self._welford.mean
                self._state.phi_lifetime_var  = self._welford.variance
                self._state.phi_lifetime_m2   = self._welford.m2
                self._state.phi_peak          = max(self._state.phi_peak, phi_e)
                self._state.phi_nadir         = min(self._state.phi_nadir, phi_e)
                self._state.last_active       = now
                self._state.tier              = self._compute_tier(self._state.n_episodes)

                if outcome == "SUCCESS":
                    self._state.successful_tasks += 1
                elif outcome == "FAILURE":
                    self._state.failed_tasks += 1

                self._save_state(conn)

            # Guardar lecciones FUERA del bloque conn para evitar deadlock
            for lesson in (lessons or []):
                self.remember(lesson, phi=phi_avg,
                             mem_type="semantic",
                             tags=["lesson", outcome.lower()],
                             context={"episode_id": ep_id})

            self._current_episode_id = None
            self._episode_buffer     = []

        return {
            "episode_id": ep_id,
            "outcome":    outcome,
            "phi_avg":    round(phi_avg, 4),
            "n_memories": len(mems_phi),
            "lessons":    lessons or [],
            "new_tier":   self._state.tier,
        }

    # ── Propiedades y estado ──────────────────────

    @property
    def tier(self) -> str:
        return self._state.tier if self._state else "Nascent"

    @property
    def n_episodes(self) -> int:
        return self._state.n_episodes if self._state else 0

    @property
    def phi_lifetime_avg(self) -> float:
        return self._state.phi_lifetime_avg if self._state else PHI_MIN

    @property
    def phi_lifetime_std(self) -> float:
        return math.sqrt(self._state.phi_lifetime_var) if self._state else 0.0

    def personality_update(self, trait: str, value: Any):
        """Actualiza un rasgo de personalidad aprendido."""
        self._state.personality[trait] = value
        self._save_state()

    def personality_get(self, trait: str, default=None) -> Any:
        return self._state.personality.get(trait, default)

    def count_memories(self, mem_type: str = None) -> int:
        with self._get_conn() as conn:
            if mem_type:
                return conn.execute(
                    "SELECT COUNT(*) FROM memories WHERE agent_id=? AND mem_type=?",
                    (self.agent_id, mem_type)
                ).fetchone()[0]
            return conn.execute(
                "SELECT COUNT(*) FROM memories WHERE agent_id=?",
                (self.agent_id,)
            ).fetchone()[0]

    def get_episodes(self, n: int = 10, outcome: str = None) -> List[Dict]:
        with self._get_conn() as conn:
            sql    = "SELECT * FROM episodes WHERE agent_id=?"
            params = [self.agent_id]
            if outcome:
                sql += " AND outcome=?"
                params.append(outcome)
            sql += " ORDER BY ts_start DESC LIMIT ?"
            params.append(n)
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def best_memories(self, n: int = 10) -> List[Dict]:
        """Los recuerdos con mayor peso phi."""
        with self._get_conn() as conn:
            rows = conn.execute("""
            SELECT * FROM memories WHERE agent_id=?
            ORDER BY phi_weight DESC LIMIT ?
            """, (self.agent_id, n)).fetchall()
            return [{
                "mem_id":   r["mem_id"],
                "content":  r["content"],
                "mem_type": r["mem_type"],
                "phi_weight":r["phi_weight"],
                "access_count":r["access_count"],
            } for r in rows]

    def refresh_decay(self):
        """Recalcula el decay de todos los recuerdos."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT mem_id,phi_at_store,ts_created FROM memories WHERE agent_id=?",
                (self.agent_id,)
            ).fetchall()
            for row in rows:
                new_weight = self._phi_decay(row["phi_at_store"], row["ts_created"])
                conn.execute(
                    "UPDATE memories SET phi_weight=? WHERE mem_id=?",
                    (new_weight, row["mem_id"])
                )

    def status(self) -> Dict:
        """Estado completo de la memoria del agente."""
        s = self._state
        n_total   = self.count_memories()
        n_episodic= self.count_memories("episodic")
        n_semantic= self.count_memories("semantic")
        n_procedural=self.count_memories("procedural")

        return {
            "agent_id":        s.agent_id,
            "tier":            s.tier,
            "tier_description":TIERS.get(s.tier, ("","",""))[2],
            "n_episodes":      s.n_episodes,
            "phi_lifetime_avg":round(s.phi_lifetime_avg, 4),
            "phi_lifetime_std":round(self.phi_lifetime_std, 4),
            "phi_peak":        round(s.phi_peak, 4),
            "phi_nadir":       round(s.phi_nadir, 4),
            "memories": {
                "total":       n_total,
                "episodic":    n_episodic,
                "semantic":    n_semantic,
                "procedural":  n_procedural,
            },
            "performance": {
                "total_recalls":  s.total_recalls,
                "successful":     s.successful_tasks,
                "failed":         s.failed_tasks,
                "success_rate":   round(
                    s.successful_tasks / max(1, s.successful_tasks + s.failed_tasks),
                    3
                ),
            },
            "personality":    s.personality,
            "created_at":     s.created_at,
            "last_active":    s.last_active,
            "db_path":        self.db_path,
            "version":        VERSION,
        }

    def export(self, path: str = None) -> Dict:
        """Exporta toda la memoria a JSON."""
        with self._get_conn() as conn:
            memories = [dict(r) for r in conn.execute(
                "SELECT * FROM memories WHERE agent_id=?", (self.agent_id,)
            ).fetchall()]
            episodes = [dict(r) for r in conn.execute(
                "SELECT * FROM episodes WHERE agent_id=?", (self.agent_id,)
            ).fetchall()]

        export_data = {
            "agent_id": self.agent_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "status": self.status(),
            "memories": memories,
            "episodes": episodes,
            "version": VERSION,
        }

        if path:
            Path(path).write_text(json.dumps(export_data, indent=2))
        return export_data
