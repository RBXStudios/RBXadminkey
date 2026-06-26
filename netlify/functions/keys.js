// ============================================================
// RBX EXPLOIT — Keys API (persistência em Netlify Blobs)
// rbxpainelkeylol.netlify.app/.netlify/functions/keys
//
// Rotas (via ?action=...):
//   validate  → valida key + HWID binding         (chamado pelo app C#)
//   create    → cria key                          (admin)
//   list      → lista keys (suporta ?search=, ?type=, ?status=)  (admin)
//   delete    → deleta key                        (admin)
//   toggle    → ativa / desativa                  (admin)
//   renew     → renova tempo da key                (admin)
//   edit      → edita tipo/duração/status/HWID em uma chamada (admin)
//   history   → timeline de eventos de uma key (?code=)         (admin)
// ============================================================
//
// IMPORTANTE: precisa do pacote "@netlify/blobs" instalado nesse projeto
// (rode `npm install @netlify/blobs` na raiz do site rbxpainelkeylol).
// Netlify Blobs é um storage key-value persistente de verdade — diferente
// de /tmp, ele não depende de qual instância da function atendeu o request.
// ============================================================

const { getStore } = require("@netlify/blobs");

const ADMIN_EMAIL    = process.env.PANEL_ADMIN_EMAIL || "rbxstudios@gmail.com";
const ADMIN_PASSWORD = process.env.PANEL_ADMIN_PASSWORD || "RBXStudios200@@";

const STORE_NAME = "rbx-keys";
const DB_KEY     = "db.json";

function getDbStore() {
  return getStore(STORE_NAME);
}

// ── Carrega / salva DB ─────────────────────────────────────
async function loadDB() {
  try {
    const store = getDbStore();
    const txt = await store.get(DB_KEY, { type: "text" });
    if (txt) {
      const data = JSON.parse(txt);
      if (data && Array.isArray(data.keys)) return data;
    }
  } catch (e) {
    console.error("loadDB error:", e);
  }
  // fallback inicial (primeira execução, ainda sem nada salvo)
  return {
    keys: [
      {
        code:      "RBXD-LOADFLINT-DEV",
        type:      "dev",
        duration:  "perm",
        createdAt: new Date().toISOString(),
        expiresAt: null,
        active:    true,
        hwid:      null,
      }
    ]
  };
}

async function saveDB(db) {
  try {
    const store = getDbStore();
    await store.set(DB_KEY, JSON.stringify(db, null, 2));
    return true;
  } catch (e) {
    console.error("saveDB error:", e);
    return false;
  }
}

// ── Helpers ──────────────────────────────────────────────────
function seg(n = 5) {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({ length: n }, () => c[Math.floor(Math.random() * c.length)]).join("");
}

function generateKey(type) {
  if (type === "free")    return `RBXF-${seg()}-${seg()}-${seg()}`;
  if (type === "premium") return `RBXP-${seg()}-${seg()}`;
  if (type === "dev")     return `RBXD-LOADFLINT-DEV`;
  throw new Error("Tipo inválido");
}

function calcExpires(duration) {
  if (duration === "perm") return null;
  const map = { "1d": 1, "30d": 30, "90d": 90 };
  const days = map[duration];
  if (!days) throw new Error("Duração inválida");
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function isExpired(k) {
  if (!k.expiresAt) return false;
  return new Date() > new Date(k.expiresAt);
}

// Varre o DB e marca como inativa (active=false) qualquer key que já passou
// do expiresAt mas ainda estava marcada como active. Persiste a mudança.
// Chamado logo após loadDB() em toda rota — assim o "active" no painel
// reflete a realidade sem precisar de cron job nem de alguém clicar em Revogar.
async function revokeExpiredKeys(DB) {
  let changed = false;
  for (const k of DB.keys) {
    if (k.active && isExpired(k)) {
      k.active = false;
      addHistory(k, "auto_revoke", "Expirou e foi desativada automaticamente");
      changed = true;
    }
  }
  if (changed) await saveDB(DB);
  return DB;
}

function daysLeft(k) {
  if (!k.expiresAt) return null;
  const diff = new Date(k.expiresAt) - new Date();
  return Math.max(0, Math.ceil(diff / 86400000));
}

// Registra um evento no histórico da própria key (mantém só os últimos 50).
// "ver histórico" no painel é isso: cada key carrega sua própria timeline.
function addHistory(k, action, detail) {
  if (!Array.isArray(k.history)) k.history = [];
  k.history.push({
    action,
    detail: detail || null,
    at: new Date().toISOString(),
  });
  if (k.history.length > 50) k.history = k.history.slice(-50);
}

function cors(r) {
  r.headers = r.headers || {};
  r.headers["Access-Control-Allow-Origin"]  = "*";
  r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
  r.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
  return r;
}

function json(status, body) {
  return cors({
    statusCode: status,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function checkAdmin(auth) {
  if (!auth || !auth.startsWith("Basic ")) return false;
  try {
    const [e, p] = Buffer.from(auth.slice(6), "base64").toString().split(":");
    return e === ADMIN_EMAIL && p === ADMIN_PASSWORD;
  } catch {
    return false;
  }
}

// ── Handler ──────────────────────────────────────────────────
exports.handler = async function (event) {
  if (event.httpMethod === "OPTIONS") return cors({ statusCode: 204, body: "" });

  // Carrega DB atual
  let DB = await loadDB();
  DB = await revokeExpiredKeys(DB);

  const action = (event.queryStringParameters || {}).action || "";
  let body = {};
  try { body = JSON.parse(event.body || "{}"); } catch {}

  // ── VALIDAR (app C#) ─────────────────────────────────────
  if (action === "validate") {
    const { key, hwid } = body;
    if (!key) return json(400, { valid: false, reason: "Key não informada" });

    const found = DB.keys.find(k => k.code === key.trim().toUpperCase());
    if (!found)           return json(200, { valid: false, reason: "Key inválida" });
    if (isExpired(found)) return json(200, { valid: false, reason: "Key expirada" });
    if (!found.active)    return json(200, { valid: false, reason: "Key desativada" });

    if (hwid) {
      if (!found.hwid) {
        found.hwid = hwid;
        addHistory(found, "hwid_bind", hwid);
        await saveDB(DB);
      } else if (found.hwid !== hwid) {
        return json(200, { valid: false, reason: "Key vinculada a outro dispositivo" });
      }
    }

    return json(200, {
      valid:     true,
      type:      found.type,
      duration:  found.duration,
      expiresAt: found.expiresAt,
      daysLeft:  daysLeft(found),
    });
  }

  // ── CRIAR ────────────────────────────────────────────────
  if (action === "create") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });

    const { type, duration } = body;
    if (!["free","premium","dev"].includes(type))
      return json(400, { error: "Tipo inválido" });

    const allowed = type === "dev" ? ["perm"] : ["1d","30d","90d","perm"];
    if (!allowed.includes(duration))
      return json(400, { error: "Duração inválida para este tipo" });

    if (type === "dev") {
      const ex = DB.keys.find(k => k.type === "dev");
      if (ex) return json(409, { error: "Key DEV já existe", key: ex.code });
    }

    const newKey = {
      code:      generateKey(type),
      type,
      duration,
      createdAt: new Date().toISOString(),
      expiresAt: calcExpires(duration),
      active:    true,
      hwid:      null,
      history:   [],
    };
    addHistory(newKey, "create", `${type} / ${duration}`);
    DB.keys.push(newKey);
    await saveDB(DB);
    return json(201, { success: true, key: newKey });
  }

  // ── LISTAR ───────────────────────────────────────────────
  if (action === "list") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });

    const stats = {
      total:   DB.keys.length,
      free:    DB.keys.filter(k => k.type === "free").length,
      premium: DB.keys.filter(k => k.type === "premium").length,
      dev:     DB.keys.filter(k => k.type === "dev").length,
      active:  DB.keys.filter(k => k.active && !isExpired(k)).length,
      expired: DB.keys.filter(k => isExpired(k)).length,
    };

    // Filtros opcionais via query string: ?search=...&type=free&status=active
    const qp = event.queryStringParameters || {};
    let filtered = DB.keys;

    if (qp.search) {
      const s = qp.search.trim().toUpperCase();
      filtered = filtered.filter(k => k.code.includes(s));
    }
    if (qp.type && ["free", "premium", "dev"].includes(qp.type)) {
      filtered = filtered.filter(k => k.type === qp.type);
    }
    if (qp.status === "active") {
      filtered = filtered.filter(k => k.active && !isExpired(k));
    } else if (qp.status === "inactive") {
      filtered = filtered.filter(k => !k.active);
    } else if (qp.status === "expired") {
      filtered = filtered.filter(k => isExpired(k));
    }

    const keysWithMeta = filtered.map(k => ({
      ...k,
      expired:  isExpired(k),
      daysLeft: daysLeft(k),
    }));

    return json(200, { stats, keys: keysWithMeta });
  }

  // ── DELETAR ──────────────────────────────────────────────
  if (action === "delete") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });
    const { code } = body;
    const idx = DB.keys.findIndex(k => k.code === code);
    if (idx === -1) return json(404, { error: "Key não encontrada" });
    DB.keys.splice(idx, 1);
    await saveDB(DB);
    return json(200, { success: true });
  }

  // ── TOGGLE ───────────────────────────────────────────────
  if (action === "toggle") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });
    const { code } = body;
    const found = DB.keys.find(k => k.code === code);
    if (!found) return json(404, { error: "Key não encontrada" });
    found.active = !found.active;
    addHistory(found, found.active ? "activate" : "deactivate");
    await saveDB(DB);
    return json(200, { success: true, active: found.active });
  }

  // ── RENOVAR ──────────────────────────────────────────────
  if (action === "renew") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });
    const { code, duration } = body;
    const found = DB.keys.find(k => k.code === code);
    if (!found) return json(404, { error: "Key não encontrada" });

    const allowed = ["1d","30d","90d","perm"];
    if (!allowed.includes(duration)) return json(400, { error: "Duração inválida" });

    found.duration  = duration;
    found.expiresAt = calcExpires(duration);
    found.active    = true;
    addHistory(found, "renew", duration);
    await saveDB(DB);
    return json(200, { success: true, key: { ...found, daysLeft: daysLeft(found) } });
  }

  // ── EDITAR ───────────────────────────────────────────────
  // Permite trocar tipo, duração, status (ativa/inativa) e desvincular o HWID,
  // tudo numa chamada só. Qualquer campo omitido no body fica como estava.
  if (action === "edit") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });
    const { code, type, duration, active, resetHwid } = body;
    const found = DB.keys.find(k => k.code === code);
    if (!found) return json(404, { error: "Key não encontrada" });

    const changes = [];

    if (type !== undefined && type !== found.type) {
      if (!["free", "premium", "dev"].includes(type)) {
        return json(400, { error: "Tipo inválido" });
      }
      found.type = type;
      changes.push(`tipo→${type}`);
    }

    if (duration !== undefined && duration !== found.duration) {
      const allowedDur = found.type === "dev" ? ["perm"] : ["1d", "30d", "90d", "perm"];
      if (!allowedDur.includes(duration)) {
        return json(400, { error: "Duração inválida para este tipo" });
      }
      found.duration = duration;
      found.expiresAt = calcExpires(duration);
      changes.push(`duração→${duration}`);
    }

    if (active !== undefined && !!active !== found.active) {
      found.active = !!active;
      changes.push(found.active ? "ativada" : "desativada");
    }

    if (resetHwid) {
      found.hwid = null;
      changes.push("hwid resetado");
    }

    if (changes.length) {
      addHistory(found, "edit", changes.join(", "));
      await saveDB(DB);
    }

    return json(200, { success: true, key: { ...found, daysLeft: daysLeft(found) } });
  }

  // ── HISTÓRICO ────────────────────────────────────────────
  // GET/POST com ?code=XXXX (ou body.code) -> devolve a timeline daquela key.
  if (action === "history") {
    if (!checkAdmin(event.headers?.authorization)) return json(401, { error: "Não autorizado" });
    const code = (event.queryStringParameters || {}).code || body.code;
    if (!code) return json(400, { error: "Code não informado" });

    const found = DB.keys.find(k => k.code === code);
    if (!found) return json(404, { error: "Key não encontrada" });

    return json(200, { code: found.code, history: found.history || [] });
  }

  return json(404, { error: "Ação não encontrada" });
};