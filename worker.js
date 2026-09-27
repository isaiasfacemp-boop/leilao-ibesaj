// ═══════════════════════════════════════════════════════
// VII/VIII Leilão IBESAJ — Worker (API + login + usuários)
// ═══════════════════════════════════════════════════════

const SESSION_DAYS = 30;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

function newId() {
  return "lote-" + Date.now().toString(36) + randomHex(3);
}

async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + ":" + password);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson(request, maxBytes) {
  const len = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (len && len > maxBytes) throw Object.assign(new Error("muito_grande"), { status: 413 });
  const text = await request.text();
  if (text.length > maxBytes) throw Object.assign(new Error("muito_grande"), { status: 413 });
  try {
    return JSON.parse(text || "{}");
  } catch (e) {
    throw Object.assign(new Error("json_invalido"), { status: 400 });
  }
}

function str(v, max = 300) {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

async function insertUser(env, { username, password, master }) {
  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  await env.DB.prepare(
    `INSERT INTO users (username, password_hash, salt, master, created_at) VALUES (?, ?, ?, ?, datetime('now'))`
  ).bind(username, hash, salt, master ? 1 : 0).run();
}

async function createSession(env, username) {
  const token = randomHex(32);
  const expires = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)").bind(token, username, expires).run();
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();
  return token;
}

async function getAuthUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.username, u.master FROM sessions s
     JOIN users u ON u.username = s.username
     WHERE s.token = ? AND s.expires_at > ?`
  ).bind(token, Date.now()).first();
  if (!row) return null;
  return { username: row.username, master: !!row.master, token };
}

function loteFromRow(row) {
  return {
    id: row.id,
    numero: row.numero,
    codigoBarras: row.codigoBarras || "",
    estabelecimento: row.estabelecimento || "",
    produto: row.produto,
    valorComercial: row.valorComercial || 0,
    valorInicial: row.valorInicial || 0,
    valorArrematado: row.valorArrematado,
    comprador: row.comprador || "",
    contato: row.contato || "",
    formaPgto: row.formaPgto || "",
    pago: row.pago || "NAO",
    status: row.status || "DISPONÍVEL",
    foto: row.foto || "",
    atualizadoPor: row.atualizadoPor,
    atualizadoEm: row.atualizadoEm
  };
}

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  // ───────── SETUP (primeiro admin) ─────────
  if (path === "/api/setup-status" && method === "GET") {
    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
    return json({ hasUsers: (row && row.n) > 0 });
  }

  if (path === "/api/setup" && method === "POST") {
    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
    if (row && row.n > 0) return json({ error: "ja_configurado", message: "O administrador já foi criado." }, 403);
    const body = await readJson(request, 10000);
    const username = str(body.username, 60);
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || password.length < 4) return json({ error: "dados", message: "Informe usuário e uma senha com pelo menos 4 caracteres." }, 400);
    await insertUser(env, { username, password, master: true });
    const token = await createSession(env, username);
    return json({ token, user: { username, master: true } });
  }

  // ───────── LOGIN / LOGOUT ─────────
  if (path === "/api/login" && method === "POST") {
    const body = await readJson(request, 10000);
    const username = str(body.username, 60);
    const password = typeof body.password === "string" ? body.password : "";
    const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    if (!row || (await hashPassword(password, row.salt)) !== row.password_hash) {
      return json({ error: "credenciais", message: "Usuário ou senha incorretos." }, 401);
    }
    const token = await createSession(env, username);
    return json({ token, user: { username: row.username, master: !!row.master } });
  }

  // ───────── Tudo abaixo exige login ─────────
  const auth = await getAuthUser(request, env);
  if (!auth) return json({ error: "nao_autenticado", message: "Faça login novamente." }, 401);

  if (path === "/api/logout" && method === "POST") {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(auth.token).run();
    return json({ ok: true });
  }

  if (path === "/api/me" && method === "GET") {
    return json({ user: { username: auth.username, master: auth.master } });
  }

  if (path === "/api/verify-password" && method === "POST") {
    const body = await readJson(request, 2000);
    const password = typeof body.password === "string" ? body.password : "";
    const row = await env.DB.prepare("SELECT salt, password_hash FROM users WHERE username = ?").bind(auth.username).first();
    if (!row) return json({ ok: false });
    const hash = await hashPassword(password, row.salt);
    return json({ ok: hash === row.password_hash });
  }

  // ───────── CONFIG DO LEILÃO ─────────
  if (path === "/api/config" && method === "GET") {
    const row = await env.DB.prepare("SELECT * FROM config WHERE id = 1").first();
    return json({ config: row || {} });
  }

  if (path === "/api/config" && method === "PUT") {
    const body = await readJson(request, 10000);
    await env.DB.prepare(
      `UPDATE config SET nome=?, edicao=?, data=?, ano=?, descontoPadrao=? WHERE id = 1`
    ).bind(
      str(body.nome, 120) || "Leilão",
      str(body.edicao, 30),
      str(body.data, 20),
      str(body.ano, 10),
      str(body.descontoPadrao, 10)
    ).run();
    return json({ ok: true });
  }

  // ───────── LOTES ─────────
  if (path === "/api/lotes/recalcular-inicial" && method === "POST") {
    if (!auth.master) return json({ error: "sem_permissao", message: "Somente o administrador pode recalcular os lotes." }, 403);
    const cfg = await env.DB.prepare("SELECT descontoPadrao FROM config WHERE id = 1").first();
    const pct = parseFloat((cfg && cfg.descontoPadrao || "0").replace(",", "."));
    if (!pct) return json({ error: "sem_desconto", message: "Nenhum desconto padrão configurado." }, 400);
    const result = await env.DB.prepare(
      "UPDATE lotes SET valorInicial = ROUND(valorComercial * ?, 2) WHERE valorComercial > 0"
    ).bind(1 - pct / 100).run();
    return json({ ok: true, afetados: result.meta.changes, percentual: pct });
  }

  if (path === "/api/lotes" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM lotes ORDER BY numero ASC").all();
    return json({ lotes: (results || []).map(loteFromRow) });
  }

  if (path === "/api/lotes" && method === "POST") {
    const body = await readJson(request, 3000000); // permite fotos em base64
    const numero = parseInt(body.numero, 10);
    const produto = str(body.produto, 200);
    if (!numero || !produto) return json({ error: "dados", message: "Informe número e produto." }, 400);

    const existente = await env.DB.prepare("SELECT id FROM lotes WHERE numero = ?").bind(numero).first();
    if (existente) return json({ error: "numero_existe", message: `O lote nº ${numero} já existe.` }, 409);

    const codigoBarras = str(body.codigoBarras, 60);
    if (codigoBarras) {
      const codConflito = await env.DB.prepare("SELECT numero FROM lotes WHERE codigoBarras = ? AND codigoBarras != ''").bind(codigoBarras).first();
      if (codConflito) return json({ error: "codigo_existe", message: `Código já usado no lote nº ${codConflito.numero}.` }, 409);
    }

    const id = newId();
    await env.DB.prepare(
      `INSERT INTO lotes (id, numero, codigoBarras, estabelecimento, produto, valorComercial, valorInicial, valorArrematado, comprador, contato, formaPgto, pago, status, foto, atualizadoPor, atualizadoEm)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '', '', '', 'NAO', 'DISPONÍVEL', ?, ?, ?)`
    ).bind(
      id, numero, codigoBarras, str(body.estabelecimento, 150), produto,
      parseFloat(body.valorComercial) || 0, parseFloat(body.valorInicial) || 0,
      str(body.foto, 2000000), auth.username, Date.now()
    ).run();

    return json({ id });
  }

  if (path.startsWith("/api/lotes/") && method === "PUT") {
    const id = decodeURIComponent(path.slice("/api/lotes/".length));
    const target = await env.DB.prepare("SELECT * FROM lotes WHERE id = ?").bind(id).first();
    if (!target) return json({ error: "nao_encontrado" }, 404);

    const body = await readJson(request, 3000000);

    // Se está mudando número ou código de barras, valida duplicidade
    if (body.numero !== undefined) {
      const novoNumero = parseInt(body.numero, 10);
      if (novoNumero !== target.numero) {
        const conflito = await env.DB.prepare("SELECT id FROM lotes WHERE numero = ? AND id != ?").bind(novoNumero, id).first();
        if (conflito) return json({ error: "numero_existe", message: `O lote nº ${novoNumero} já existe.` }, 409);
      }
    }
    if (body.codigoBarras !== undefined && body.codigoBarras) {
      const conflito = await env.DB.prepare("SELECT numero FROM lotes WHERE codigoBarras = ? AND id != ? AND codigoBarras != ''").bind(body.codigoBarras, id).first();
      if (conflito) return json({ error: "codigo_existe", message: `Código já usado no lote nº ${conflito.numero}.` }, 409);
    }

    // Monta update dinâmico apenas com os campos enviados
    const campos = ["numero","codigoBarras","estabelecimento","produto","valorComercial","valorInicial","valorArrematado","comprador","contato","formaPgto","pago","status","foto"];
    const sets = [];
    const vals = [];
    for (const c of campos) {
      if (body[c] !== undefined) {
        sets.push(`${c} = ?`);
        vals.push(body[c]);
      }
    }
    if (!sets.length) return json({ error: "dados", message: "Nada para atualizar." }, 400);
    sets.push("atualizadoPor = ?", "atualizadoEm = ?");
    vals.push(auth.username, Date.now());
    vals.push(id);

    await env.DB.prepare(`UPDATE lotes SET ${sets.join(", ")} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }

  if (path.startsWith("/api/lotes/") && method === "DELETE") {
    if (!auth.master) return json({ error: "sem_permissao", message: "Somente o administrador pode excluir lotes." }, 403);
    const id = decodeURIComponent(path.slice("/api/lotes/".length));
    await env.DB.prepare("DELETE FROM lotes WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  // ───────── USUÁRIOS (somente admin/master) ─────────
  if (path === "/api/users" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT username, master, created_at FROM users ORDER BY master DESC, username").all();
    return json({ users: results || [] });
  }

  if (path === "/api/users" && method === "POST") {
    if (!auth.master) return json({ error: "sem_permissao", message: "Somente o administrador pode criar usuários." }, 403);
    const body = await readJson(request, 10000);
    const username = str(body.username, 60);
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || password.length < 4) return json({ error: "dados", message: "Informe usuário e uma senha com pelo menos 4 caracteres." }, 400);
    const exists = await env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(username).first();
    if (exists) return json({ error: "existe", message: "Já existe um usuário com esse nome." }, 409);
    await insertUser(env, { username, password, master: !!body.master });
    return json({ ok: true });
  }

  if (path.startsWith("/api/users/") && method === "DELETE") {
    if (!auth.master) return json({ error: "sem_permissao", message: "Somente o administrador pode remover usuários." }, 403);
    const username = decodeURIComponent(path.slice("/api/users/".length));
    if (username === auth.username) return json({ error: "auto_remocao", message: "Você não pode remover seu próprio usuário." }, 400);
    const target = await env.DB.prepare("SELECT master FROM users WHERE username = ?").bind(username).first();
    if (!target) return json({ error: "nao_encontrado" }, 404);
    if (target.master) {
      const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE master = 1").first();
      if (row.n <= 1) return json({ error: "ultimo_admin", message: "Não é possível remover o único administrador." }, 400);
    }
    await env.DB.batch([
      env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(username),
      env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username)
    ]);
    return json({ ok: true });
  }

  return json({ error: "nao_encontrado" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }
    try {
      return await handleApi(request, env, url);
    } catch (e) {
      const status = (e && e.status) || 500;
      const messages = {
        413: "Os dados ficaram grandes demais (fotos muito pesadas?).",
        400: "Dados inválidos."
      };
      return json({ error: (e && e.message) || "erro", message: messages[status] || "Erro no servidor." }, status);
    }
  }
};
