const AGES = ["3-5", "5-7", "7-9"];
const KINDS = ["picture", "story", "activity"];
const COOKIE = "omb_admin";
const SESSION_SECONDS = 12 * 60 * 60;
const enc = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
  });
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return "";
}

async function isAuthed(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const token = getCookie(request, COOKIE);
  const [exp, sig] = token.split(".");
  if (!exp || !sig || !/^\d+$/.test(exp)) return false;
  if (Number(exp) < Math.floor(Date.now() / 1000)) return false;
  const expected = await hmac(env.ADMIN_PASSWORD, "session:" + exp);
  return safeEqual(sig, expected);
}

function cookieHeader(value, maxAge) {
  return `${COOKIE}=${value}; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function clean(body) {
  if (!body || typeof body !== "object") return { error: "Bad request." };
  const title = String(body.title || "").trim();
  const tagline = String(body.tagline || "").trim();
  const age = String(body.age_group || "");
  const kind = String(body.kind || "");
  const price = Number(body.price);
  let cover = String(body.cover || "").trim();

  if (!title || title.length > 120) return { error: "Title is required (up to 120 characters)." };
  if (tagline.length > 200) return { error: "Tagline is too long (up to 200 characters)." };
  if (!AGES.includes(age)) return { error: "Pick an age group." };
  if (!KINDS.includes(kind)) return { error: "Pick a kind of book." };
  if (!Number.isInteger(price) || price < 1 || price > 100000) return { error: "Price must be a whole number of rupees." };
  if (cover && (cover.length > 500 || !/^(https:\/\/|covers\/)/.test(cover))) {
    return { error: "Cover must be an https:// link or a path like covers/name.jpg." };
  }
  return {
    value: {
      title, tagline, age_group: age, kind, price,
      cover: cover || null,
      in_stock: body.in_stock ? 1 : 0,
      hidden: body.hidden ? 1 : 0,
    },
  };
}

async function handleAdmin(request, env, url) {
  const path = url.pathname;

  if (!env.ADMIN_PASSWORD) {
    return json({ error: "Admin login is not set up yet." }, 503);
  }

  // Block requests that come from another website.
  const origin = request.headers.get("Origin");
  if (request.method !== "GET" && origin && origin !== url.origin) {
    return json({ error: "Not allowed." }, 403);
  }

  if (path === "/api/admin/login" && request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (e) {}
    const given = String(body.password || "");
    const same = safeEqual(await hmac("pw-check", given), await hmac("pw-check", env.ADMIN_PASSWORD));
    if (!same) {
      await new Promise((r) => setTimeout(r, 800));
      return json({ error: "Wrong password." }, 401);
    }
    const exp = String(Math.floor(Date.now() / 1000) + SESSION_SECONDS);
    const token = exp + "." + (await hmac(env.ADMIN_PASSWORD, "session:" + exp));
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader(token, SESSION_SECONDS) });
  }

  if (path === "/api/admin/logout" && request.method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader("", 0) });
  }

  if (!(await isAuthed(request, env))) {
    return json({ error: "Please log in." }, 401);
  }

  if (request.method !== "GET") {
    const type = request.headers.get("Content-Type") || "";
    if (!type.includes("application/json")) return json({ error: "Bad request." }, 415);
  }

  if (path === "/api/admin/books" && request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, title, tagline, age_group, kind, price, cover, in_stock, hidden FROM books ORDER BY sort_order, id"
    ).all();
    return json(results);
  }

  if (path === "/api/admin/books" && request.method === "POST") {
    let body;
    try { body = await request.json(); } catch (e) { return json({ error: "Bad request." }, 400); }
    const c = clean(body);
    if (c.error) return json({ error: c.error }, 400);
    const v = c.value;
    const next = await env.DB.prepare("SELECT COALESCE(MAX(sort_order), 0) + 1 AS n FROM books").first();
    const res = await env.DB.prepare(
      "INSERT INTO books (title, tagline, age_group, kind, price, cover, in_stock, hidden, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(v.title, v.tagline, v.age_group, v.kind, v.price, v.cover, v.in_stock, v.hidden, next.n).run();
    return json({ ok: true, id: res.meta.last_row_id }, 201);
  }

  const m = path.match(/^\/api\/admin\/books\/(\d+)$/);
  if (m && request.method === "PUT") {
    let body;
    try { body = await request.json(); } catch (e) { return json({ error: "Bad request." }, 400); }
    const c = clean(body);
    if (c.error) return json({ error: c.error }, 400);
    const v = c.value;
    const res = await env.DB.prepare(
      "UPDATE books SET title = ?, tagline = ?, age_group = ?, kind = ?, price = ?, cover = ?, in_stock = ?, hidden = ? WHERE id = ?"
    ).bind(v.title, v.tagline, v.age_group, v.kind, v.price, v.cover, v.in_stock, v.hidden, Number(m[1])).run();
    if (!res.meta.changes) return json({ error: "Book not found." }, 404);
    return json({ ok: true });
  }

  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/books") {
      const { results } = await env.DB.prepare(
        "SELECT id, title, tagline, age_group, kind, price, cover, in_stock FROM books WHERE hidden = 0 ORDER BY sort_order, id"
      ).all();
      return json(results);
    }

    if (url.pathname.startsWith("/api/admin/")) {
      try {
        return await handleAdmin(request, env, url);
      } catch (e) {
        return json({ error: "Something went wrong." }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};
