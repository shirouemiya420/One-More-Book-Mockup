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

  if (path === "/api/admin/orders" && request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, created_at, name, phone, address, items, total, status, razorpay_payment_id FROM orders ORDER BY id DESC LIMIT 100"
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


const MAX_ITEMS = 20;

async function createRazorpayOrder(env, amountPaise, receipt, orderId) {
  const auth = btoa(env.RAZORPAY_KEY_ID + ":" + env.RAZORPAY_KEY_SECRET);
  const res = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: { Authorization: "Basic " + auth, "Content-Type": "application/json" },
    body: JSON.stringify({ amount: amountPaise, currency: "INR", receipt, notes: { order_id: String(orderId) } }),
  });
  if (!res.ok) return null;
  return await res.json();
}

async function handlePayments(request, env, url) {
  if (request.method !== "POST") return json({ error: "Not found." }, 404);
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: "Checkout is not set up yet." }, 503);
  }
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) return json({ error: "Not allowed." }, 403);
  if (!(request.headers.get("Content-Type") || "").includes("application/json")) {
    return json({ error: "Bad request." }, 415);
  }
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: "Bad request." }, 400); }
  if (!body || typeof body !== "object") return json({ error: "Bad request." }, 400);

  if (url.pathname === "/api/checkout") {
    const name = String(body.name || "").trim();
    const phone = String(body.phone || "").replace(/\D/g, "");
    const address = String(body.address || "").trim();
    if (name.length < 2 || name.length > 100) return json({ error: "Please enter your name." }, 400);
    if (phone.length < 10 || phone.length > 15) return json({ error: "Please enter a valid phone number." }, 400);
    if (address.length < 10 || address.length > 400) return json({ error: "Please enter your full delivery address." }, 400);

    if (!Array.isArray(body.items) || body.items.length === 0 || body.items.length > MAX_ITEMS) {
      return json({ error: "Your bag is empty." }, 400);
    }
    const wanted = new Map();
    for (const it of body.items) {
      const id = Number(it && it.id);
      const qty = Number(it && it.qty);
      if (!Number.isInteger(id) || id < 1 || !Number.isInteger(qty) || qty < 1 || qty > 99) {
        return json({ error: "Something is wrong with your bag." }, 400);
      }
      wanted.set(id, Math.min(99, (wanted.get(id) || 0) + qty));
    }
    const ids = [...wanted.keys()];
    const marks = ids.map(() => "?").join(",");
    const { results } = await env.DB.prepare(
      `SELECT id, title, price, in_stock, hidden FROM books WHERE id IN (${marks})`
    ).bind(...ids).all();
    if (results.length !== ids.length) return json({ error: "A book in your bag is no longer available." }, 400);

    const lines = [];
    let total = 0;
    for (const r of results) {
      if (r.hidden || !r.in_stock) return json({ error: r.title + " is sold out." }, 400);
      const qty = wanted.get(r.id);
      lines.push({ id: r.id, title: r.title, qty, price: r.price });
      total += qty * r.price;
    }
    if (!Number.isInteger(total) || total < 1 || total > 100000) {
      return json({ error: "This order total is not allowed." }, 400);
    }

    const ins = await env.DB.prepare(
      "INSERT INTO orders (name, phone, address, items, total, status) VALUES (?, ?, ?, ?, ?, 'created')"
    ).bind(name, phone, address, JSON.stringify(lines), total).run();
    const orderId = ins.meta.last_row_id;

    const rz = await createRazorpayOrder(env, total * 100, "omb_" + orderId, orderId);
    if (!rz || !rz.id) {
      await env.DB.prepare("UPDATE orders SET status = 'failed' WHERE id = ?").bind(orderId).run();
      return json({ error: "Could not start payment. Please try again." }, 502);
    }
    await env.DB.prepare("UPDATE orders SET razorpay_order_id = ? WHERE id = ?").bind(rz.id, orderId).run();
    return json({ orderId, razorpayOrderId: rz.id, amount: total * 100, currency: "INR", keyId: env.RAZORPAY_KEY_ID });
  }

  if (url.pathname === "/api/verify") {
    const rzOrder = String(body.razorpay_order_id || "");
    const rzPay = String(body.razorpay_payment_id || "");
    const rzSig = String(body.razorpay_signature || "");
    if (!/^order_[A-Za-z0-9]+$/.test(rzOrder) || !/^pay_[A-Za-z0-9]+$/.test(rzPay) || !/^[a-f0-9]{64}$/.test(rzSig)) {
      return json({ error: "Payment could not be verified." }, 400);
    }
    const order = await env.DB.prepare(
      "SELECT id, status FROM orders WHERE razorpay_order_id = ?"
    ).bind(rzOrder).first();
    if (!order) return json({ error: "Order not found." }, 404);

    const expected = await hmac(env.RAZORPAY_KEY_SECRET, rzOrder + "|" + rzPay);
    if (!safeEqual(rzSig, expected)) return json({ error: "Payment could not be verified." }, 400);

    if (order.status !== "paid") {
      await env.DB.prepare(
        "UPDATE orders SET status = 'paid', razorpay_payment_id = ? WHERE id = ? AND status = 'created'"
      ).bind(rzPay, order.id).run();
    }
    return json({ ok: true, orderId: order.id });
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

    if (url.pathname === "/api/checkout" || url.pathname === "/api/verify") {
      try {
        return await handlePayments(request, env, url);
      } catch (e) {
        return json({ error: "Something went wrong." }, 500);
      }
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
