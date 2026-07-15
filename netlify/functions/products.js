const crypto = require("crypto");

function json(body, status = 200) {
  return { statusCode: status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }, body: JSON.stringify(body) };
}

function isAdmin(headers) {
  const { SESSION_SECRET } = process.env;
  const token = (headers.cookie || "").match(/(?:^|;\s*)mp_admin=([^;]+)/)?.[1];
  if (!token || !SESSION_SECRET) return false;
  const [payload, signature] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload || "").digest("base64url");
  if (!payload || !signature || signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try { return JSON.parse(Buffer.from(payload, "base64url").toString()).exp > Date.now(); } catch { return false; }
}

function supabaseHeaders() {
  const key = process.env.SUPABASE_SECRET_KEY;
  return { apikey: key, Authorization: `Bearer ${key}`, "Content-Type": "application/json" };
}

exports.handler = async (event) => {
  const { SUPABASE_URL, SUPABASE_SECRET_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return json({ error: "Store database is not configured" }, 503);
  const endpoint = `${SUPABASE_URL.replace(/\/$/, "")}/rest/v1/products`;

  if (event.httpMethod === "GET") {
    const response = await fetch(`${endpoint}?select=*&order=created_at.desc`, { headers: supabaseHeaders() });
    if (!response.ok) return json({ error: "Could not load products" }, 502);
    const rows = await response.json();
    return json(rows.map(row => ({
      id: row.id, name: row.name, brand: row.brand || "Men's Plaza", price: Number(row.price),
      oldPrice: Number(row.old_price || 0), cat: row.category || "Other", gender: row.gender || "Unisex",
      size: row.sizes || "", img: row.image || "", images: row.images || [], notes: row.notes || "", stock: Number(row.stock || 0)
    })));
  }

  if (event.httpMethod !== "PUT") return json({ error: "Method not allowed" }, 405);
  if (!isAdmin(event.headers)) return json({ error: "Unauthorized" }, 401);
  let products;
  try { products = JSON.parse(event.body || "[]"); } catch { return json({ error: "Invalid product data" }, 400); }
  if (!Array.isArray(products) || products.length > 500) return json({ error: "Invalid product list" }, 400);
  const rows = products.filter(p => p?.id && p?.name && Number.isFinite(Number(p.price))).map(p => ({
    id: String(p.id), name: String(p.name), brand: String(p.brand || "Men's Plaza"), price: Number(p.price), old_price: Number(p.oldPrice || 0),
    category: String(p.cat || "Other"), gender: String(p.gender || "Unisex"), sizes: String(p.size || ""), image: String(p.img || ""),
    images: Array.isArray(p.images) ? p.images : [], notes: String(p.notes || ""), stock: Number(p.stock || 0), updated_at: new Date().toISOString()
  }));
  const deleted = await fetch(`${endpoint}?id=not.is.null`, { method: "DELETE", headers: supabaseHeaders() });
  if (!deleted.ok) return json({ error: "Could not save products" }, 502);
  if (rows.length) {
    const saved = await fetch(endpoint, { method: "POST", headers: { ...supabaseHeaders(), Prefer: "return=minimal" }, body: JSON.stringify(rows) });
    if (!saved.ok) return json({ error: "Could not save products" }, 502);
  }
  return json({ ok: true, count: rows.length });
};
