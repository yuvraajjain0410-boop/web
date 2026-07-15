const crypto = require("crypto");

function json(body, status = 200, headers = {}) {
  return { statusCode: status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers }, body: JSON.stringify(body) };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json({ error: "Method not allowed" }, 405);

  let password = "";
  try { password = JSON.parse(event.body || "{}").password || ""; } catch { /* invalid request */ }
  const { ADMIN_PASSWORD, SESSION_SECRET } = process.env;
  if (!ADMIN_PASSWORD || !SESSION_SECRET || password !== ADMIN_PASSWORD) return json({ error: "Incorrect password" }, 401);

  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000 })).toString("base64url");
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  const token = `${payload}.${signature}`;
  return json({ ok: true }, 200, {
    "Set-Cookie": `mp_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
  });
};
