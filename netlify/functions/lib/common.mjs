
import pg from "pg";
import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 2,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

function getSecret() {
  const value = process.env.SESSION_SECRET;
  if (!value || value.length < 32) {
    throw new Error("SESSION_SECRET is missing or invalid");
  }
  return new TextEncoder().encode(value);
}

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

export async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

export async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

export async function createSession(user) {
  const token = await new SignJWT({
    email: user.email,
    role: user.role
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(String(user.id))
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(getSecret());

  return `nursewave_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`;
}

export function clearSession() {
  return "nursewave_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

export async function getSession(request) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)nursewave_session=([^;]+)/);

  if (!match) return null;

  try {
    const { payload } = await jwtVerify(
      match[1],
      getSecret(),
      { algorithms: ["HS256"] }
    );

    const result = await pool.query(
      `SELECT id, full_name, company_name, email, role
       FROM users
       WHERE id = $1 AND is_active = TRUE`,
      [payload.sub]
    );

    return result.rows[0] || null;
  } catch {
    return null;
  }
}

export function publicUser(user) {
  return {
    id: user.id,
    full_name: user.full_name,
    company_name: user.company_name,
    email: user.email,
    role: user.role
  };
}
