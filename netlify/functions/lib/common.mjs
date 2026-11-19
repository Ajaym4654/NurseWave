
import pg from "pg";
import bcrypt from "bcryptjs";
import { SignJWT, jwtVerify } from "jose";
import { randomUUID } from "node:crypto";

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

async function ensureSessionTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id UUID PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ip_address TEXT,
      user_agent TEXT,
      device_label TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ended_at TIMESTAMPTZ
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      session_id UUID,
      event_type TEXT NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function requestInfo(request) {
  const forwarded = request.headers.get("x-nf-client-connection-ip") ||
    request.headers.get("x-forwarded-for") || "";
  const ip = forwarded.split(",")[0].trim() || null;
  const ua = request.headers.get("user-agent") || "Unknown browser";
  let device = "Unknown device";
  if (/ipad|tablet/i.test(ua)) device = "Tablet";
  else if (/mobile|android|iphone/i.test(ua)) device = "Mobile";
  else device = "Desktop";
  let browser = "Browser";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/chrome\//i.test(ua)) browser = "Chrome";
  else if (/firefox\//i.test(ua)) browser = "Firefox";
  else if (/safari\//i.test(ua) && !/chrome\//i.test(ua)) browser = "Safari";
  return { ip, ua, device: `${device} · ${browser}` };
}

export async function createSession(user, request) {
  await ensureSessionTables();
  const sessionId = randomUUID();
  const info = requestInfo(request);
  await pool.query(
    "INSERT INTO user_sessions (session_id,user_id,ip_address,user_agent,device_label) VALUES ($1,$2,$3,$4,$5)",
    [sessionId,user.id,info.ip,info.ua,info.device]
  );
  await pool.query(
    "INSERT INTO activity_logs (user_id,session_id,event_type,ip_address,user_agent,details) VALUES ($1,$2,'login',$3,$4,$5)",
    [user.id,sessionId,info.ip,info.ua,JSON.stringify({device:info.device})]
  );

  const token = await new SignJWT({
    email: user.email,
    role: user.role,
    sid: sessionId
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
  const match = cookie.match(/(?:^|;\\s*)nursewave_session=([^;]+)/);
  if (!match) return null;

  try {
    const { payload } = await jwtVerify(match[1],getSecret(),{algorithms:["HS256"]});
    if (!payload.sid) return null;
    await ensureSessionTables();
    const active = await pool.query(
      "SELECT 1 FROM user_sessions WHERE session_id=$1 AND user_id=$2 AND ended_at IS NULL",
      [payload.sid,payload.sub]
    );
    if (!active.rowCount) return null;
    await pool.query("UPDATE user_sessions SET last_seen_at=NOW() WHERE session_id=$1",[payload.sid]);
    const result = await pool.query(
      `SELECT id, full_name, company_name, email, role
       FROM users WHERE id=$1 AND is_active=TRUE`,
      [payload.sub]
    );
    return result.rows[0] || null;
  } catch {
    return null;
  }
}

export async function endSession(request) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\\s*)nursewave_session=([^;]+)/);
  if (!match) return;
  try {
    const { payload } = await jwtVerify(match[1],getSecret(),{algorithms:["HS256"]});
    if (!payload.sid) return;
    await ensureSessionTables();
    const info=requestInfo(request);
    const ended=await pool.query(
      "UPDATE user_sessions SET ended_at=NOW(),last_seen_at=NOW() WHERE session_id=$1 AND ended_at IS NULL RETURNING user_id",
      [payload.sid]
    );
    if (ended.rowCount) {
      await pool.query(
        "INSERT INTO activity_logs (user_id,session_id,event_type,ip_address,user_agent,details) VALUES ($1,$2,'logout',$3,$4,$5)",
        [ended.rows[0].user_id,payload.sid,info.ip,info.ua,JSON.stringify({reason:"logout or page refresh"})]
      );
    }
  } catch (error) {
    console.error("Session end error:",error);
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
