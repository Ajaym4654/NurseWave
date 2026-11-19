import { createHash, randomBytes } from "node:crypto";
import {
  pool, json, readBody, getSession, hashPassword
} from "./lib/common.mjs";

const sha256 = value => createHash("sha256").update(value).digest("hex");

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      generated_at TIMESTAMPTZ
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function requireSuperAdmin(request) {
  const user = await getSession(request);
  return user?.role === "super_admin" ? user : null;
}

export default async request => {
  try {
    await ensureTables();

    if (request.method === "GET") {
      const admin = await requireSuperAdmin(request);
      if (!admin) return json({ success:false, message:"Super Admin access required." }, 403);
      const result = await pool.query(`
        SELECT r.id, r.email, r.status, r.created_at, r.generated_at,
               u.full_name, u.company_name
        FROM password_reset_requests r
        JOIN users u ON u.id = r.user_id
        ORDER BY r.created_at DESC
        LIMIT 100
      `);
      return json({ success:true, requests:result.rows });
    }

    if (request.method !== "POST") {
      return json({ success:false, message:"Method not allowed." }, 405);
    }

    const body = await readBody(request);
    if (!body) return json({ success:false, message:"Invalid request body." }, 400);

    if (body.action === "request") {
      const email = String(body.email || "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json({ success:false, message:"Please enter a valid email address." }, 400);
      }

      const found = await pool.query(
        "SELECT id FROM users WHERE email=$1 AND is_active=TRUE LIMIT 1",
        [email]
      );
      if (found.rowCount) {
        await pool.query(
          "INSERT INTO password_reset_requests (user_id,email) VALUES ($1,$2)",
          [found.rows[0].id,email]
        );
      }
      return json({
        success:true,
        message:"If an active account exists for that email, its reset request has been sent to the Super Admin."
      });
    }

    if (body.action === "generate") {
      const admin = await requireSuperAdmin(request);
      if (!admin) return json({ success:false, message:"Super Admin access required." }, 403);
      const requestId = Number(body.request_id);
      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        return json({ success:false, message:"Invalid reset request." }, 400);
      }

      const found = await pool.query(
        "SELECT id,user_id,email FROM password_reset_requests WHERE id=$1 AND status='pending' LIMIT 1",
        [requestId]
      );
      if (!found.rowCount) return json({ success:false, message:"This request is no longer pending." }, 404);

      const item = found.rows[0];
      const rawToken = randomBytes(32).toString("base64url");
      const tokenHash = sha256(rawToken);
      await pool.query(
        "INSERT INTO password_reset_tokens (user_id,token_hash,expires_at) VALUES ($1,$2,NOW()+INTERVAL '30 minutes')",
        [item.user_id,tokenHash]
      );
      await pool.query(
        "UPDATE password_reset_requests SET status='generated',generated_at=NOW() WHERE id=$1",
        [requestId]
      );

      const origin = request.headers.get("origin") || new URL(request.url).origin;
      const link = `${origin}/?reset=${encodeURIComponent(rawToken)}`;
      return json({ success:true, link, message:"One-time reset link generated. It expires in 30 minutes." });
    }

    if (body.action === "complete") {
      const token = String(body.token || "");
      const password = String(body.password || "");
      if (token.length < 30 || token.length > 200) {
        return json({ success:false, message:"This reset link is invalid or expired." }, 400);
      }
      if (password.length < 10 || password.length > 128) {
        return json({ success:false, message:"Password must be 10–128 characters long." }, 400);
      }

      const tokenHash = sha256(token);
      const found = await pool.query(
        "SELECT id,user_id FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW() LIMIT 1",
        [tokenHash]
      );
      if (!found.rowCount) {
        return json({ success:false, message:"This reset link is invalid, expired, or already used. Please request a new one." }, 400);
      }

      const passwordHash = await hashPassword(password);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const locked = await client.query(
          "SELECT id,user_id FROM password_reset_tokens WHERE id=$1 AND used_at IS NULL AND expires_at>NOW() FOR UPDATE",
          [found.rows[0].id]
        );
        if (!locked.rowCount) {
          await client.query("ROLLBACK");
          return json({ success:false, message:"This reset link has already been used or expired." }, 400);
        }
        await client.query("UPDATE users SET password_hash=$1 WHERE id=$2", [passwordHash,locked.rows[0].user_id]);
        await client.query("UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL", [locked.rows[0].user_id]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
      return json({ success:true, message:"Your password has been updated. You can now log in." });
    }

    return json({ success:false, message:"Unknown action." }, 400);
  } catch (error) {
    console.error("Password reset error:",error);
    return json({ success:false, message:"Unable to process the password request. Please try again." }, 500);
  }
};
