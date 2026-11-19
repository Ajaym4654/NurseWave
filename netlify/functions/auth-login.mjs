
import {
  pool,
  json,
  readBody,
  verifyPassword,
  createSession,
  publicUser
} from "./lib/common.mjs";

export default async (request) => {
  if (request.method !== "POST") {
    return json({ success: false, message: "Method not allowed" }, 405);
  }

  const body = await readBody(request);

  if (!body) {
    return json({ success: false, message: "Invalid request body" }, 400);
  }

  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!email || !password) {
    return json({
      success: false,
      message: "Email and password are required."
    }, 400);
  }

  try {
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved'`);

    // Keep the configured Super Admin account active so it cannot be locked out
    // by an older inactive flag left in the users table.
    await pool.query(
      `UPDATE users SET is_active=TRUE
       WHERE email='ajaym4654@gmail.com' AND role='super_admin' AND is_active=FALSE`
    );

    const result = await pool.query(
      `SELECT id, full_name, company_name, email,
              password_hash, role, is_active, approval_status
       FROM users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    const user = result.rows[0];

    if (user?.role === "employer" && user.approval_status === "pending") {
      return json({ success:false, message:"Your account is waiting for Super Admin approval. Please try again after approval." }, 403);
    }
    if (user?.role === "employer" && user.approval_status === "denied") {
      return json({ success:false, message:"Your account approval was denied. Please contact the Super Admin at ajaym4654@gmail.com." }, 403);
    }

    if (
      !user ||
      !user.is_active ||
      !user.password_hash ||
      !(await verifyPassword(password, user.password_hash))
    ) {
      return json({
        success: false,
        message: "Invalid email or password."
      }, 401);
    }

    const cookie = await createSession(user, request);

    return json({
      success: true,
      message: "Login successful.",
      user: publicUser(user)
    }, 200, {
      "Set-Cookie": cookie
    });

  } catch (error) {
    console.error("Login error:", error);

    return json({
      success: false,
      message: "Unable to login. Please try again."
    }, 500);
  }
};
