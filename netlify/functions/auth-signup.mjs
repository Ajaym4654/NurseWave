
import {
  pool,
  json,
  readBody,
  hashPassword,
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

  const fullName = String(body.full_name || "").trim();
  const companyName = String(body.company_name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!fullName || !companyName || !email || !password) {
    return json({
      success: false,
      message: "Please fill in all required fields."
    }, 400);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({
      success: false,
      message: "Please enter a valid email address."
    }, 400);
  }

  if (fullName.length > 120 || companyName.length > 160) {
    return json({
      success: false,
      message: "Name or company name is too long."
    }, 400);
  }

  if (password.length < 10 || password.length > 128) {
    return json({
      success: false,
      message: "Password must be 10–128 characters long."
    }, 400);
  }

  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rowCount > 0) {
      return json({
        success: false,
        message: "An account with this email already exists."
      }, 409);
    }

    const passwordHash = await hashPassword(password);

    const result = await pool.query(
      `INSERT INTO users
        (full_name, company_name, email, password_hash, role, is_active)
       VALUES ($1, $2, $3, $4, 'employer', TRUE)
       RETURNING id, full_name, company_name, email, role`,
      [fullName, companyName, email, passwordHash]
    );

    const user = result.rows[0];
    const cookie = await createSession(user);

    return json({
      success: true,
      message: "Account created successfully.",
      user: publicUser(user)
    }, 201, {
      "Set-Cookie": cookie
    });

  } catch (error) {
    console.error("Signup error:", error);

    if (error.code === "23505") {
      return json({
        success: false,
        message: "An account with this email already exists."
      }, 409);
    }

    return json({
      success: false,
      message: "Unable to create account. Please try again."
    }, 500);
  }
};
