
import { pool, json, readBody } from "./lib/common.mjs";
import { hash } from "bcryptjs";
import { timingSafeEqual } from "node:crypto";

export default async (request) => {
  if (request.method !== "POST") {
    return json({ success: false, message: "Method not allowed." }, 405);
  }

  try {
    const expected = process.env.ADMIN_SETUP_SECRET || "";
    const supplied = request.headers.get("x-admin-setup-secret") || "";

    if (
      !expected ||
      !supplied ||
      Buffer.byteLength(expected) !== Buffer.byteLength(supplied) ||
      !timingSafeEqual(Buffer.from(expected), Buffer.from(supplied))
    ) {
      return json({ success: false, message: "Unauthorized." }, 401);
    }

    const body = await readBody(request);
    const password = String(body?.password || "");

    if (password.length < 10 || password.length > 128) {
      return json({
        success: false,
        message: "Password must be 10–128 characters."
      }, 400);
    }

    const passwordHash = await hash(password, 12);

    const result = await pool.query(
      `UPDATE users
       SET password_hash = $1, is_active = TRUE
       WHERE email = $2
         AND role = 'super_admin'
         AND password_hash IS NULL
         AND is_active = FALSE
       RETURNING id, email, role, is_active`,
      [passwordHash, "ajaym4654@gmail.com"]
    );

    if (!result.rowCount) {
      return json({
        success: false,
        message: "Admin account not found, already activated, or unavailable."
      }, 409);
    }

    return json({
      success: true,
      message: "Super Admin activated successfully."
    });
  } catch (error) {
    console.error("Admin bootstrap error:", error);
    return json({
      success: false,
      message: "Unable to activate admin account."
    }, 500);
  }
};
