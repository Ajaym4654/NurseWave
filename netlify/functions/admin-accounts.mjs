import { pool, json, readBody, getSession } from "./lib/common.mjs";

async function ensureApprovalColumn() {
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved'`);
}

async function requireAdmin(request) {
  const user = await getSession(request);
  return user?.role === "super_admin" ? user : null;
}

export default async request => {
  try {
    await ensureApprovalColumn();
    const admin = await requireAdmin(request);
    if (!admin) return json({ success:false, message:"Super Admin access required." },403);

    if (request.method === "GET") {
      const result = await pool.query(`
        SELECT id,full_name,company_name,email,created_at,approval_status
        FROM users
        WHERE role='employer' AND approval_status IN ('pending','denied')
        ORDER BY CASE WHEN approval_status='pending' THEN 0 ELSE 1 END, created_at DESC
        LIMIT 200
      `);
      return json({success:true,accounts:result.rows});
    }

    if (request.method !== "POST") return json({success:false,message:"Method not allowed."},405);

    const body = await readBody(request);
    const userId = Number(body?.user_id);
    const action = String(body?.action || "");
    if (!Number.isSafeInteger(userId) || userId < 1 || !["allow","deny"].includes(action)) {
      return json({success:false,message:"Invalid account approval action."},400);
    }

    const status = action === "allow" ? "approved" : "denied";
    const active = action === "allow";
    const updated = await pool.query(`
      UPDATE users SET approval_status=$1,is_active=$2
      WHERE id=$3 AND role='employer' AND approval_status IN ('pending','denied')
      RETURNING id,full_name,email,approval_status
    `,[status,active,userId]);

    if (!updated.rowCount) return json({success:false,message:"This account could not be updated. It may already be approved or no longer exist."},404);

    await pool.query(
      "INSERT INTO activity_logs (user_id,event_type,details) VALUES ($1,$2,$3::jsonb)",
      [admin.id,`account_${action}`,JSON.stringify({target_user_id:userId,email:updated.rows[0].email})]
    ).catch(()=>{});

    return json({
      success:true,
      message:action === "allow" ? "Account approved. The employer can now log in." : "Account approval denied.",
      account:updated.rows[0]
    });
  } catch (error) {
    console.error("Account approval error:",error);
    return json({success:false,message:"Unable to process account approval."},500);
  }
};
