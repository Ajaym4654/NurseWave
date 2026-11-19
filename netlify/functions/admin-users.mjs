import { createClient } from "@supabase/supabase-js";
import { pool, json, getSession } from "./lib/common.mjs";

const BUCKET = "nursewave-resumes";
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth:{persistSession:false,autoRefreshToken:false} }
);

export default async request => {
  const admin = await getSession(request);
  if (!admin || admin.role !== "super_admin") {
    return json({success:false,message:"Super Admin access required."},403);
  }
  if (request.method !== "DELETE") {
    return json({success:false,message:"Method not allowed."},405);
  }

  const url = new URL(request.url);
  const userId = Number(url.searchParams.get("id"));
  if (!Number.isSafeInteger(userId) || userId < 1) {
    return json({success:false,message:"Select a valid user account."},400);
  }
  if (String(userId) === String(admin.id)) {
    return json({success:false,message:"You cannot delete your own Super Admin account."},400);
  }

  const client = await pool.connect();
  let storageKeys = [];
  try {
    await client.query("BEGIN");
    const target = await client.query(
      "SELECT id,full_name,email,company_name,role FROM users WHERE id=$1 FOR UPDATE",
      [userId]
    );
    if (!target.rowCount) {
      await client.query("ROLLBACK");
      return json({success:false,message:"User account not found."},404);
    }
    if (target.rows[0].role !== "employer") {
      await client.query("ROLLBACK");
      return json({success:false,message:"Only employer/recruiter accounts can be deleted. Super Admin accounts are protected."},403);
    }

    const jobs = await client.query("SELECT id FROM jobs WHERE owner_user_id=$1",[userId]);
    const jobIds = jobs.rows.map(row=>row.id);
    const applications = await client.query(
      jobIds.length
        ? "SELECT id FROM applications WHERE employer_id=$1 OR job_id=ANY($2)"
        : "SELECT id FROM applications WHERE employer_id=$1",
      jobIds.length ? [userId,jobIds] : [userId]
    );
    const applicationIds = applications.rows.map(row=>row.id);

    if (applicationIds.length) {
      const resumes = await client.query(
        "SELECT storage_key FROM resumes WHERE application_id=ANY($1)",
        [applicationIds]
      );
      storageKeys = resumes.rows.map(row=>row.storage_key).filter(Boolean);
      await client.query("DELETE FROM resumes WHERE application_id=ANY($1)",[applicationIds]);
      await client.query("DELETE FROM applications WHERE id=ANY($1)",[applicationIds]);
    }

    if (jobIds.length) {
      await client.query("DELETE FROM jobs WHERE id=ANY($1)",[jobIds]);
    }

    await client.query(
      "INSERT INTO activity_logs (user_id,event_type,details) VALUES ($1,'admin_user_deleted',$2::jsonb)",
      [admin.id,JSON.stringify({
        deleted_user_id:userId,
        deleted_email:target.rows[0].email,
        deleted_company:target.rows[0].company_name,
        deleted_jobs:jobIds.length,
        deleted_applications:applicationIds.length
      })]
    );
    await client.query("DELETE FROM users WHERE id=$1",[userId]);
    await client.query("COMMIT");

    if (storageKeys.length) {
      const {error}=await supabase.storage.from(BUCKET).remove(storageKeys);
      if (error) console.error("Deleted user's resume cleanup error:",error);
    }

    return json({
      success:true,
      message:`${target.rows[0].full_name||target.rows[0].email}'s account deleted. ${jobIds.length} job(s), ${applicationIds.length} application(s) and linked resumes were removed.`,
      deleted:{user_id:userId,jobs:jobIds.length,applications:applicationIds.length}
    });
  } catch(error) {
    await client.query("ROLLBACK");
    console.error("Admin user deletion error:",error);
    return json({success:false,message:"Unable to delete this user account. No changes were committed."},500);
  } finally {
    client.release();
  }
};
