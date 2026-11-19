
import { createClient } from "@supabase/supabase-js";
import { randomUUID } from "node:crypto";
import {
  pool,
  json,
  getSession
} from "./lib/common.mjs";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const BUCKET = "nursewave-resumes";
const MAX_SIZE = 5 * 1024 * 1024;

const ALLOWED_TYPES = [
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
];

export default async (request) => {
  const user = await getSession(request);

  // GET APPLICATIONS
  if (request.method === "GET") {
    if (!user) {
      return json({
        success: false,
        message: "Please log in first."
      }, 401);
    }

    try {
      const result = user.role === "super_admin"
        ? await pool.query(
            `SELECT
               a.*,
               a.candidate_name AS name,
               a.candidate_email AS email,
               a.candidate_phone AS phone,
               a.nursing_license AS license,
               j.title AS job_title,
               j.city AS job_city,
               j.state AS job_state,
               r.original_filename,
               (r.storage_key IS NOT NULL) AS has_resume
             FROM applications a
             JOIN jobs j ON j.id = a.job_id
             LEFT JOIN LATERAL (
               SELECT original_filename, storage_key
               FROM resumes
               WHERE application_id = a.id
               ORDER BY created_at DESC NULLS LAST
               LIMIT 1
             ) r ON true
             ORDER BY a.created_at DESC`
          )
        : await pool.query(
            `SELECT
               a.*,
               a.candidate_name AS name,
               a.candidate_email AS email,
               a.candidate_phone AS phone,
               a.nursing_license AS license,
               j.title AS job_title,
               j.city AS job_city,
               j.state AS job_state,
               r.original_filename,
               (r.storage_key IS NOT NULL) AS has_resume
             FROM applications a
             JOIN jobs j ON j.id = a.job_id
             LEFT JOIN LATERAL (
               SELECT original_filename, storage_key
               FROM resumes
               WHERE application_id = a.id
               ORDER BY created_at DESC NULLS LAST
               LIMIT 1
             ) r ON true
             WHERE a.employer_id = $1
             ORDER BY a.created_at DESC`,
            [user.id]
          );

      return json({
        success: true,
        applications: result.rows
      });

    } catch (error) {
      console.error("Applications fetch error:", error);

      return json({
        success: false,
        message: "Unable to load applications."
      }, 500);
    }
  }

  // DELETE APPLICATIONS — SUPER ADMIN ONLY
  if (request.method === "DELETE") {
    if (!user || user.role !== "super_admin") {
      return json({ success: false, message: "Only Super Admin can delete applications." }, 403);
    }

    const url = new URL(request.url);
    const applicationId = url.searchParams.get("id");
    const deleteAll = url.searchParams.get("all") === "true";

    if (!deleteAll && (!applicationId || !/^\d+$/.test(applicationId))) {
      return json({ success: false, message: "Select a valid application to delete." }, 400);
    }

    const client = await pool.connect();
    let storageKeys = [];

    try {
      await client.query("BEGIN");
      const selected = deleteAll
        ? await client.query("SELECT id FROM applications")
        : await client.query("SELECT id FROM applications WHERE id = $1", [applicationId]);

      if (!deleteAll && !selected.rowCount) {
        await client.query("ROLLBACK");
        return json({ success: false, message: "Application not found." }, 404);
      }

      const ids = selected.rows.map(row => row.id);
      if (ids.length) {
        const resumes = await client.query("SELECT storage_key FROM resumes WHERE application_id = ANY($1)", [ids]);
        storageKeys = resumes.rows.map(row => row.storage_key).filter(Boolean);
        await client.query("DELETE FROM resumes WHERE application_id = ANY($1)", [ids]);
        await client.query("DELETE FROM applications WHERE id = ANY($1)", [ids]);
      }

      await client.query("COMMIT");
      if (storageKeys.length) {
        const { error } = await supabase.storage.from(BUCKET).remove(storageKeys);
        if (error) console.error("Deleted application resume cleanup error:", error);
      }
      return json({ success: true, deleted: ids.length, message: ids.length + " application(s) deleted." });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Application delete error:", error);
      return json({ success: false, message: "Unable to delete application(s)." }, 500);
    } finally {
      client.release();
    }
  }

  // ONLY POST IS ALLOWED AFTER GET
  if (request.method !== "POST") {
    return json({
      success: false,
      message: "Method not allowed."
    }, 405);
  }

  let uploadedPath = null;

  try {
    const form = await request.formData();

    const jobId = String(form.get("jobId") || "").trim();
    const candidateName = String(form.get("name") || "").trim();
    const candidateEmail = String(form.get("email") || "").trim().toLowerCase();
    const candidatePhone = String(form.get("phone") || "").trim();
    const nursingLicense = String(form.get("license") || "").trim();
    const note = String(form.get("note") || "").trim();
    const file = form.get("resume");

    if (!/^\d+$/.test(jobId)) {
      return json({
        success: false,
        message: "Invalid job."
      }, 400);
    }

    if (
      !candidateName ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(candidateEmail) ||
      !nursingLicense
    ) {
      return json({
        success: false,
        message: "Please provide valid name, email and nursing license."
      }, 400);
    }

    if (
      candidateName.length > 150 ||
      candidateEmail.length > 254 ||
      candidatePhone.length > 50 ||
      nursingLicense.length > 150 ||
      note.length > 5000
    ) {
      return json({
        success: false,
        message: "Some application fields are too long."
      }, 400);
    }

    if (!file || typeof file.arrayBuffer !== "function") {
      return json({
        success: false,
        message: "Please attach your resume."
      }, 400);
    }

    if (file.size <= 0 || file.size > MAX_SIZE) {
      return json({
        success: false,
        message: "Resume must be under 5 MB."
      }, 400);
    }

    if (!ALLOWED_TYPES.includes(file.type)) {
      return json({
        success: false,
        message: "Only PDF, DOC and DOCX resumes are allowed."
      }, 400);
    }

    // CHECK JOB
    const jobResult = await pool.query(
      `SELECT id, owner_user_id
       FROM jobs
       WHERE id = $1 AND status = 'active'`,
      [jobId]
    );

    if (!jobResult.rowCount) {
      return json({
        success: false,
        message: "This job is no longer available."
      }, 404);
    }

    const employerId = jobResult.rows[0].owner_user_id;

    // SAFE FILE NAME
    const safeName = String(file.name || "resume")
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .slice(-100);

    const storageKey = `${jobId}/${randomUUID()}-${safeName}`;
    const fileBuffer = Buffer.from(await file.arrayBuffer());

    // UPLOAD RESUME TO SUPABASE STORAGE
    const upload = await supabase.storage
      .from(BUCKET)
      .upload(storageKey, fileBuffer, {
        contentType: file.type,
        upsert: false
      });

    if (upload.error) {
      console.error("Resume upload error:", upload.error);

      return json({
        success: false,
        message: "Resume upload failed. Please try again."
      }, 500);
    }

    uploadedPath = storageKey;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // SAVE APPLICATION DETAILS
      const application = await client.query(
        `INSERT INTO applications (
          job_id,
          employer_id,
          candidate_name,
          candidate_email,
          candidate_phone,
          nursing_license,
          note
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING id`,
        [
          jobId,
          employerId,
          candidateName,
          candidateEmail,
          candidatePhone || null,
          nursingLicense,
          note || null
        ]
      );

      const applicationId = application.rows[0].id;

      // LINK RESUME TO APPLICATION
      await client.query(
        `INSERT INTO resumes (
          application_id,
          storage_key,
          original_filename,
          mime_type,
          file_size
        )
        VALUES ($1,$2,$3,$4,$5)`,
        [
          applicationId,
          storageKey,
          safeName,
          file.type,
          file.size
        ]
      );

      await client.query("COMMIT");

      uploadedPath = null;

      return json({
        success: true,
        message: "Application submitted successfully."
      }, 201);

    } catch (error) {
      await client.query("ROLLBACK");
      throw error;

    } finally {
      client.release();
    }

  } catch (error) {
    console.error("Application submission error:", error);

    // REMOVE UPLOADED FILE IF DATABASE SAVE FAILED
    if (uploadedPath) {
      const { error: cleanupError } = await supabase.storage
        .from(BUCKET)
        .remove([uploadedPath]);

      if (cleanupError) {
        console.error("Resume cleanup error:", cleanupError);
      }
    }

    return json({
      success: false,
      message: "Unable to submit application. Please try again."
    }, 500);
  }
};
