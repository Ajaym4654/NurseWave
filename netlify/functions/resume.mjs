
import { createClient } from "@supabase/supabase-js";
import { pool, json, getSession } from "./lib/common.mjs";

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

export default async (request) => {
  if (request.method !== "GET") {
    return json({ success: false, message: "Method not allowed." }, 405);
  }

  const user = await getSession(request);

  if (!user) {
    return json({ success: false, message: "Please log in first." }, 401);
  }

  const url = new URL(request.url);
  const applicationId = url.searchParams.get("applicationId");

  if (!applicationId || !/^\d+$/.test(applicationId)) {
    return json({ success: false, message: "Invalid application ID." }, 400);
  }

  try {
    const result = await pool.query(
      `SELECT
         r.storage_key,
         r.original_filename,
         r.mime_type,
         r.file_size,
         a.employer_id
       FROM resumes r
       JOIN applications a ON a.id = r.application_id
       WHERE r.application_id = $1
       LIMIT 1`,
      [applicationId]
    );

    if (!result.rowCount) {
      return json({ success: false, message: "Resume not found." }, 404);
    }

    const resume = result.rows[0];

    if (
      user.role !== "super_admin" &&
      String(resume.employer_id) !== String(user.id)
    ) {
      return json({ success: false, message: "Access denied." }, 403);
    }

    const { data, error } = await supabase.storage
      .from(BUCKET)
      .download(resume.storage_key);

    if (error || !data) {
      console.error("Resume download error:", error);
      return json({ success: false, message: "Unable to retrieve resume." }, 502);
    }

    const safeFilename = String(resume.original_filename || "resume")
      .replace(/[^a-zA-Z0-9._-]/g, "_")
      .slice(0, 120);

    const buffer = new Uint8Array(await data.arrayBuffer());

    return new Response(buffer, {
      status: 200,
      headers: {
        "Content-Type": resume.mime_type || "application/octet-stream",
        "Content-Disposition": `attachment; filename="${safeFilename}"`,
        "Content-Length": String(buffer.byteLength),
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff"
      }
    });

  } catch (error) {
    console.error("Resume API error:", error);

    return json({
      success: false,
      message: "Unable to download resume."
    }, 500);
  }
};
