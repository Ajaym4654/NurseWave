
import { pool, json, readBody, getSession } from "./lib/common.mjs";

const fields = [
  "title", "street", "city", "zip", "state",
  "weeks", "hours_per_week", "w2_rate", "overtime_rate",
  "weekly_non_taxable", "weekly_taxable", "gross_weekly",
  "blended_rate", "about", "requirements", "perks"
];

function clean(value, max = 10000) {
  return String(value ?? "").trim().slice(0, max);
}

function number(value, min = 0, max = 10000000) {
  const n = Number(value);
  return Number.isFinite(n) && n >= min && n <= max ? n : null;
}

function normalize(row) {
  return {
    id: row.id,
    owner_user_id: row.owner_user_id,
    title: row.title,
    company: row.company,
    agency_name: row.agency_name || row.company,
    recruiter_name: row.recruiter_name || "",
    street: row.street,
    city: row.city,
    zip: row.zip,
    state: row.state,
    location: row.location,
    weeks: row.duration_weeks,
    hours_per_week: row.hours_per_week,
    w2_rate: Number(row.w2_rate),
    overtime_rate: Number(row.overtime_rate),
    weekly_non_taxable: Number(row.weekly_nontaxable || 0),
    weekly_taxable: Number(row.weekly_taxable),
    gross_weekly: Number(row.gross_weekly),
    blended_rate: Number(row.blended_rate),
    openings: row.openings,
    about: row.about,
    requirements: row.requirements,
    perks: row.perks,
    status: row.status,
    created_at: row.created_at
  };
}

export default async (request) => {
  try {
    const user = await getSession(request);
    const method = request.method;

    if (method === "GET") {
      const url = new URL(request.url);
      const id = url.searchParams.get("id");

      if (id && !/^\d+$/.test(id)) {
        return json({ success: false, message: "Invalid job ID." }, 400);
      }

      let result;

      if (user?.role === "super_admin") {
        result = await pool.query(
          `SELECT jobs.*, u.full_name AS recruiter_name,
                  u.company_name AS agency_name
           FROM jobs
           LEFT JOIN users u ON u.id = jobs.owner_user_id
           ${id ? "WHERE jobs.id = $1" : ""}
           ORDER BY jobs.created_at DESC`,
          id ? [id] : []
        );
      } else if (user) {
  result = await pool.query(
    `SELECT jobs.*, u.full_name AS recruiter_name,
            u.company_name AS agency_name
     FROM jobs
     LEFT JOIN users u ON u.id = jobs.owner_user_id
     WHERE (jobs.status = 'active' OR jobs.owner_user_id = $1)
     ${id ? "AND jobs.id = $2" : ""}
     ORDER BY jobs.created_at DESC`,
    id ? [user.id, id] : [user.id]
  );
      } else {
        result = await pool.query(
          `SELECT jobs.*, u.full_name AS recruiter_name,
                  u.company_name AS agency_name
           FROM jobs
           LEFT JOIN users u ON u.id = jobs.owner_user_id
           WHERE jobs.status = 'active'
           ${id ? "AND jobs.id = $1" : ""}
           ORDER BY jobs.created_at DESC`,
          id ? [id] : []
        );
      }

      return json({
        success: true,
        jobs: result.rows.map(normalize)
      });
    }

    if (!user) {
      return json({ success: false, message: "Please log in first." }, 401);
    }

    if (method === "POST") {
      const body = await readBody(request);
      if (!body) return json({ success: false, message: "Invalid data." }, 400);

      const title = clean(body.title, 200);
      const city = clean(body.city, 120);
      const state = clean(body.state, 80);
      const company = user.company_name;

      const weeks = number(body.weeks, 1, 104);
      const hours = number(body.hours_per_week, 1, 168);
      const w2 = number(body.w2_rate);
      const ot = number(body.overtime_rate);
      const nonTaxable = number(body.weekly_non_taxable);
      const taxable = number(body.weekly_taxable);
      const gross = number(body.gross_weekly);
      const blended = number(body.blended_rate);

      if (
        !title || !city || !state ||
        [weeks, hours, w2, ot, nonTaxable, taxable, gross, blended].includes(null)
      ) {
        return json({
          success: false,
          message: "Please provide valid job details and pay values."
        }, 400);
      }

      const result = await pool.query(
        `INSERT INTO jobs (
          owner_user_id, title, company, street, city, zip, state,
          location, hours_per_week, duration_weeks, w2_rate, overtime_rate,
          weekly_nontaxable, weekly_taxable, gross_weekly, blended_rate,
          about, requirements, perks, status
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
          $17,$18,$19,'active'
        )
        RETURNING *`,
        [
          user.id, title, company,
          clean(body.street, 200), city, clean(body.zip, 30), state,
          [city, state].filter(Boolean).join(", "),
          hours, weeks, w2, ot, nonTaxable, taxable, gross, blended,
          clean(body.about), clean(body.requirements),
          clean(body.perks)
        ]
      );

      return json({
        success: true,
        message: "Job created successfully.",
        job: normalize(result.rows[0])
      }, 201);
    }

    if (method === "PATCH") {
      const url = new URL(request.url);
      const id = url.searchParams.get("id");
      if (!id || !/^\\d+$/.test(id)) {
        return json({ success: false, message: "Valid job ID required." }, 400);
      }

      const body = await readBody(request);
      const status = body?.status;
      if (!["active", "closed"].includes(status)) {
        return json({ success: false, message: "Invalid job status." }, 400);
      }

      const result = await pool.query(
        `UPDATE jobs
         SET status = $1
         WHERE id = $2
           AND ($3::boolean OR owner_user_id = $4)
         RETURNING id, status`,
        [status, id, user.role === "super_admin", user.id]
      );

      if (!result.rowCount) {
        return json({ success: false, message: "Job not found or access denied." }, 404);
      }

      return json({
        success: true,
        message: status === "closed" ? "Job closed." : "Job reopened.",
        job: result.rows[0]
      });
    }

    if (method === "PUT" || method === "DELETE") {
      const url = new URL(request.url);
      const id = url.searchParams.get("id");

      if (!id || !/^\d+$/.test(id)) {
        return json({ success: false, message: "Valid job ID required." }, 400);
      }

      if (method === "DELETE") {
        const result = await pool.query(
          `DELETE FROM jobs
           WHERE id = $1
           AND ($2::boolean OR owner_user_id = $3)
           RETURNING id`,
          [id, user.role === "super_admin", user.id]
        );

        if (!result.rowCount) {
          return json({ success: false, message: "Job not found." }, 404);
        }

        return json({ success: true, message: "Job deleted." });
      }

      const body = await readBody(request);
      if (!body) return json({ success: false, message: "Invalid data." }, 400);

      const current = await pool.query(
        `SELECT * FROM jobs
         WHERE id = $1
         AND ($2::boolean OR owner_user_id = $3)`,
        [id, user.role === "super_admin", user.id]
      );

      if (!current.rowCount) {
        return json({ success: false, message: "Job not found." }, 404);
      }

      const old = normalize(current.rows[0]);
      const merged = { ...old, ...body };

      const title = clean(merged.title, 200);
      const city = clean(merged.city, 120);
      const state = clean(merged.state, 80);

      const weeks = number(merged.weeks, 1, 104);
      const hours = number(merged.hours_per_week, 1, 168);
      const w2 = number(merged.w2_rate);
      const ot = number(merged.overtime_rate);
      const nonTaxable = number(merged.weekly_non_taxable);
      const taxable = number(merged.weekly_taxable);
      const gross = number(merged.gross_weekly);
      const blended = number(merged.blended_rate);

      if (
        !title || !city || !state ||
        [weeks, hours, w2, ot, nonTaxable, taxable, gross, blended].includes(null)
      ) {
        return json({ success: false, message: "Invalid job details." }, 400);
      }

      const result = await pool.query(
        `UPDATE jobs SET
          title=$1, street=$2, city=$3, zip=$4, state=$5,
          location=$6, duration_weeks=$7, hours_per_week=$8,
          w2_rate=$9, overtime_rate=$10, weekly_nontaxable=$11,
          weekly_taxable=$12, gross_weekly=$13, blended_rate=$14,
          about=$15, requirements=$16, perks=$17,
          created_at=NOW()
         WHERE id=$18
         RETURNING *`,
        [
          title, clean(merged.street, 200), city,
          clean(merged.zip, 30), state, `${city}, ${state}`,
          weeks, hours, w2, ot, nonTaxable, taxable, gross, blended,
          clean(merged.about), clean(merged.requirements),
          clean(merged.perks), id
        ]
      );

      return json({
        success: true,
        message: "Job updated successfully.",
        job: normalize(result.rows[0])
      });
    }

    return json({ success: false, message: "Method not allowed." }, 405);

  } catch (error) {
    console.error("Jobs API error:", error);
    return json({ success: false, message: "Unable to process jobs request." }, 500);
  }
};
