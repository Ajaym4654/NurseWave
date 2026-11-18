
import pg from "pg";

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

export default async (request) => {
  if (request.method !== "GET") {
    return new Response(
      JSON.stringify({ success: false, message: "Method not allowed" }),
      { status: 405 }
    );
  }

  try {
    const result = await pool.query(`
      SELECT
        current_database() AS database,
        to_regclass('public.users') AS users,
        to_regclass('public.jobs') AS jobs,
        to_regclass('public.applications') AS applications,
        to_regclass('public.resumes') AS resumes
    `);

    const tables = result.rows[0];

    const missing = Object.entries(tables)
      .filter(([key, value]) => key !== "database" && !value)
      .map(([key]) => key);

    return new Response(
      JSON.stringify({
        success: missing.length === 0,
        message: missing.length === 0
          ? "NurseWave database connected successfully!"
          : "Database connected, but some tables are missing.",
        database: tables.database,
        tables,
        missing
      }),
      {
        status: missing.length === 0 ? 200 : 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch (error) {
    console.error("Database error:", error);

    return new Response(
      JSON.stringify({
        success: false,
        message: "Database connection failed. Check DATABASE_URL."
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
};
