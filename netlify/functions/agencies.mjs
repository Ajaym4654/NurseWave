import { pool, json, getSession } from "./lib/common.mjs";

export default async request => {
  try {
    const user = await getSession(request);
    if (!user || user.role !== "super_admin") {
      return json({ success:false, message:"Super Admin access required." },403);
    }
    if (request.method !== "GET") {
      return json({ success:false, message:"Method not allowed." },405);
    }

    const result = await pool.query(`
      SELECT
        COALESCE(NULLIF(BTRIM(company_name),''),'Unspecified Agency') AS company_name,
        id, full_name, email, approval_status, created_at
      FROM users
      WHERE role='employer'
      ORDER BY COALESCE(NULLIF(LOWER(BTRIM(company_name)),''),'unspecified agency'),
               created_at DESC, full_name ASC
    `);

    const grouped = new Map();
    for (const row of result.rows) {
      const name = row.company_name;
      if (!grouped.has(name)) grouped.set(name,[]);
      grouped.get(name).push({
        id: row.id,
        full_name: row.full_name,
        email: row.email,
        approval_status: row.approval_status || "approved",
        created_at: row.created_at
      });
    }

    const agencies = [...grouped.entries()]
      .map(([company_name,users])=>({company_name,users}))
      .sort((a,b)=>a.company_name.localeCompare(b.company_name));

    return json({success:true,agencies});
  } catch (error) {
    console.error("Agency directory error:",error);
    return json({success:false,message:"Unable to load agencies."},500);
  }
};
