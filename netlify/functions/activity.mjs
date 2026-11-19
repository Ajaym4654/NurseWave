import { pool, json, getSession } from "./lib/common.mjs";

export default async request => {
  if (request.method !== "GET") return json({success:false,message:"Method not allowed."},405);
  const admin=await getSession(request);
  if (!admin || admin.role!=="super_admin") {
    return json({success:false,message:"Super Admin access required."},403);
  }
  try {
    const [sessions,logs]=await Promise.all([
      pool.query(`
        SELECT s.session_id,s.user_id,u.full_name,u.email,u.role,
               s.ip_address,s.user_agent,s.device_label,
               s.created_at,s.last_seen_at
        FROM user_sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.ended_at IS NULL AND u.is_active=TRUE
        ORDER BY s.last_seen_at DESC
      `),
      pool.query(`
        SELECT l.id,l.user_id,u.full_name,u.email,u.role,l.session_id,
               l.event_type,l.ip_address,l.user_agent,l.details,l.created_at
        FROM activity_logs l
        LEFT JOIN users u ON u.id=l.user_id
        ORDER BY l.created_at DESC
        LIMIT 500
      `)
    ]);
    return json({success:true,active_sessions:sessions.rows,activities:logs.rows});
  } catch(error) {
    console.error("Activity log error:",error);
    return json({success:false,message:"Unable to load activity log."},500);
  }
};
