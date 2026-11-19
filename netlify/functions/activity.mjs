import { pool, json, getSession, readBody } from "./lib/common.mjs";
import { jwtVerify } from "jose";

export default async request => {
  const user=await getSession(request);
  if (!user) return json({success:false,message:"Login required."},401);

  if(request.method==="POST"){
    const body=await readBody(request);
    const action=String(body?.action||"").slice(0,120);
    if(!action) return json({success:false,message:"Activity name is required."},400);
    try{
      const cookie=request.headers.get("cookie")||"";
      const match=cookie.match(/(?:^|;\s*)nursewave_session=([^;]+)/);
      let sessionId=null;
      if(match){
        const secret=process.env.SESSION_SECRET;
        const verified=await jwtVerify(match[1],new TextEncoder().encode(secret),{algorithms:["HS256"]});
        sessionId=verified.payload.sid||null;
      }
      const forwarded=request.headers.get("x-nf-client-connection-ip")||request.headers.get("x-forwarded-for")||"";
      const ip=forwarded.split(",")[0].trim()||null;
      await pool.query(
        "INSERT INTO activity_logs (user_id,session_id,event_type,ip_address,user_agent,details) VALUES ($1,$2,'action',$3,$4,$5)",
        [user.id,sessionId,ip,request.headers.get("user-agent")||null,JSON.stringify({action})]
      );
      return json({success:true});
    }catch(error){
      console.error("Activity write error:",error);
      return json({success:false,message:"Unable to record activity."},500);
    }
  }

  if(request.method!=="GET") return json({success:false,message:"Method not allowed."},405);
  if(user.role!=="super_admin") return json({success:false,message:"Super Admin access required."},403);
  try {
    const [sessions,logs]=await Promise.all([
      pool.query(`
        SELECT s.session_id,s.user_id,u.full_name,u.email,u.role,
               s.ip_address,s.user_agent,s.device_label,
               s.created_at,s.last_seen_at
        FROM user_sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.ended_at IS NULL
          AND s.last_seen_at > NOW() - INTERVAL '30 minutes'
          AND u.is_active=TRUE
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
