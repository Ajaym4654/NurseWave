
import { json, getSession, publicUser } from "./lib/common.mjs";

export default async (request) => {
  if (request.method !== "GET") {
    return json({ success: false, message: "Method not allowed" }, 405);
  }

  const user = await getSession(request);

  if (!user) {
    return json({
      success: false,
      user: null,
      message: "Not logged in."
    }, 401);
  }

  return json({
    success: true,
    user: publicUser(user)
  });
};
