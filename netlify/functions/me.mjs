
import { json, getSession, publicUser } from "./lib/common.mjs";

export default async (request) => {
  if (request.method !== "GET") {
    return json({ success: false, message: "Method not allowed" }, 405);
  }

  const user = await getSession(request);

  if (!user) {
    return json({
      success: true,
      user: null,
      message: "Not logged in."
    });
  }

  return json({
    success: true,
    user: publicUser(user)
  });
};
