
import { json, clearSession } from "./lib/common.mjs";

export default async (request) => {
  if (request.method !== "POST") {
    return json({ success: false, message: "Method not allowed" }, 405);
  }

  return json({
    success: true,
    message: "Logged out successfully."
  }, 200, {
    "Set-Cookie": clearSession()
  });
};
