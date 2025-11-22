import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import z from "zod";
import HttpSms from "httpsms";

const app = new Hono();
const bannedUsers = new Set<string>();
const client = new HttpSms(
  "uk_Gcjk5xwgLoEHOxbVdvRkImBfs4ciets_Vyz7fw5iDsMT2OOfMF_0ieIETgDnWXSQ",
);

// DOS
app.use("*", async (c, next) => {
  const userId = c.req.header("ip") || "anonymous";

  if (bannedUsers.has(userId)) {
    return c.json(
      { message: "your account has been suspended due to malicious activity." },
      403,
    );
  }

  await next();
});

// attacker will ddos here
app.get("/resource", async (c) => {
  return c.json({ message: "ok" }, 200);
});

app.post(
  "/agent",
  zValidator(
    "json",
    z.object({
      type: z.string(),
      data: z.string().optional(),
    }),
  ),
  async (c) => {
    const { type, data } = c.req.valid("json");

    switch (type) {
      case "U2R":
        return c.json({ message: "PROCESS TERMINATED" }, 403);
      case "R2L":
        return c.json({ message: "UNAUTHORIZED" }, 401);
      case "DOS":
        if (!data) return c.json({ message: "USER NOT FOUND" }, 503);
        bannedUsers.add(data);
        return c.json({ message: "SERVICE UNAVAILABLE" }, 503);
      case "PROBE":
        await client.messages.postSend({
          from: `+91${process.env.FROM}`,
          to: `+91${process.env.TO}`,
          encrypted: false,
          content: `NOTIFICATION: ${data} IS TRYING TO PROBE YOUR SYSTEM!!! ALERT ALERT!!!`,
        });
        return c.json({ message: "NOTIFIED" }, 406);
    }
  },
);

export default app;
