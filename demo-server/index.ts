import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import z from "zod";
import HttpSms from "httpsms";

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { AnchorProvider, BN, Program } from "@coral-xyz/anchor";
import IDL from "../rayguard-program/target/idl/rayguard_program.json";
import { type RayguardProgram } from "../rayguard-program/target/types/rayguard_program";
import NodeWallet from "@coral-xyz/anchor/dist/cjs/nodewallet";

const app = new Hono();
const bannedUsers = new Set<string>();
const client = new HttpSms(
  "uk_Gcjk5xwgLoEHOxbVdvRkImBfs4ciets_Vyz7fw5iDsMT2OOfMF_0ieIETgDnWXSQ",
);

const rpcUrl = `http://127.0.0.1:8899`;
const connection = new Connection(rpcUrl);
const provider = new AnchorProvider(
  connection,
  new NodeWallet(
    Keypair.fromSecretKey(
      // signer publickey
      Uint8Array.from([]),
    ),
  ),
  {
    skipPreflight: true,
    commitment: "processed",
    preflightCommitment: "processed",
  },
);
const program = new Program<RayguardProgram>(IDL as RayguardProgram, provider);

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

app.post("/createLedger", async (c) => {
  await program.methods
    .createLedger(new BN(1))
    .accounts({ authority: provider.publicKey })
    .rpc();

  return c.json({ message: "ok" });
});

app.post(
  "/addLog",
  zValidator(
    "json",
    z.object({
      ledger: z.string(),
    }),
  ),
  async (c) => {
    const { ledger } = c.req.valid("json");
    console.log(ledger);

    await program.methods
      .addLog({
        ipAddress: "1.1.1.1",
        threatType: "DOS",
        actionTaken: "BLOCK_IP",
      })
      .accounts({ ledger: new PublicKey(ledger) })
      .rpc();

    return c.json({});
  },
);

export default app;
