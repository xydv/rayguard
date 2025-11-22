import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import z from "zod";
import HttpSms from "httpsms";
import { createChannel, createResponse } from "better-sse";

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { AnchorProvider, BN, Program } from "@coral-xyz/anchor";
import IDL from "../rayguard-program/target/idl/rayguard_program.json";
import { type RayguardProgram } from "../rayguard-program/target/types/rayguard_program";
import NodeWallet from "@coral-xyz/anchor/dist/cjs/nodewallet";

const app = new Hono();
const channel = createChannel();
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
      Uint8Array.from([
        100, 48, 60, 71, 86, 179, 14, 216, 64, 203, 186, 94, 205, 107, 73, 21,
        42, 136, 132, 201, 221, 76, 247, 175, 232, 102, 85, 60, 114, 27, 96,
        243, 138, 80, 193, 221, 63, 123, 195, 74, 131, 100, 205, 136, 241, 46,
        231, 250, 96, 245, 22, 151, 138, 74, 123, 28, 60, 111, 163, 102, 228,
        101, 93, 191,
      ]),
    ),
  ),
);

const program = new Program<RayguardProgram>(IDL as RayguardProgram, provider);

app.post(
  "/createLedger",
  zValidator(
    "json",
    z.object({
      seed: z.string(),
    }),
  ),
  async (c) => {
    const { seed } = c.req.valid("json");

    await program.methods
      .createLedger(new BN(seed))
      .accounts({ authority: provider.publicKey })
      .rpc({
        skipPreflight: true,
        preflightCommitment: "processed",
        commitment: "processed",
      });

    return c.json({ message: "ok" });
  },
);

app.post(
  "/addLog",
  zValidator(
    "json",
    z.object({
      ledger: z.string(),
      ipAddress: z.string(),
      threatType: z.string(),
      actionTaken: z.string(),
    }),
  ),
  async (c) => {
    const d = c.req.valid("json");

    channel.broadcast(d, "message");

    const { ledger, actionTaken, ipAddress, threatType } = d;

    await program.methods
      .addLog({
        ipAddress,
        threatType,
        actionTaken,
      })
      .accounts({ ledger: new PublicKey(ledger) })
      .rpc({
        skipPreflight: true,
        preflightCommitment: "processed",
        commitment: "processed",
      });

    return c.json({});
  },
);

app.post(
  "/verify",
  zValidator(
    "json",
    z.object({
      ledger: z.string(),
      ipAddress: z.string(),
      threatType: z.string(),
      actionTaken: z.string(),
    }),
  ),
  async (c) => {
    const { ledger, ipAddress, threatType, actionTaken } = c.req.valid("json");

    try {
      const ledgerPubkey = new PublicKey(ledger);

      const logs = await program.account.log.all();

      const isVerified = logs.some(
        (log) =>
          log.account.ipAddress === ipAddress &&
          log.account.threatType === threatType &&
          log.account.actionTaken === actionTaken,
      );

      if (isVerified) {
        return c.json({
          success: true,
          message: "Log verified on-chain",
          verified: true,
        });
      } else {
        return c.json({
          success: true,
          message: "Log not found in ledger",
          verified: false,
        });
      }
    } catch (e) {
      console.error(e);
      return c.json(
        {
          success: false,
          message: "Failed to verify log or invalid ledger",
          error: String(e),
        },
        500,
      );
    }
  },
);

app.get("/sse", (c) =>
  createResponse(c.req.raw, (session) => {
    channel.register(session);
  }),
);

export default app;
