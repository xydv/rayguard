import asyncio
import json
from pathlib import Path

from anchorpy import Program, Provider, Wallet
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS_PROGRAM_ID

# ==========================================
# CONFIGURATION
# ==========================================
# 1. Point to your wallet and IDL
WALLET_PATH = "/home/aditya/.config/solana/id.json"
IDL_PATH = (
    "/home/aditya/Code/rayguard/rayguard-program/target/idl/rayguard_program.json"
)

# 2. Your Program ID (From the IDL or your Rust code)
PROGRAM_ID = Pubkey.from_string("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY")

# 3. Connect to Devnet
RPC_URL = "http://127.0.0.1:8899"


async def get_program():
    """Helper to set up the connection."""
    client = AsyncClient(RPC_URL)

    # Load Wallet
    with open(WALLET_PATH, "r") as f:
        secret = json.load(f)
    kp = Keypair.from_bytes(bytes(secret))
    wallet = Wallet(kp)

    provider = Provider(client, wallet)

    # Load IDL
    with open(IDL_PATH, "r") as f:
        idl_json = json.load(f)

    program = Program(idl_json, PROGRAM_ID, provider)
    return program, provider


# ==========================================
# FUNCTION 1: CREATE LEDGER
# ==========================================
async def create_ledger(seed_id: int):
    """
    Calls 'create_ledger' instruction.
    Derives PDA using seeds: ["state", seed_id(u16)]
    """
    program, provider = await get_program()

    # 1. Convert seed to 2 bytes (u16) little-endian
    seed_bytes = seed_id.to_bytes(2, "little")

    # 2. Find the Address (PDA) where the Ledger will live
    ledger_pda, _ = Pubkey.find_program_address([b"state", seed_bytes], PROGRAM_ID)

    print(f"Creating Ledger at: {ledger_pda}")

    # 3. Call the smart contract
    # Note: We match the argument name 'seed' from your IDL
    tx = (
        await program.methods.create_ledger(seed_id)
        .accounts(
            {
                "ledger": ledger_pda,
                "authority": provider.wallet.public_key,
                "system_program": SYS_PROGRAM_ID,
            }
        )
        .rpc()
    )

    return str(tx), str(ledger_pda)


# ==========================================
# FUNCTION 2: ADD LOG
# ==========================================
async def add_log(ledger_address_str: str, ip: str, threat: str, action: str):
    """
    Calls 'add_log' instruction.
    1. Fetches Ledger to get current 'count'.
    2. Derives Log PDA using seeds: ["log", ledger_key, count(u64)]
    3. Sends transaction.
    """
    program, provider = await get_program()
    ledger_pubkey = Pubkey.from_string(ledger_address_str)

    # 1. Fetch the Ledger Account to get the current count
    try:
        ledger_account = await program.account["Ledger"].fetch(ledger_pubkey)
        current_count = ledger_account.count
    except Exception as e:
        return None, f"Could not find ledger account: {e}"

    # 2. Derive the Log PDA
    # Seeds: "log" + ledger_address + count (8 bytes u64)
    count_bytes = current_count.to_bytes(8, "little")
    log_pda, _ = Pubkey.find_program_address(
        [b"log", bytes(ledger_pubkey), count_bytes], PROGRAM_ID
    )

    # 3. Prepare the Arguments Struct (AddLogArgs)
    # Your IDL expects a single argument named 'args' which is a struct
    log_args = {"ip_address": ip, "threat_type": threat, "action_taken": action}

    print(f"Writing log #{current_count} to: {log_pda}")

    # 4. Send Transaction
    try:
        tx = (
            await program.methods.add_log(log_args)
            .accounts(
                {
                    "ledger": ledger_pubkey,
                    "log": log_pda,
                    "authority": provider.wallet.public_key,
                    "system_program": SYS_PROGRAM_ID,
                }
            )
            .rpc()
        )
        return str(tx), None
    except Exception as e:
        return None, str(e)


# Helper for testing directly
if __name__ == "main":
    # Test run
    asyncio.run(create_ledger(105))
