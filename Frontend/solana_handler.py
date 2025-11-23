import asyncio
import json
from pathlib import Path
from anchorpy import Provider, Wallet, Program, Idl  # <--- 1. IMPORT 'Idl'
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import ID as SYS_PROGRAM_ID

# ==========================================
# CONFIGURATION
# ==========================================
WALLET_PATH = "id.json"
IDL_PATH = "rayguard_program.json" 
PROGRAM_ID = Pubkey.from_string("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY")
RPC_URL = "https://devnet.helius-rpc.com/?api-key=3306ede2-b0da-4ea3-a571-50369811ddb4"

async def get_program():
    """Helper to set up the connection."""
    client = AsyncClient(RPC_URL)
    
    # Load Wallet
    with open(WALLET_PATH, "r") as f:
        secret = json.load(f)
    kp = Keypair.from_bytes(bytes(secret))
    wallet = Wallet(kp)
    
    provider = Provider(client, wallet)
    
    # 2. FIX: Load IDL as a string, then parse it into an Idl object
    with open(IDL_PATH, "r") as f:
        raw_idl = f.read()
    idl = Idl.from_json(raw_idl)
        
    # Now 'idl' is an object, not a dict, so Program() can read it correctly
    program = Program(idl, PROGRAM_ID, provider)
    return program, provider

# ==========================================
# FUNCTION 1: CREATE LEDGER
# ==========================================
async def create_ledger(seed_id: int):
    program, provider = await get_program()
    
    seed_bytes = seed_id.to_bytes(2, 'little')
    
    ledger_pda, _ = Pubkey.find_program_address(
        [b"state", seed_bytes],
        PROGRAM_ID
    )
    
    print(f"Creating Ledger at: {ledger_pda}")
    
    tx = await program.methods.create_ledger(seed_id).accounts({
        "ledger": ledger_pda,
        "authority": provider.wallet.public_key,
        "system_program": SYS_PROGRAM_ID
    }).rpc()
    
    return str(tx), str(ledger_pda)

# ==========================================
# FUNCTION 2: ADD LOG
# ==========================================
async def add_log(ledger_address_str: str, ip: str, threat: str, action: str):
    program, provider = await get_program()
    ledger_pubkey = Pubkey.from_string(ledger_address_str)
    
    try:
        ledger_account = await program.account["Ledger"].fetch(ledger_pubkey)
        current_count = ledger_account.count
    except Exception as e:
        return None, f"Could not find ledger account: {e}"

    count_bytes = current_count.to_bytes(8, 'little')
    log_pda, _ = Pubkey.find_program_address(
        [b"log", bytes(ledger_pubkey), count_bytes],
        PROGRAM_ID
    )
    
    log_args = {
        "ip_address": ip,
        "threat_type": threat,
        "action_taken": action
    }
    
    print(f"Writing log #{current_count} to: {log_pda}")

    try:
        tx = await program.methods.add_log(log_args).accounts({
            "ledger": ledger_pubkey,
            "log": log_pda,
            "authority": provider.wallet.public_key,
            "system_program": SYS_PROGRAM_ID
        }).rpc()
        return str(tx), None
    except Exception as e:
        return None, str(e)

if __name__ == "__main__":
    # Windows-specific fix for asyncio loop issues
    if asyncio.get_event_loop_policy().__class__.__name__ == 'WindowsProactorEventLoopPolicy':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(create_ledger(105))