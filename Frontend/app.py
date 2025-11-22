# app.py
import streamlit as st
import pandas as pd
import numpy as np
import time
import joblib
import plotly.express as px
import threading
import struct
import asyncio
from datetime import datetime
from sklearn.preprocessing import StandardScaler, LabelEncoder
from concurrent.futures import ThreadPoolExecutor

# -------------------------
# Configuration / constants
# -------------------------
STEPS_PER_RERUN = 1          # process this many rows per Streamlit run (keeps UI responsive)
SLEEP_BETWEEN_STEPS = 0.05   # seconds (UI friendly)
DATA_PATH = "nsl_kdd_dataset.csv"
MODEL_PATH = "attack_type_classifier.pkl"
ENCODER_PATH = "attack_label_encoder.pkl"
UPLOADED_IMAGE = "/mnt/data/5896a81e-2d6f-4d6c-91d1-8e023fa114f0.png"  # from your session

IDL_PATH = "rayguard_program.json"
PROGRAM_ID_STR = "J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY"

# -------------------------
# Blockchain availability
# -------------------------
BLOCKCHAIN_AVAILABLE = False
try:
    from anchorpy import Program, Provider, Wallet, Context, Idl
    from solana.rpc.async_api import AsyncClient
    from solders.keypair import Keypair
    from solders.pubkey import Pubkey
    BLOCKCHAIN_AVAILABLE = True
except Exception as e:
    # Keep the app functional even if blockchain libs aren't installed
    st.sidebar.info("Blockchain libraries missing or not configured. On-chain features disabled.")
    BLOCKCHAIN_AVAILABLE = False

# Threadpool for non-blocking blockchain calls
_executor = ThreadPoolExecutor(max_workers=2)

# -------------------------
# App styling
# -------------------------
st.set_page_config(page_title="SentinelFlow AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp { background-color: #050505; color: #e0e0e0; }
[data-testid="stSidebar"] { background-color: #0a0a0a; border-right: 1px solid #333; }
div[data-testid="stMetric"] { background-color: rgba(20, 20, 30, 0.8); border: 1px solid #333; border-radius: 8px; }
div[data-testid="stMetric"] label { color: #00ff9d; }
div[data-testid="stMetric"] div[data-testid="stMetricValue"] { color: #fff; }
.alert-box { padding: 12px; border-radius: 6px; text-align: center; font-weight: 700; margin-bottom: 8px; }
.explanation-box { font-size: 0.85rem; color: #ffcccb; text-align: center; border: 1px solid #ff0055; padding: 8px; border-radius: 5px; margin-top: 5px; background-color: rgba(255, 0, 85, 0.06); }
.tx-link { font-size: 0.8rem; color: #00ff9d; text-align: center; margin-top: 5px; text-decoration: none; display: block; }
</style>
""", unsafe_allow_html=True)

# -------------------------
# Session state defaults
# -------------------------
if 'ledger_pubkey' not in st.session_state: st.session_state.ledger_pubkey = None
if 'history' not in st.session_state: st.session_state.history = []
if 'stats' not in st.session_state: st.session_state.stats = {'safe': 0, 'threat': 0, 'dos': 0}
if 'ptr' not in st.session_state: st.session_state.ptr = 0
if 'running' not in st.session_state: st.session_state.running = False
if 'scaler' not in st.session_state: st.session_state.scaler = None
if 'model' not in st.session_state: st.session_state.model = None
if 'encoder' not in st.session_state: st.session_state.encoder = None
if 'data' not in st.session_state: st.session_state.data = None

# -------------------------
# Async blockchain helper wrappers (safe non-blocking)
# -------------------------
async def create_ledger_async():
    """Async create ledger (same code from your original, but careful - ephemeral payer used here)."""
    client = AsyncClient("https://api.devnet.solana.com")
    payer = Keypair()
    try:
        await client.request_airdrop(payer.pubkey(), 2_000_000_000)
    except Exception:
        pass
    await asyncio.sleep(0.25)
    with open(IDL_PATH, "r") as f:
        raw_idl = f.read()
    idl = Idl.from_json(raw_idl)
    program = Program(idl, Pubkey.from_string(PROGRAM_ID_STR), Provider(client, Wallet(payer)))
    seed = str(int(time.time()))
    ledger_pda, _ = Pubkey.find_program_address([b"state", seed.encode()], program.program_id)
    await program.rpc["create_ledger"](
        seed,
        ctx=Context(
            accounts={
                "ledger": ledger_pda,
                "authority": payer.pubkey(),
                "system_program": Pubkey.from_string("11111111111111111111111111111111")
            },
            signers=[payer]
        )
    )
    await client.close()
    return str(ledger_pda)

async def log_async(ledger_str, ip, threat, action):
    client = AsyncClient("http://127.0.0.1:8899")
    payer = Keypair()
    try:
        await client.request_airdrop(payer.pubkey(), 1_000_000_000)
    except Exception:
        pass
    await asyncio.sleep(0.25)
    with open(IDL_PATH, "r") as f:
        raw_idl = f.read()
    idl = Idl.from_json(raw_idl)
    program = Program(idl, Pubkey.from_string(PROGRAM_ID_STR), Provider(client, Wallet(payer)))
    ledger_key = Pubkey.from_string(ledger_str)
    acc = await program.account["Ledger"].fetch(ledger_key)
    count_bytes = struct.pack("<Q", acc.count)
    log_pda, _ = Pubkey.find_program_address([b"log", bytes(ledger_key), count_bytes], program.program_id)
    tx = await program.rpc["add_log"](
        {"ip_address": ip, "threat_type": threat, "action_taken": action},
        ctx=Context(
            accounts={
                "ledger": ledger_key, "log": log_pda,
                "authority": payer.pubkey(),
                "system_program": Pubkey.from_string("11111111111111111111111111111111")
            },
            signers=[payer]
        )
    )
    await client.close()
    return str(tx)

def create_ledger_bg():
    """Run create_ledger_async in background thread and set session_state when done."""
    try:
        ledger = asyncio.run(create_ledger_async())
        # we cannot directly set session_state from thread, but we can write to a temporary file or print.
        # Simpler: return ledger and inform user to refresh - but we'll display in the sidebar via a notification.
        # For simplicity in this demo, write to a tiny file; Streamlit will need user to press Deploy again to pick it up.
        # Here we'll just return the ledger result; the caller (main thread) will set state.
        return ledger
    except Exception as e:
        return None

def log_threat_bg(ledger, ip, threat, action):
    """Submit a log to Solana in background to avoid blocking the UI."""
    if not BLOCKCHAIN_AVAILABLE or not ledger:
        return None
    try:
        res = asyncio.run(log_async(ledger, ip, threat, action))
        return res
    except Exception as e:
        # return None on failure, don't break UI
        return None

# -------------------------
# Data & Model Loading
# -------------------------
@st.cache_resource
def load_resources():
    res = {}
    # Data
    try:
        df = pd.read_csv(DATA_PATH)
        X_num = df.select_dtypes(include=[np.number])
        if 'label' in X_num.columns:
            X_num = X_num.drop(columns=['label'])
        res['data'] = X_num.reset_index(drop=True)
    except Exception as e:
        return None, f"Missing or unreadable dataset at '{DATA_PATH}': {e}"

    # Scaler
    try:
        scaler = StandardScaler()
        scaler.fit(res['data'].values)
        res['scaler'] = scaler
    except Exception as e:
        return None, f"Scaler fit failed: {e}"

    # Model (optional)
    try:
        res['model'] = joblib.load(MODEL_PATH)
    except Exception:
        res['model'] = None

    # Encoder (optional)
    try:
        res['encoder'] = joblib.load(ENCODER_PATH)
    except Exception:
        le = LabelEncoder()
        le.fit(['DoS', 'Probe', 'R2L', 'U2R', 'normal'])
        res['encoder'] = le

    return res, None

resources, err = load_resources()
if err:
    st.error(err)
    st.stop()

# push into session state for quick access
st.session_state.data = resources['data']
st.session_state.scaler = resources['scaler']
st.session_state.model = resources['model']
st.session_state.encoder = resources['encoder']

# -------------------------
# Predict function (fixed)
# -------------------------
def predict_traffic(row):
    """
    Hybrid prediction:
    1) Try ML model if available
    2) Otherwise fallback to rule-based on scaled features (so thresholds are meaningful)
    """
    scaler = st.session_state.scaler
    model = st.session_state.model
    le = st.session_state.encoder

    # use scaled row for rule thresholds
    try:
        scaled = scaler.transform(row.values.reshape(1, -1))[0]
    except Exception:
        # fallback: no scaling possible
        scaled = row.values

    # ML
    if model is not None:
        try:
            probs = model.predict_proba(scaled.reshape(1, -1))
            idx = int(np.argmax(probs))
            lbl = le.inverse_transform([idx])[0] if hasattr(le, 'inverse_transform') else str(idx)
            conf = float(np.max(probs))
            # if model confident it's not normal -> return
            if lbl.lower() not in ['normal', 'benign'] and conf > 0.5:
                return lbl, conf, "AI: model detected anomaly"
        except Exception:
            # silent fallback to rules
            pass

    # RULES ON SCALED VALUES (so thresholds are unit-less)
    # choose thresholds that work on standardized data (mean=0, std=1)
    # e.g. src_bytes scaled > 2 means unusually large payload vs dataset
    col_map = {c: i for i, c in enumerate(st.session_state.data.columns)}
    def val(col):
        return float(scaled[col_map[col]]) if col in col_map else 0.0

    src = val('src_bytes') if 'src_bytes' in col_map else 0.0
    dst = val('dst_bytes') if 'dst_bytes' in col_map else 0.0
    cnt = val('count') if 'count' in col_map else 0.0
    root = val('num_root') if 'num_root' in col_map else 0.0

    # sensible thresholds on z-score scale
    if src > 2.0 or dst > 2.0 or cnt > 2.0:
        return "DoS_Flood", 0.98, "Rule: volume spike (scaled)"
    if root > 1.5:
        return "U2R_Escalation", 0.99, "Rule: root/priv escalation (scaled)"

    return "normal", 0.99, "Baseline"

# -------------------------
# Sidebar: Blockchain controls and Start/Stop
# -------------------------
st.sidebar.title("⛓️ Blockchain Config")
if not BLOCKCHAIN_AVAILABLE:
    st.sidebar.error("🚫 Blockchain libs missing. On-chain logging disabled.")
else:
    if st.session_state.ledger_pubkey is None:
        st.sidebar.warning("🔴 Disconnected")
        if st.sidebar.button("🚀 DEPLOY NEW LEDGER"):
            with st.spinner("Creating ledger on Solana (background)..."):
                # run background thread to create ledger
                future = _executor.submit(create_ledger_bg)
                # Wait for completion but keep UI responsive: block briefly and then poll later
                ledger = future.result(timeout=30) if future.done() else None
                if ledger:
                    st.session_state.ledger_pubkey = ledger
                    st.success("Ledger created. Pubkey saved.")
                    st.experimental_rerun()
                else:
                    st.sidebar.error("Ledger creation failed or timed out. Try again.")
    else:
        st.sidebar.success("🟢 Ledger Online")
        st.sidebar.code(st.session_state.ledger_pubkey)
        if st.sidebar.button("Disconnect"):
            st.session_state.ledger_pubkey = None
            st.experimental_rerun()

st.sidebar.divider()
start = st.sidebar.button("▶️ START SYSTEM")
stop = st.sidebar.button("⏹️ ABORT")

if start:
    st.session_state.running = True
if stop:
    st.session_state.running = False

# -------------------------
# Main UI
# -------------------------
c1, c2 = st.columns([5, 1])
with c1:
    st.title("🛡️ SENTINEL FLOW")
    st.markdown("##### > HYBRID AI & ON-CHAIN SECURITY")
with c2:
    st.markdown("### 🟢 LIVE")

# show uploaded image preview (helpful for debugging / theme)
try:
    st.image(UPLOADED_IMAGE, caption="Uploaded screenshot (for reference)", use_column_width=False, width=420)
except Exception:
    pass

st.divider()
m1, m2, m3, m4 = st.columns(4)
metric_safe = m1.empty(); metric_threat = m2.empty(); metric_dos = m3.empty(); metric_alert = m4.empty()

col_live, col_log = st.columns([2, 1])
with col_live:
    st.subheader("📡 Live Traffic")
    chart_place = st.empty()
with col_log:
    st.subheader("📜 Threat Log")
    log_place = st.empty()

# initialize chart data in session
if 'chart_data' not in st.session_state:
    st.session_state.chart_data = pd.DataFrame(columns=['Time', 'Load'])

# -------------------------
# Streaming loop control (stepwise per rerun)
# -------------------------
if st.session_state.running:
    # process a small batch on each rerun so Streamlit stays responsive
    ptr = st.session_state.ptr
    data = st.session_state.data
    n = len(data)
    steps = 0

    while steps < STEPS_PER_RERUN and ptr < n:
        row = data.iloc[ptr]
        label, conf, expl = predict_traffic(row)
        ts = datetime.now().strftime("%H:%M:%S")
        is_threat = label.lower() not in ['normal', 'benign']

        if is_threat:
            st.session_state.stats['threat'] += 1
            if 'dos' in label.lower():
                st.session_state.stats['dos'] += 1

            color = "#ff0055"
            msg = f"🚨 {label.upper()}"

            tx_sig = None
            # non-blocking blockchain logging (background thread)
            if BLOCKCHAIN_AVAILABLE and st.session_state.ledger_pubkey:
                fake_ip = f"192.168.1.{np.random.randint(10,99)}"
                # submit to thread executor (returns future)
                future = _executor.submit(log_threat_bg, st.session_state.ledger_pubkey, fake_ip, label, "BLOCKED")
                # do not block: the future will run in background; we can peek later if required
                # if you want to wait here (not recommended), call future.result(timeout=10)

            entry = {"TIME": ts, "TYPE": label, "CONF": f"{conf*100:.0f}%", "CHAIN": "✅" if tx_sig else "⏳"}
            st.session_state.history.insert(0, entry)

            metric_alert.markdown(f'<div class="alert-box" style="background-color:{color}; color:black; box-shadow:0 0 12px {color};">{msg}</div>', unsafe_allow_html=True)
            metric_alert.markdown(f'<div class="explanation-box"><strong>AI/Rule:</strong> {expl}</div>', unsafe_allow_html=True)

        else:
            st.session_state.stats['safe'] += 1
            color = "#00ff9d"
            msg = "✅ SECURE"
            metric_alert.markdown(f'<div class="alert-box" style="background-color:{color}; color:black;">{msg}</div>', unsafe_allow_html=True)

        # update metrics
        metric_safe.metric("SAFE", st.session_state.stats['safe'])
        metric_threat.metric("THREATS", st.session_state.stats['threat'])
        metric_dos.metric("DoS ATTACKS", st.session_state.stats['dos'])

        # update chart
        # scale for visual: use original value if exists else use scaled fallback
        load_raw = row.get('src_bytes', 0)
        val = np.log1p(load_raw * 0.001) if load_raw >= 0 else 0.0
        st.session_state.chart_data = pd.concat([st.session_state.chart_data, pd.DataFrame({'Time': [ts], 'Load': [val]})]).tail(50)

        fig = px.area(st.session_state.chart_data, x='Time', y='Load', template='plotly_dark')
        fig.update_traces(line_color=color, fillcolor=color)
        fig.update_layout(height=350, margin=dict(t=10,b=10,l=10,r=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        chart_place.plotly_chart(fig, use_container_width=True)

        # update log
        if st.session_state.history:
            log_place.dataframe(pd.DataFrame(st.session_state.history).head(8), hide_index=True, use_container_width=True)

        ptr += 1
        steps += 1
        st.session_state.ptr = ptr

    # finished processing this step(s) -> sleep briefly and rerun to continue
    if ptr >= n:
        st.session_state.running = False
        st.success("Finished dataset replay.")
    else:
        # brief pause then rerun to simulate streaming while allowing UI to refresh
        time.sleep(SLEEP_BETWEEN_STEPS)
        st.experimental_rerun()
else:
    # not running: just render last state
    metric_safe.metric("SAFE", st.session_state.stats['safe'])
    metric_threat.metric("THREATS", st.session_state.stats['threat'])
    metric_dos.metric("DoS ATTACKS", st.session_state.stats['dos'])
    if st.session_state.history:
        log_place.dataframe(pd.DataFrame(st.session_state.history).head(8), hide_index=True, use_container_width=True)
    else:
        log_place.info("No threats logged yet. Start the system to simulate traffic.")

# Small footer
st.markdown("---")
st.caption("Note: This demo replays rows of NSL-KDD as simulated live traffic. Blockchain writes are executed in background threads (if libs available).")
