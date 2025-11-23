import streamlit as st
import pandas as pd
import requests
import json
import time
from datetime import datetime
from solders.pubkey import Pubkey

# -----------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------
BACKEND_URL = "https://laptop.aditya.stream"
SSE_URL = f"{BACKEND_URL}/sse"
VERIFY_URL = f"{BACKEND_URL}/verify"
PROGRAM_ID = Pubkey.from_string("J3zRkAgCWjpXnKUr6teTdS2nLTGA3ZhEUi6gBvi5ZhdY")

st.set_page_config(
    page_title="SentinelFlow – Live Threat Monitor",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------
# CUSTOM CSS (Cyberpunk/Dark Theme)
# -----------------------------------------------------
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #c9d1d9; }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #161b22;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #30363d;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    /* Headers */
    h1, h2, h3 { color: #58a6ff !important; font-family: 'Segoe UI', monospace; }
    
    /* Custom Logs Styling */
    .log-row {
        background-color: #161b22;
        padding: 10px;
        border-radius: 5px;
        margin-bottom: 5px;
        border-left: 3px solid #30363d;
    }
    .log-benign { border-left-color: #2ea043; }
    .log-malicious { border-left-color: #f85149; }
    
    /* Proof Text */
    .proof-text {
        font-family: monospace;
        font-size: 0.8em;
        color: #2ea043;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------
# SESSION STATE INITIALIZATION
# -----------------------------------------------------
if "events" not in st.session_state:
    st.session_state.events = []
if "total_threats" not in st.session_state:
    st.session_state.total_threats = 0
if "ledger_pda" not in st.session_state:
    st.session_state.ledger_pda = None

# -----------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------

def initialize_ledger():
    import numpy as np
    seed_int = np.random.randint(1, 65535)
    seed_bytes = seed_int.to_bytes(2, "little")
    pda, _ = Pubkey.find_program_address([b"state", seed_bytes], PROGRAM_ID)

    try:
        requests.post(f"{BACKEND_URL}/createLedger", json={"seed": str(seed_int)}, timeout=5)
        st.session_state.ledger_pda = str(pda)
        st.sidebar.success(f"✅ Ledger Init: {str(pda)[:8]}...")
    except requests.exceptions.RequestException as e:
        st.sidebar.error(f"❌ Backend Error: {e}")

def verify_event(index):
    """Sends event data to backend for verification and updates state with proof."""
    event = st.session_state.events[index]
    
    # Construct payload exactly as requested
    payload = {
        "ledger": event.get("Ledger"),
        "ipAddress": event.get("IP Address"),
        "threatType": event.get("Type"),
        "actionTaken": event.get("Action")
    }

    try:
        response = requests.post(VERIFY_URL, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("verified"):
                # Update the event in session state with the proof
                st.session_state.events[index]["proof"] = data.get("proof")
                # Force a rerun to update UI immediately
                st.rerun()
            else:
                st.toast(f"Verification Failed: {data.get('message')}", icon="⚠️")
        else:
            st.toast("Verification Request Failed", icon="❌")
    except Exception as e:
        st.toast(f"Error connecting to backend: {e}", icon="🔥")

def get_event_stream():
    headers = {'Accept': 'text/event-stream'}
    try:
        with requests.get(SSE_URL, stream=True, headers=headers, timeout=30) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode('utf-8')
                    if decoded_line.startswith('data:'):
                        json_str = decoded_line[5:].strip()
                        try:
                            data = json.loads(json_str)
                            yield data
                        except json.JSONDecodeError:
                            pass
    except Exception:
        # Fail silently in loop to allow retry or stop
        return

# -----------------------------------------------------
# SIDEBAR CONTROLS
# -----------------------------------------------------
with st.sidebar:
    st.title("🎛 Controls")
    streaming_active = st.toggle("🔴 Activate Live Stream", value=False)
    st.markdown("---")
    st.write("Provide Seed / Init Ledger:")
    if st.button("Initialize New Ledger"):
        initialize_ledger()
        
    if st.session_state.ledger_pda:
        st.info(f"**Active Ledger:**\n`{st.session_state.ledger_pda}`")
    else:
        st.warning("No Ledger Initialized")

    if st.button("Clear History"):
        st.session_state.events = []
        st.session_state.total_threats = 0
        st.rerun()

# -----------------------------------------------------
# MAIN UI LAYOUT
# -----------------------------------------------------
st.title("🛡 SentinelFlow Monitor")

# 1. METRICS
col1, col2, col3, col4 = st.columns(4)
metric_count = col1.empty()
metric_last_ip = col2.empty()
metric_status = col3.empty()
metric_action = col4.empty()

# Initialize default metrics
metric_count.metric("Total Events", st.session_state.total_threats)
metric_last_ip.metric("Latest Source IP", "Waiting...")
metric_status.metric("Threat Status", "N/A")
metric_action.metric("Action Taken", "N/A")

st.markdown("---")

col_chart, col_log = st.columns([2, 1])

with col_chart:
    st.subheader("📊 Traffic Intensity")
    chart_placeholder = st.empty()

with col_log:
    st.subheader("📜 Live Event Log")
    # We create a container here that we will constantly wipe and rewrite
    log_container = st.empty()

def render_logs():
    """Renders the custom log table with Verify buttons."""
    with log_container.container():
        # Header Row
        h1, h2, h3, h4 = st.columns([2, 3, 3, 3])
        h1.markdown("**Time**")
        h2.markdown("**IP Address**")
        h3.markdown("**Type**")
        h4.markdown("**Chain Verify**")
        st.markdown("---")

        # Data Rows (Displaying max 10-15 rows to keep UI fast)
        # We iterate through the stored events
        for idx, event in enumerate(st.session_state.events):
            
            # Determine row color class based on threat type
            color_class = "log-malicious" if "Benign" not in event["Type"] else "log-benign"
            
            # Create a container for the row to apply styling (optional, using markdown below)
            row_c1, row_c2, row_c3, row_c4 = st.columns([2, 3, 3, 3])
            
            row_c1.write(f"`{event['Time']}`")
            row_c2.write(event['IP Address'])
            
            # Status with color
            if "Benign" in event['Type']:
                row_c3.markdown(f":green[{event['Type']}]")
            else:
                row_c3.markdown(f":red[{event['Type']}]")

            # VERIFY BUTTON or PROOF logic
            with row_c4:
                if event.get("proof"):
                    # If proof exists, show it
                    proof_short = event['proof'][:6] + "..." + event['proof'][-4:]
                    st.markdown(f"✅ [`{proof_short}`](https://explorer.solana.com/tx/{event['proof']}?cluster=devnet)")
                else:
                    # Show Verify Button
                    # NOTE: Unique key is required for buttons in loops
                    if st.button("Verify", key=f"vbtn_{idx}"):
                        verify_event(idx)

# -----------------------------------------------------
# MAIN LOGIC LOOP
# -----------------------------------------------------

# Initial Render (Static)
render_logs()
df_static = pd.DataFrame(st.session_state.events)
if not df_static.empty:
    chart_placeholder.line_chart(df_static.groupby("Time").count()["IP Address"], height=300)

if streaming_active:
    for evt in get_event_stream():
        
        # 1. Filter by Ledger
        if st.session_state.ledger_pda and evt.get("ledger") != st.session_state.ledger_pda:
            continue

        # 2. Process New Event
        timestamp = datetime.now().strftime("%H:%M:%S")
        st.session_state.total_threats += 1
        
        new_event = {
            "Time": timestamp,
            "IP Address": evt.get("ipAddress", "Unknown"),
            "Type": evt.get("threatType", "Unknown"),
            "Action": evt.get("actionTaken", "Unknown"),
            "Ledger": evt.get("ledger", st.session_state.ledger_pda),
            "proof": None # Initialize proof as None
        }
        
        st.session_state.events.insert(0, new_event)
        if len(st.session_state.events) > 50:
            st.session_state.events.pop()

        # 3. Update Metrics
        metric_count.metric("Total Events", st.session_state.total_threats)
        metric_last_ip.metric("Latest Source IP", new_event["IP Address"])
        
        if "Benign" in new_event["Type"]:
            metric_status.metric("Threat Status", "Benign", delta="Safe", delta_color="normal")
        else:
            metric_status.metric("Threat Status", "Malicious", delta="Detected", delta_color="inverse")
        metric_action.metric("Action Taken", new_event["Action"])

        # 4. Update Chart
        df = pd.DataFrame(st.session_state.events)
        if not df.empty:
            chart_data = df.groupby("Time").count()["IP Address"].reset_index()
            chart_data.columns = ["Time", "Count"]
            chart_placeholder.line_chart(chart_data.set_index("Time"), height=300)

        # 5. Update Logs (Custom Render)
        render_logs()
        
        # Small sleep to prevent CPU spiking
        time.sleep(0.1)