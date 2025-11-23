import streamlit as st
import pandas as pd
from datetime import datetime
import requests
import random
import time
import io

# ==========================================
# 0. DATA LOADING & UTILS
# ==========================================

# Fallback data provided by user
FALLBACK_DATA = """duration,protocol_type,service,flag,src_bytes,dst_bytes,land,wrong_fragment,urgent,hot,num_failed_logins,logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate,label
0, 1, 2, 2, 491, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 150, 25, 0.17, 0.03, 0.0, 0.0, 0.0, 0.0, 0.05, 0.0
0.6663, 0.5777, 0.2406, 0.0993, 0.7613, 0.40, 0.9963, 0.7354, 0.0424, 0.244, 0.9991, 0.6863, 0.7561, 0.3766, 0.42, 0.7636, 0.8605, 0.2622, 0.21, 0.5239, 0.77, 0.7371, 0.908, 0.7, 0.5004, 0.3518, 0.24, 0.7533, 0.0226, 0.27, 0.22, 0.251, 0.2237, 0.3368, 0.5465, 0.5235, 0.55, 0.4703, 0.5396, 0.5166, 0.6167
0.6661, 0.3736, 0.2879, 0.9999, 0.5963, 0.0412, 0.3451, 0.3648, 0.7301, 0.2264, 0.6052, 0.3933, 0.0604, 0.999, 0.5373, 0.8013, 0.5308, 0.5603, 0.1345, 0.622, 0.463, 0.2055, 0.4701, 0.207, 0.8725, 0.2812, 0.7233, 0.646, 0.6255, 0.1679, 0.4303, 0.6093, 0.3504, 0.7, 0.3272, 0.2576, 0.6912, 0.5487, 0.2602, 0.6135, 0.4132
"""

# Pre-defined IP Pool
IP_POOL = [
    "192.168.1.10",  # Reserved for 'demo'
    "10.0.0.5",
    "172.16.254.1",
    "203.0.113.42",
    "198.51.100.7"
]

@st.cache_data
def load_nsl_data():
    # Try loading from CSV first, if fails use fallback
    # try:
    #     df = pd.read_csv("nsl_kdd_dataset.csv")
    # except FileNotFoundError:
    #     st.toast("⚠️ Dataset file not found. Using sample fallback data.", icon="📂")
    #     df = pd.read_csv(io.StringIO(FALLBACK_DATA))
    
    # Using fallback directly as per recent context
    df = pd.read_csv(io.StringIO(FALLBACK_DATA))
    
    if 'label' in df.columns:
        df = df.drop(columns=['label'])
        
    return df

def get_random_ip_from_pool():
    # Returns a random IP from the pool (excluding the first one reserved for demo if needed, 
    # but for simplicity we pick from the last 4)
    return random.choice(IP_POOL[1:])

# ==========================================
# 1. AUTH CLASS
# ==========================================
class Auth:
    def __init__(self):
        # Initialize session state variables if they don't exist
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'username' not in st.session_state:
            st.session_state.username = None
        if 'user_ip' not in st.session_state:
            st.session_state.user_ip = None

    def login(self, username, password):
        valid_credentials = {'demo': 'demo1234', 'admin': 'admin123', 'user': 'user123'}
        
        if username in valid_credentials and valid_credentials[username] == password:
            st.session_state.authenticated = True
            st.session_state.username = username
            
            # Assign specific IP for 'demo', random from pool for others
            if username == 'demo':
                st.session_state.user_ip = IP_POOL[0]
            elif username == 'admin':
                st.session_state.user_ip = IP_POOL[1]
            elif username == 'user':
                st.session_state.user_ip = IP_POOL[2]
            else:
                # For other users, pick a random one from the remaining pool
                st.session_state.user_ip = get_random_ip_from_pool()
                
            return True
        return False

    def logout(self):
        st.session_state.authenticated = False
        st.session_state.username = None
        st.session_state.user_ip = None

    def is_authenticated(self):
        return st.session_state.authenticated
    
    def get_username(self):
        return st.session_state.username

# ==========================================
# 2. CONFIG & NEON DARK CSS
# ==========================================
st.set_page_config(
    page_title="TicketHub",
    page_icon="🎫",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&display=swap');

    /* GLOBAL DARK THEME OVERRIDES */
    [data-testid="stAppViewContainer"] {
        background-color: #0e1117;
        font-family: 'Outfit', sans-serif;
    }
    
    h1, h2, h3, p, div, span {
        color: #ffffff;
        font-family: 'Outfit', sans-serif;
    }

    /* GLOWING HEADER */
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: -webkit-linear-gradient(eee, #333);
        background-clip: text;
        # -webkit-text-fill-color: transparent;
        color: #fff;
        text-shadow: 0 0 15px rgba(0, 229, 255, 0.6), 0 0 30px rgba(0, 229, 255, 0.4);
        margin-bottom: 1rem;
    }

    /* CARD CONTAINER STYLING */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: #1a1c24; /* Dark Grey Card Background */
        border: 1px solid #2d2d3a;
        border-radius: 16px;
        padding: 0 !important;
        transition: all 0.3s ease;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        overflow: hidden;
    }

    div[data-testid="stVerticalBlockBorderWrapper"]:hover {
        border-color: #00e5ff; /* Neon Blue Border on Hover */
        transform: translateY(-5px);
        box-shadow: 0 0 20px rgba(0, 229, 255, 0.2);
    }

    /* IMAGE STYLING */
    .card-image-container {
        position: relative;
        height: 200px;
        width: 100%;
        overflow: hidden;
    }
    
    .card-image {
        width: 100%;
        height: 100%;
        object-fit: cover;
        opacity: 0.9;
        transition: transform 0.3s ease;
    }
    
    div[data-testid="stVerticalBlockBorderWrapper"]:hover .card-image {
        transform: scale(1.05);
        opacity: 1;
    }

    /* FLOATING TAG */
    .category-badge {
        position: absolute;
        top: 15px;
        right: 15px;
        background: rgba(0, 0, 0, 0.7);
        color: #00e5ff;
        border: 1px solid #00e5ff;
        padding: 5px 15px;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
        backdrop-filter: blur(4px);
        box-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
        z-index: 2;
    }

    /* TEXT STYLING */
    .event-title {
        font-size: 1.3rem;
        font-weight: 700;
        color: #ffffff;
        margin: 15px 0 10px 0;
        text-shadow: 0 0 10px rgba(255,255,255,0.3);
    }

    .event-meta {
        color: #a0a0a0;
        font-size: 0.9rem;
        display: flex;
        align-items: center;
        margin-bottom: 5px;
    }

    .event-meta svg {
        margin-right: 8px;
        width: 16px;
        height: 16px;
        color: #00e5ff; /* Neon Icon Color */
    }

    /* PRICE GLOW */
    .price-tag {
        font-size: 1.4rem;
        font-weight: 700;
        color: #00e5ff;
        text-shadow: 0 0 10px rgba(0, 229, 255, 0.5);
    }

    /* BUTTON STYLING */
    .stButton button {
        background: linear-gradient(90deg, #00c6ff 0%, #0072ff 100%);
        color: white;
        border: none;
        font-weight: 600;
        width: 100%;
        border-radius: 8px;
        padding: 0.6rem 1rem;
        margin-top: 10px;
    }
    
    .stButton button:hover {
        box-shadow: 0 0 15px rgba(0, 114, 255, 0.6);
        color: white;
    }

    /* INPUT FIELDS */
    .stTextInput input {
        background-color: #1a1c24;
        color: white;
        border: 1px solid #2d2d3a;
    }
    
    /* USER PILL */
    .user-pill {
        background: #1a1c24;
        border: 1px solid #333;
        color: #fff;
        padding: 8px 20px;
        border-radius: 30px;
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 3. ROBUST DATA (Fixed Images)
# ==========================================
EVENTS_DATA = [
    {
        'id': 1,
        'title': "Summer Music Festival",
        'date': "Jun 15, 2025",
        'location': "Central Park, NY",
        'price': 85,
        'category': "Music",
        'available': 450,
        'image_url': "https://images.unsplash.com/photo-1501281668745-f7f57925c3b4?auto=format&fit=crop&w=800&q=80", 
    },
    {
        'id': 2,
        'title': "Tech Conference 2025",
        'date': "Jul 22, 2025",
        'location': "San Francisco, CA",
        'price': 199,
        'category': "Technology",
        'available': 120,
        'image_url': "https://images.unsplash.com/photo-1505373877841-8d25f7d46678?auto=format&fit=crop&w=800&q=80",
    },
    # {
    #     'id': 3,
    #     'title': "Comedy Night Live",
    #     'date': "Jun 28, 2025",
    #     'location': "MSG, NY",
    #     'price': 65,
    #     'category': "Comedy",
    #     'available': 380,
    #     'image_url': "https://images.unsplash.com/photo-1585699324551-f603ad9a158d?auto=format&fit=crop&w=800&q=80",
    # },
    {
        'id': 4,
        'title': "Sports Championship",
        'date': "Aug 10, 2025",
        'location': "Yankee Stadium, NY",
        'price': 120,
        'category': "Sports",
        'available': 2500,
        'image_url': "https://images.unsplash.com/photo-1461896836934-ffe607ba8211?auto=format&fit=crop&w=800&q=80",
    },
    # {
    #     'id': 5,
    #     'title': "Modern Art Opening",
    #     'date': "Jul 5, 2025",
    #     'location': "MoMA, New York",
    #     'price': 25,
    #     'category': "Art",
    #     'available': 300,
    #     'image_url': "https://images.unsplash.com/photo-1518998053901-5348d3969161?auto=format&fit=crop&w=800&q=80",
    # },
    {
        'id': 6,
        'title': "Food & Wine Festival",
        'date': "Jul 18, 2025",
        'location': "Downtown LA, CA",
        'price': 95,
        'category': "Food",
        'available': 600,
        'image_url': "https://images.unsplash.com/photo-1504674900247-0877df9cc836?auto=format&fit=crop&w=800&q=80",
    }
]

# ==========================================
# 4. MAIN APP
# ==========================================
class ModernTicketApp:
    def __init__(self):
        self.auth = Auth()
        self.events_df = pd.DataFrame(EVENTS_DATA)
        self.dataset_df = load_nsl_data()
        
    def login_page(self):
        c1, c2, c3 = st.columns([1, 1, 1])
        with c2:
            st.markdown("<br><br><br>", unsafe_allow_html=True)
            st.markdown('<div class="main-header" style="text-align:center">🎫 TicketHub</div>', unsafe_allow_html=True)
            with st.form("login_form"):
                st.markdown("<p style='text-align:center; color:#aaa'>Login to continue</p>", unsafe_allow_html=True)
                username = st.text_input("Username", placeholder="demo")
                password = st.text_input("Password", type="password", placeholder="demo1234")
                
                if st.form_submit_button("Enter Platform", use_container_width=True):
                    if self.auth.login(username, password):
                        st.rerun()
                    else:
                        st.error("Invalid credentials")

    def send_data_payload(self):
        """Sends random dataset row to the backend"""
        if self.dataset_df.empty:
            st.error("Dataset not loaded. Cannot send payload.")
            return

        try:
            # Simple random sampling as we removed label column in load_nsl_data
            # and rely on server for classification
            random_row = self.dataset_df.sample(n=1).iloc[0].to_dict()
            
            # Ensure label is gone (it should be from load_nsl_data but extra safety check)
            if 'label' in random_row:
                del random_row['label']
            
            # Convert any potential numpy types to standard python types for JSON serialization
            # This handles 0 values correctly (they are preserved as 0 or 0.0)
            payload = {k: (float(v) if isinstance(v, (int, float)) else v) for k, v in random_row.items()}

            # 3. Prepare Headers with Session IP
            # Ensure we have an IP even if session state was cleared or not initialized properly
            current_ip = st.session_state.get('user_ip')
            if not current_ip:
                # Fallback to pool if missing (though login should set it)
                current_ip = get_random_ip_from_pool()
                st.session_state.user_ip = current_ip

            headers = {
                "Content-Type": "application/json",
                "ip": current_ip 
            }

            # 4. Send POST Request
            url = "https://informational-feedback-engagement-reading.trycloudflare.com/predict"
            
            # UI for Debugging
            with st.expander("ℹ️ Debug: Payload & Network Settings", expanded=True):
                st.write(f"**Target URL:** `{url}`")
                st.write(f"**Headers:** `{headers}`") 
                st.json(payload)
                
                use_mock = st.checkbox("🛠️ Enable Mock Mode (Simulate Success)", value=False)

            if use_mock:
                with st.spinner("Simulating server request..."):
                    time.sleep(1.5) 
                st.toast("✅ (Mock) Transaction sent successfully!", icon="🚀")
                return

            with st.spinner("Sending data to server..."):
                response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            if response.status_code == 200:
                print(response.json()) 
                st.toast("✅ Transaction sent to server!", icon="🚀")
                with st.expander("Server Response"):
                    st.json(response.json())
            else:
                st.toast(f"⚠️ Server returned {response.status_code}", icon="⚠️")
                
        except requests.exceptions.ConnectionError:
            st.error(f"❌ Connection Error: Could not reach `{url}`.")
            st.info("💡 Tip: Check 'Enable Mock Mode' in the debug expander.")
        except requests.exceptions.Timeout:
            st.error("❌ Error: Request timed out.")
        except Exception as e:
            st.error(f"Error sending payload: {str(e)}")

    def render_event_card(self, event):
        # The card container
        with st.container(border=True):
            st.markdown(f"""
            <div class="card-image-container">
                <div class="category-badge">{event['category']}</div>
                <img src="{event['image_url']}" class="card-image" onerror="this.onerror=null; this.src='https://via.placeholder.com/800x400?text=Event';">
            </div>
            <div style="padding: 0 10px;">
                <div class="event-title">{event['title']}</div>
                <div class="event-meta">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
                    {event['date']}
                </div>
                <div class="event-meta">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                    {event['location']}
                </div>
                <div class="event-meta" style="margin-bottom: 15px;">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 5v2m0 4v2m0 4v2M5 5a2 2 0 00-2 2v3a2 2 0 110 4v3a2 2 0 002 2h14a2 2 0 002-2v-3a2 2 0 110-4V7a2 2 0 00-2-2H5z"></path></svg>
                    {event['available']} left
                </div>
            </div>
            """, unsafe_allow_html=True)

            c_price, c_btn = st.columns([1, 1.5])
            with c_price:
                st.markdown(f"""<div style="padding-left:10px; padding-top:5px;"><div class="price-tag">₹{event['price']}</div></div>""", unsafe_allow_html=True)
            with c_btn:
                if st.button("Book Now", key=f"btn_{event['id']}", use_container_width=True):
                    self.send_data_payload()

    def main_view(self):
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown('<div class="main-header">Featured Events</div>', unsafe_allow_html=True)
        with col2:
            display_ip = st.session_state.get('user_ip')
            if not display_ip:
                # Fallback if session was cleared but user is still viewing (unlikely with Auth guard)
                display_ip = get_random_ip_from_pool()
                st.session_state.user_ip = display_ip
                
            st.markdown(f'<div style="text-align:right; padding-top:15px"><span class="user-pill">👤 {self.auth.get_username()} (IP: {display_ip})</span></div>', unsafe_allow_html=True)

        search = ""
        category = "All Categories"

        df = self.events_df.copy()
        if search:
            df = df[df['title'].str.contains(search, case=False)]
        if category != "All Categories":
            df = df[df['category'] == category]

        events = df.to_dict('records')
        if not events:
            st.warning("No events found.")
        else:
            for i in range(0, len(events), 3):
                batch = events[i:i+3]
                cols = st.columns(3)
                for idx, event in enumerate(batch):
                    with cols[idx]:
                        self.render_event_card(event)

    def run(self):
        if not self.auth.is_authenticated():
            self.login_page()
        else:
            self.main_view()

if __name__ == "__main__":
    app = ModernTicketApp()
    app.run()