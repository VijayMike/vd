import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import streamlit as st
import sqlite3
import time
import os

# ------------------- Config -------------------
HEADERS = {'User-Agent': 'Mozilla/5.0'}
MAX_PAGES = 50  # Limit crawling to avoid overload
DB_FILE = 'scan_results.db'

# ------------------- DB Setup -------------------
conn = sqlite3.connect(DB_FILE)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS scans
            (url TEXT, label TEXT, match TEXT, location TEXT, timestamp TEXT)''')
conn.commit()

# ------------------- Patterns & Suggestions -------------------
LEAK_PATTERNS = {
    'Email Address': (re.compile(r'[\w\.-]+@[\w\.-]+'), "Avoid exposing emails directly. Use forms or CAPTCHA."),
    'API Key': (re.compile(r'(api_key|apikey|API_KEY|sk_live|sk_test|pk_live|pk_test)[=:\"\']?[a-zA-Z0-9_\-]{10,}'), "Store keys in env vars. Never hardcode them in frontend."),
    'AWS Secret': (re.compile(r'AKIA[0-9A-Z]{16}'), "Do not expose AWS secrets. Rotate keys if exposed."),
    'Private IP': (re.compile(r'\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b|\b192\.168\.(?:[0-9]{1,3}\.)[0-9]{1,3}\b'), "Private IPs shouldn’t be exposed in public content."),
    'JWT Token': (re.compile(r'eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+'), "Never expose tokens. Use secure HTTP-only cookies instead."),
    'Basic Auth Credentials': (re.compile(r'[\w\-]+:[\w\-]+@'), "Credentials should not be visible in URLs. Use secure headers."),
}

# ------------------- Helper Functions -------------------
def save_to_db(url, label, match, location):
    c.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?)",
            (url, label, match, location, time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

def get_internal_links(base_url, soup):
    links = set()
    for tag in soup.find_all('a', href=True):
        href = tag['href']
        joined_url = urljoin(base_url, href)
        if urlparse(joined_url).netloc == urlparse(base_url).netloc:
            links.add(joined_url)
    return links

def scan_page(url, visited):
    leaks_found = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text()

        for label, (pattern, suggestion) in LEAK_PATTERNS.items():
            for match in pattern.findall(text):
                snippet = match if len(match) < 60 else match[:57] + '...'
                location = f"{url}"
                leaks_found.append((label, snippet, location, suggestion))
                save_to_db(url, label, match, location)

        internal_links = get_internal_links(url, soup)
        for link in internal_links:
            if link not in visited and len(visited) < MAX_PAGES:
                visited.add(link)
                leaks_found.extend(scan_page(link, visited))
    except Exception as e:
        st.error(f"Error scanning {url}: {e}")
    return leaks_found

# ------------------- Streamlit UI -------------------
st.set_page_config(page_title="Sensitive Data Exposure Scanner", layout="wide")
st.title("🔍 Sensitive Data Exposure Scanner")

# Sidebar input for website URL
input_url = st.sidebar.text_input("Enter a target website URL (e.g., https://example.com)")

if st.sidebar.button("Scan Now") and input_url:
    st.info("Starting deep scan... Please wait.")
    
    visited = set()
    visited.add(input_url)
    leaks = scan_page(input_url, visited)

    # Displaying scan results in the main body
    if leaks:
        st.success(f"✅ {len(leaks)} sensitive data leaks found!")
        for label, match, location, suggestion in leaks:
            st.markdown(f"""
            <div style="border:1px solid #ddd; padding:10px; margin:10px 0; border-radius:8px;">
                <b>🔐 Leak Type:</b> {label}<br>
                <b>🌐 Found At:</b> <a href="{location}" target="_blank">{location}</a><br>
                <b>🧩 Snippet:</b> <code>{match}</code><br>
                <b>💡 Suggestion:</b> {suggestion}
            </div>
            """, unsafe_allow_html=True)

        # Generate downloadable report
        report_content = "🔐 VulneraDetect Scan Report\n"
        report_content += f"Target URL: {input_url}\n"
        report_content += f"Scanned Pages: {len(visited)}\n"
        report_content += f"Leaks Found: {len(leaks)}\n"
        report_content += "-" * 40 + "\n"

        for label, match, location, suggestion in leaks:
            report_content += f"""
            Leak Type: {label}
            Found At : {location}
            Snippet  : {match}
            Suggestion: {suggestion}
            {'-'*40}
            """

        st.download_button(
            label="📄 Download Scan Report",
            data=report_content,
            file_name="vulneradetect_scan_report.txt",
            mime="text/plain"
        )

    else:
        st.success("✅ No sensitive data leaks found.")

    with st.expander("📊 View Previous Scan Logs"):
        results = c.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50").fetchall()
        for row in results:
            st.write(f"[{row[4]}] {row[0]} | {row[1]}: {row[2]}")

# Footer
st.markdown("""---
🔒 Built  by **VulneraDetect** – your first step to proactive web security.
""")
