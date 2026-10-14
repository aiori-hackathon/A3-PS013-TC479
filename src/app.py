"""
app.py - the interactive incident dashboard.   Start it with:   streamlit run app.py

Everything is driven by the filters in the sidebar. You can also filter by:
  * dragging across the activity chart (zooms the time window),
  * clicking a bar in the "Top source IPs" chart,
  * clicking "Investigate" on a detection,
  * clicking a row in the timeline and using the pivot buttons.
The dark theme is set in .streamlit/config.toml.
"""
import html
import json
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

import config
from src import ai_helper, attack_map, database, evidence, normalize, pipeline, report, validate

st.set_page_config(page_title="ARIXA Forensic Timeline | Incident Console",
                   page_icon=":material/shield:", layout="wide")

SEVERITIES = database.SEVERITIES                       # INFO, WARN, HIGH, CRITICAL
SEV_ORDER = SEVERITIES[::-1]                           # most serious first
TIMEZONES = ["UTC", "Asia/Kolkata", "America/New_York", "America/Chicago", "America/Los_Angeles",
             "Europe/London", "Europe/Berlin", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney"]
SEV_COLOR = {"CRITICAL": "#EF4444", "HIGH": "#F97316", "WARN": "#EAB308", "INFO": "#64748B"}
SEV_ROW_BG = {"CRITICAL": "rgba(239,68,68,0.14)", "HIGH": "rgba(249,115,22,0.11)",
              "WARN": "rgba(234,179,8,0.10)"}

# ---------------------------------------------------------------------------
# Light / dark mode.
# Streamlit's own parts (tables, inputs, charts) follow its theme settings,
# which we switch at runtime. Our own HTML cards use the CSS variables below.
# ---------------------------------------------------------------------------
STREAMLIT_THEMES = {
    "dark": {"base": "dark", "primaryColor": "#3B82F6", "backgroundColor": "#0B1120",
             "secondaryBackgroundColor": "#111827", "textColor": "#E2E8F0",
             "borderColor": "#1E293B", "dataframeHeaderBackgroundColor": "#0F172A"},
    "light": {"base": "light", "primaryColor": "#2563EB", "backgroundColor": "#F6F8FB",
              "secondaryBackgroundColor": "#EDF1F7", "textColor": "#0F172A",
              "borderColor": "#DCE3EC", "dataframeHeaderBackgroundColor": "#EEF2F7"},
}
CSS_VARS = {
    "dark": {"bg": "#0B1120", "surface": "#111827", "surface2": "#0F172A", "border": "#1E293B",
             "text": "#E2E8F0", "muted": "#94A3B8", "faint": "#64748B", "accent": "#3B82F6",
             "top1": "#131C2E", "top2": "#0F172A", "chip-bg": "#0B1220", "track": "#1E293B",
             "shadow": "none",
             "mitre-bg": "#1E293B", "mitre-fg": "#BFDBFE", "mitre-bd": "#27354D",
             "ok-fg": "#86EFAC", "ok-bd": "#166534", "ok-bg": "#052E16",
             "bad-fg": "#FCA5A5", "bad-bd": "#7F1D1D", "bad-bg": "#450A0A",
             "ai-fg": "#93C5FD", "ai-bd": "#1E3A8A", "ai-bg": "#0B1B3F", "filter-fg": "#BFDBFE",
             "al-fg": "#FDE68A", "al-bd": "#713F12", "al-bg": "#291A05",
             "s-crit": "#FCA5A5", "s-high": "#FDBA74", "s-warn": "#FDE047", "s-info": "#CBD5E1"},
    "light": {"bg": "#F6F8FB", "surface": "#FFFFFF", "surface2": "#F8FAFC", "border": "#DCE3EC",
              "text": "#0F172A", "muted": "#475569", "faint": "#64748B", "accent": "#2563EB",
              "top1": "#FFFFFF", "top2": "#F1F5F9", "chip-bg": "#F8FAFC", "track": "#E2E8F0",
              "shadow": "0 1px 2px rgba(15,23,42,.06)",
              "mitre-bg": "#EFF6FF", "mitre-fg": "#1D4ED8", "mitre-bd": "#BFDBFE",
              "ok-fg": "#166534", "ok-bd": "#86EFAC", "ok-bg": "#F0FDF4",
              "bad-fg": "#991B1B", "bad-bd": "#FCA5A5", "bad-bg": "#FEF2F2",
              "ai-fg": "#1E40AF", "ai-bd": "#93C5FD", "ai-bg": "#EFF6FF", "filter-fg": "#1D4ED8",
              "al-fg": "#854D0E", "al-bd": "#FDE68A", "al-bg": "#FEFCE8",
              "s-crit": "#B91C1C", "s-high": "#C2410C", "s-warn": "#A16207", "s-info": "#475569"},
}
# Severity text colours inside tables (darker shades so they stay readable on white).
SEV_TEXT = {"dark": {"CRITICAL": "#F87171", "HIGH": "#FB923C", "WARN": "#FACC15", "INFO": "#94A3B8"},
            "light": {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "WARN": "#A16207", "INFO": "#64748B"}}
STATUS_TEXT = {"dark": ("#4ADE80", "#F87171"), "light": ("#15803D", "#DC2626")}

# The toggle's value lives in session_state; keep Streamlit's theme in sync with it.
st.session_state.setdefault("dark_mode", st._config.get_option("theme.base") != "light")
MODE = "dark" if st.session_state.dark_mode else "light"
if st._config.get_option("theme.base") != MODE:
    for option, value in STREAMLIT_THEMES[MODE].items():
        st._config.set_option(f"theme.{option}", value)
    st.rerun()                     # redraw with the new theme
SEV_FG = SEV_TEXT[MODE]
OK_FG, BAD_FG = STATUS_TEXT[MODE]

# ---------------------------------------------------------------------------
# Styling. HTML strings have no leading spaces on purpose (Markdown would
# otherwise turn indented HTML into a code block).
# ---------------------------------------------------------------------------
st.markdown("<style>:root{" + ";".join(f"--{k}:{v}" for k, v in CSS_VARS[MODE].items()) + "}</style>",
            unsafe_allow_html=True)
st.markdown("""<style>
.block-container{padding-top:1.4rem;padding-bottom:2rem;max-width:1500px}
header[data-testid="stHeader"]{background:transparent}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;padding:14px 18px;border:1px solid var(--border);border-radius:10px;background:linear-gradient(180deg,var(--top1),var(--top2));box-shadow:var(--shadow)}
.brand{display:flex;gap:12px;align-items:center}
.logo{width:40px;height:40px;border-radius:9px;background:linear-gradient(135deg,#2563EB,#1E40AF);display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;font-size:.95rem}
.brand .title{font-size:1.15rem;font-weight:650;color:var(--text);line-height:1.2}
.brand .subtitle{font-size:.78rem;color:var(--muted)}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:.74rem;padding:4px 11px;border-radius:999px;border:1px solid var(--border);color:var(--muted);background:var(--chip-bg);white-space:nowrap}
.chip.ok{color:var(--ok-fg);border-color:var(--ok-bd);background:var(--ok-bg)}
.chip.bad{color:var(--bad-fg);border-color:var(--bad-bd);background:var(--bad-bg)}
.chip.ai{color:var(--ai-fg);border-color:var(--ai-bd);background:var(--ai-bg)}
.chip.filter{color:var(--filter-fg);border-color:var(--accent);background:var(--ai-bg)}
.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:10px}
@media(max-width:1100px){.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}
.kpi{border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:var(--surface);border-top:3px solid var(--k,#3B82F6);box-shadow:var(--shadow)}
.kpi .label{font-size:.7rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
.kpi .value{font-size:1.65rem;font-weight:650;color:var(--text);line-height:1.35}
.kpi .value small{font-size:.85rem;color:var(--muted);font-weight:500}
.kpi .sub{font-size:.74rem;color:var(--muted)}
.section{font-size:.74rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600;margin:4px 0 8px}
.hint{font-size:.74rem;color:var(--faint);margin:-4px 0 8px}
.sev{display:inline-block;font-size:.66rem;font-weight:700;letter-spacing:.05em;padding:2px 8px;border-radius:4px;border:1px solid}
.sev-critical{background:rgba(239,68,68,.12);color:var(--s-crit);border-color:rgba(239,68,68,.45)}
.sev-high{background:rgba(249,115,22,.12);color:var(--s-high);border-color:rgba(249,115,22,.45)}
.sev-warn{background:rgba(234,179,8,.12);color:var(--s-warn);border-color:rgba(234,179,8,.45)}
.sev-info{background:rgba(100,116,139,.12);color:var(--s-info);border-color:rgba(100,116,139,.45)}
.mitre{font-family:Consolas,monospace;font-size:.7rem;padding:2px 7px;border-radius:4px;background:var(--mitre-bg);color:var(--mitre-fg);border:1px solid var(--mitre-bd)}
.step{padding:2px 0 2px 14px;border-left:3px solid var(--dot)}
.step .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.step .when{font-family:Consolas,monospace;font-size:.74rem;color:var(--muted)}
.step .what{font-weight:600;color:var(--text);font-size:.92rem;margin-top:3px}
.step .detail{font-size:.8rem;color:var(--muted);margin-top:2px}
.step .meta{font-size:.72rem;color:var(--faint);margin-top:3px;font-family:Consolas,monospace}
.sevrow{display:grid;grid-template-columns:80px 1fr 44px;gap:10px;align-items:center;margin:7px 0;font-size:.8rem;color:var(--muted)}
.bar{height:8px;border-radius:4px;background:var(--track);overflow:hidden}
.bar>div{height:100%;border-radius:4px}
.src{padding:9px 12px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;background:var(--surface)}
.src .name{font-family:Consolas,monospace;font-size:.78rem;color:var(--text);word-break:break-all}
.src .info{font-size:.72rem;color:var(--muted);margin-top:2px}
.kv{display:grid;grid-template-columns:110px 1fr;gap:4px 12px;font-size:.82rem}
.kv .k{color:var(--muted)}
.kv .v{color:var(--text);font-family:Consolas,monospace;word-break:break-all}
.note{font-size:.8rem;color:var(--muted);padding:10px 14px;border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:6px;background:var(--surface2);margin-bottom:12px}
.ailabel{font-size:.78rem;color:var(--al-fg);padding:8px 12px;border:1px solid var(--al-bd);background:var(--al-bg);border-radius:6px;margin:8px 0}
.footer{margin-top:28px;padding-top:12px;border-top:1px solid var(--border);font-size:.72rem;color:var(--faint);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
.stTabs [data-baseweb="tab-list"]{gap:4px;border-bottom:1px solid var(--border)}
.stTabs [data-baseweb="tab"]{padding:10px 18px}
.stTabs [data-baseweb="tab"] p{font-size:.98rem;font-weight:600}
/* ---- Main navigation bar ---- */
.st-key-navbar{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:8px 10px;margin:4px 0 16px;box-shadow:var(--shadow)}
.st-key-navbar button{min-height:54px;padding:0 8px;border-radius:10px;border:1px solid transparent;background:transparent;color:var(--muted);transition:all .18s ease}
.st-key-navbar button p{font-size:.93rem;font-weight:600;white-space:nowrap}
.st-key-navbar button:hover{background:var(--surface2);color:var(--text);border-color:var(--border);transform:translateY(-1px)}
.st-key-navbar button[data-testid="stBaseButton-primary"]{background:var(--accent);color:#fff;border-color:var(--accent);box-shadow:0 6px 18px rgba(59,130,246,.35)}
/* ---- AI Copilot: animated gradient border + soft glow ---- */
.st-key-nav_ai button{color:var(--text);border:1.5px solid transparent !important;background:linear-gradient(var(--surface),var(--surface)) padding-box,linear-gradient(90deg,#8B5CF6,#3B82F6,#EC4899,#8B5CF6) border-box !important;background-size:100% 100%,300% 100% !important;animation:aiBorder 4s linear infinite,aiGlow 2.8s ease-in-out infinite}
.st-key-nav_ai button[data-testid="stBaseButton-primary"]{background:linear-gradient(90deg,#7C3AED,#2563EB,#DB2777,#7C3AED) !important;background-size:300% 100% !important;color:#fff;animation:aiShift 5s linear infinite,aiGlow 2.8s ease-in-out infinite}
.st-key-nav_ai button [data-testid="stIconMaterial"]{color:#A78BFA}
.st-key-nav_ai button[data-testid="stBaseButton-primary"] [data-testid="stIconMaterial"]{color:#fff}
@keyframes aiBorder{0%{background-position:0 0,0% 50%}100%{background-position:0 0,300% 50%}}
@keyframes aiShift{0%{background-position:0% 50%}100%{background-position:300% 50%}}
@keyframes aiGlow{0%,100%{box-shadow:0 0 0 rgba(139,92,246,0)}50%{box-shadow:0 0 22px rgba(139,92,246,.5)}}
.ai-hero{position:relative;padding:22px 24px;border-radius:14px;border:1.5px solid transparent;background:linear-gradient(var(--surface),var(--surface)) padding-box,linear-gradient(120deg,#8B5CF6,#3B82F6,#EC4899) border-box;margin-bottom:14px;overflow:hidden}
.ai-hero:after{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(600px 130px at 8% 0%,rgba(139,92,246,.18),transparent),radial-gradient(520px 140px at 92% 100%,rgba(236,72,153,.13),transparent)}
.ai-hero .t{font-size:1.4rem;font-weight:700;background:linear-gradient(90deg,#8B5CF6,#3B82F6,#EC4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.ai-hero .d{font-size:.88rem;color:var(--muted);margin-top:4px;max-width:920px}
[class*="st-key-ai_go"] button{background:linear-gradient(90deg,#7C3AED,#2563EB,#DB2777,#7C3AED) !important;background-size:300% 100% !important;border:none !important;color:#fff !important;animation:aiShift 5s linear infinite;box-shadow:0 6px 20px rgba(124,58,237,.35)}
.st-key-open_delete button{color:#EF4444;border-color:rgba(239,68,68,.45)}
.st-key-open_delete button:hover{background:rgba(239,68,68,.1);border-color:#EF4444;color:#EF4444}
.st-key-confirm_delete button{background:#DC2626 !important;border-color:#DC2626 !important;color:#fff !important}
.st-key-confirm_delete button:disabled{opacity:.35;cursor:not-allowed}
[data-testid="stSidebarHeader"]{height:2.2rem;min-height:0;padding-top:.6rem}
[data-testid="stSidebarUserContent"]{padding-top:.4rem}
[data-testid="stFileUploaderDropzone"]{border:2px dashed var(--accent) !important;border-radius:12px !important;background:var(--ai-bg) !important;min-height:96px;transition:all .15s ease}
[data-testid="stFileUploaderDropzone"]:hover{border-color:#8B5CF6 !important;box-shadow:0 0 0 4px rgba(59,130,246,.15)}
/* ---- Validation: emerald highlight (nav button + scorecard) ---- */
.st-key-nav_validation button{color:var(--text);border:1.5px solid transparent !important;background:linear-gradient(var(--surface),var(--surface)) padding-box,linear-gradient(90deg,#10B981,#22D3EE,#10B981) border-box !important;background-size:100% 100%,300% 100% !important;animation:aiBorder 5s linear infinite,okGlow 2.8s ease-in-out infinite}
.st-key-nav_validation button[data-testid="stBaseButton-primary"]{background:linear-gradient(90deg,#059669,#0891B2,#059669) !important;background-size:300% 100% !important;color:#fff;animation:aiShift 6s linear infinite,okGlow 2.8s ease-in-out infinite}
.st-key-nav_validation button [data-testid="stIconMaterial"]{color:#34D399}
.st-key-nav_validation button[data-testid="stBaseButton-primary"] [data-testid="stIconMaterial"]{color:#fff}
@keyframes okGlow{0%,100%{box-shadow:0 0 0 rgba(16,185,129,0)}50%{box-shadow:0 0 22px rgba(16,185,129,.5)}}
.score-hero{position:relative;padding:22px 26px;border-radius:16px;border:2px solid transparent;background:linear-gradient(var(--surface),var(--surface)) padding-box,linear-gradient(120deg,#10B981,#22D3EE,#3B82F6) border-box;margin-bottom:16px;overflow:hidden;animation:okGlow 3.2s ease-in-out infinite}
.score-hero:after{content:"";position:absolute;inset:0;pointer-events:none;background:radial-gradient(700px 160px at 0% 0%,rgba(16,185,129,.16),transparent),radial-gradient(600px 160px at 100% 100%,rgba(34,211,238,.10),transparent)}
.score-hero .top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.score-hero .t{font-size:1.35rem;font-weight:700;background:linear-gradient(90deg,#10B981,#22D3EE);-webkit-background-clip:text;background-clip:text;color:transparent}
.score-hero .verdict{font-size:.8rem;font-weight:700;letter-spacing:.06em;padding:6px 14px;border-radius:999px;background:rgba(16,185,129,.16);color:#10B981;border:1px solid rgba(16,185,129,.5)}
.score-hero .verdict.fail{background:rgba(239,68,68,.15);color:#EF4444;border-color:rgba(239,68,68,.5)}
.score-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-top:16px}
@media(max-width:1000px){.score-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.score-grid .m{padding:12px 14px;border-radius:10px;background:var(--surface2);border:1px solid var(--border)}
.score-grid .v{font-size:1.75rem;font-weight:700;color:var(--text);line-height:1.2}
.score-grid .v small{font-size:.9rem;color:var(--muted);font-weight:500}
.score-grid .l{font-size:.72rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.scard{padding:14px 16px;border-radius:12px;background:var(--surface);border:1px solid var(--border);border-top:4px solid var(--c);height:100%}
.scard .h{display:flex;justify-content:space-between;align-items:center;font-weight:650;color:var(--text)}
.scard .p{font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:999px;color:#fff;background:var(--c)}
.rule{display:inline-block;font-size:.72rem;padding:2px 8px;border-radius:6px;margin:3px 4px 0 0;border:1px solid}
.rule.ok{color:#10B981;border-color:rgba(16,185,129,.45);background:rgba(16,185,129,.10)}
.rule.miss{color:#EF4444;border-color:rgba(239,68,68,.45);background:rgba(239,68,68,.10)}
.rule.extra{color:#EAB308;border-color:rgba(234,179,8,.45);background:rgba(234,179,8,.10)}
.scard .facts{font-size:.76rem;color:var(--muted);margin-top:10px;line-height:1.6}
.race{margin:6px 0 4px}
.race .row{display:grid;grid-template-columns:150px 1fr 120px;gap:12px;align-items:center;margin:8px 0;font-size:.82rem;color:var(--muted)}
.race .track{height:16px;border-radius:8px;background:var(--track);overflow:hidden}
.race .fill{height:100%;border-radius:8px}
.cmp{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
@media(max-width:1000px){.cmp{grid-template-columns:1fr}}
.cmpcol{padding:14px;border-radius:12px;background:var(--surface);border:1px solid var(--border);display:flex;flex-direction:column;gap:6px}
.cmpcol .h{font-weight:700;color:var(--text);font-size:.95rem}
.cmpcol .s{font-size:.74rem;color:var(--muted);margin-bottom:4px}
.ev{display:grid;grid-template-columns:62px 52px 1fr;gap:8px;align-items:center;font-size:.76rem;padding:6px 8px;border-radius:8px;color:var(--muted);background:var(--surface2)}
.ev.attack{color:var(--text);background:rgba(249,115,22,.12);box-shadow:inset 3px 0 0 #F97316}
.ev.attack.shell{background:rgba(124,58,237,.14);box-shadow:inset 3px 0 0 #8B5CF6}
.ev .tm{font-family:Consolas,monospace}
.ev .hs{font-family:Consolas,monospace;font-size:.68rem;padding:1px 6px;border-radius:4px;background:var(--mitre-bg);color:var(--mitre-fg);text-align:center}
.vd{margin-top:auto;padding:10px 12px;border-radius:8px;font-size:.8rem;font-weight:600}
.vd.ok{color:#10B981;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.45)}
.vd.bad{color:#EF4444;background:rgba(239,68,68,.10);border:1px solid rgba(239,68,68,.4)}
.kc{display:flex;gap:3px;margin:2px 0 8px;flex-wrap:nowrap;overflow-x:auto}
.kc .t{flex:1 1 0;min-width:96px;padding:10px 8px 10px 19px;background:var(--surface2);color:var(--faint);clip-path:polygon(0 0,calc(100% - 12px) 0,100% 50%,calc(100% - 12px) 100%,0 100%,12px 50%);transition:transform .15s ease}
.kc .t:first-child{padding-left:14px;clip-path:polygon(0 0,calc(100% - 12px) 0,100% 50%,calc(100% - 12px) 100%,0 100%)}
.kc .t.lit{color:var(--text);box-shadow:inset 0 3px 0 var(--c)}
.kc .t.lit:hover{transform:translateY(-2px)}
.kc .id{font-family:Consolas,monospace;font-size:.66rem;opacity:.8}
.kc .n{font-size:.76rem;font-weight:650;min-height:2.5em;line-height:1.25;margin:2px 0;word-break:normal;overflow-wrap:normal;hyphens:none}
.kc .c{font-size:.7rem;font-family:Consolas,monospace;opacity:.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kc .t:not(.lit) .n{font-weight:500}
/* ---- Loading screen while analysing (Gmail-style top bar) ---- */
.gbar{position:fixed;top:0;left:0;right:0;height:4px;z-index:1000001;background:rgba(59,130,246,.15)}
.gbar>div{height:100%;background:linear-gradient(90deg,#4285F4,#34A853,#FBBC05,#EA4335,#4285F4);background-size:200% 100%;animation:gshift 1.2s linear infinite;box-shadow:0 0 12px rgba(66,133,244,.8);transition:width .35s ease}
@keyframes gshift{from{background-position:0 0}to{background-position:200% 0}}
.an-wrap{position:fixed;inset:0;z-index:1000000;display:flex;align-items:center;justify-content:center;background:rgba(2,6,23,.55);backdrop-filter:blur(3px);animation:fadein .2s ease}
@keyframes fadein{from{opacity:0}to{opacity:1}}
.an-card{width:min(560px,92vw);padding:22px 24px;border-radius:16px;background:var(--surface);border:1px solid var(--border);box-shadow:0 20px 60px rgba(0,0,0,.45)}
.an-title{font-size:1.1rem;font-weight:700;color:var(--text);margin-bottom:12px}
.an-track{height:8px;border-radius:999px;background:var(--track);overflow:hidden;margin-bottom:14px}
.an-track>div{height:100%;border-radius:999px;background:linear-gradient(90deg,#3B82F6,#8B5CF6,#10B981);transition:width .35s ease}
.an-steps{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px}
.an-steps li{display:flex;gap:10px;align-items:center;font-size:.86rem;color:var(--muted)}
.an-steps li.done{color:var(--text)}
.an-steps .ic{width:18px;height:18px;flex:0 0 18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700}
.an-steps li.done .ic{background:#10B981;color:#fff}
.an-steps li.now .ic{border:2px solid #3B82F6;border-top-color:transparent;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.an-done{margin-top:14px;padding:10px 12px;border-radius:8px;font-size:.86rem;color:#10B981;background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.4)}
.ai-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.ai-pill{font-size:.72rem;padding:3px 10px;border-radius:999px;border:1px solid var(--border);color:var(--muted);background:var(--surface2)}
</style>""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def esc(value) -> str:
    return "-" if value in (None, "") else html.escape(str(value))


def badge(sev: str) -> str:
    return f'<span class="sev sev-{sev.lower()}">{sev}</span>'


def short_time(iso) -> str:
    """'2026-10-09T08:32:10Z' -> '2026-10-09 08:32:10'."""
    return iso.replace("T", " ").replace("Z", "") if iso else "-"


def html_block(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def to_naive(iso: str) -> datetime:
    """ISO UTC string -> naive datetime (the time slider works with naive UTC values)."""
    return normalize.from_iso(iso).replace(tzinfo=None)


def to_iso(dt: datetime) -> str:
    return normalize.to_iso(dt.replace(tzinfo=timezone.utc))


conn = database.connect()
stats = database.stats(conn)
ai_on, ai_msg = ai_helper.status()

# ---------------------------------------------------------------------------
# Header bar with live status chips
# ---------------------------------------------------------------------------
checks = evidence.verify(log=False)
if not checks:
    ev_chip = '<span class="chip">No evidence collected</span>'
elif all(c["status"] == "OK" for c in checks):
    ev_chip = f'<span class="chip ok">&#9679; Evidence verified {len(checks)}/{len(checks)}</span>'
else:
    bad = sum(1 for c in checks if c["status"] != "OK")
    ev_chip = f'<span class="chip bad">&#9679; Integrity failure: {bad} file(s)</span>'
ai_chip = ('<span class="chip ai">AI assist enabled</span>' if ai_on
           else '<span class="chip">AI assist off</span>')
head_col, mode_col = st.columns([7, 1.3], vertical_alignment="center")
with head_col:
    html_block(
        '<div class="topbar"><div class="brand"><div class="logo">AX</div><div>'
        '<div class="title">ARIXA Forensic Timeline</div>'
        '<div class="subtitle">Incident reconstruction console &middot; PS-013 &middot; all times UTC</div>'
        f'</div></div><div class="chips">{ev_chip}{ai_chip}'
        f'<span class="chip">{stats["sources"]} source(s)</span></div></div>')
with mode_col:
    st.toggle(":material/dark_mode: Dark" if MODE == "dark" else ":material/light_mode: Light",
              key="dark_mode", help="Switch between dark and light appearance")


# ---------------------------------------------------------------------------
# Loading screen while logs are analysed: a Gmail-style bar across the top of the
# page plus a checklist of the real pipeline steps. Each step stays on screen for a
# moment so the audience can follow it; that pause is NOT counted as triage time.
# ---------------------------------------------------------------------------
OVERLAY = st.empty()


def _draw_loading(title: str, steps: list, fraction: float, summary: str = "") -> None:
    items = "".join(
        f'<li class="{"done" if s["done"] else "now"}"><span class="ic">{"&#10003;" if s["done"] else ""}</span>'
        f'{esc(s["label"])}</li>' for s in steps)
    OVERLAY.markdown(
        f'<div class="gbar"><div style="width:{max(fraction, 0.04) * 100:.0f}%"></div></div>'
        f'<div class="an-wrap"><div class="an-card"><div class="an-title">{esc(title)}</div>'
        f'<div class="an-track"><div style="width:{max(fraction, 0.04) * 100:.0f}%"></div></div>'
        f'<ul class="an-steps">{items}</ul>'
        + (f'<div class="an-done">{summary}</div>' if summary else "") + '</div></div>',
        unsafe_allow_html=True)


def analyse_with_loading(title: str, files: int, run):
    """Run `run(progress)` (a pipeline.ingest call) behind the loading screen; returns its result."""
    steps = []
    pause = min(0.4, max(0.15, 2.2 / (2 * max(files, 1) + 2)))   # about 2-3 s in total

    def progress(stage, label, fraction):
        if steps:
            steps[-1]["done"] = True
        steps.append({"label": label, "done": False})
        _draw_loading(title, steps, fraction)
        time.sleep(pause)

    _draw_loading(title, [{"label": "Reading the files", "done": False}], 0.02)
    result = run(progress)
    for s in steps:
        s["done"] = True
    _draw_loading(title, steps, 1.0,
                  f'&#10003; Analysis complete: <b>{result["events"]:,} events</b>, '
                  f'<b>{result["detections"]} alerts</b>, {result["gaps"]} parsing gaps &middot; '
                  f'processing time {result["seconds"]:.2f} s')
    time.sleep(0.9)
    OVERLAY.empty()
    return result


def load_samples_now():
    """Reload the three built-in scenarios behind the loading screen, then redraw everything."""
    pipeline.reset_outputs()
    folders = sorted(p for p in config.SAMPLE_LOGS_DIR.iterdir() if p.is_dir())
    analyse_with_loading("Loading the three sample scenarios", 4,
                         lambda progress: pipeline.ingest(folders, verbose=False, progress=progress))
    st.session_state.pop("f_time", None)       # new data -> new time range
    st.rerun()


# ---------------------------------------------------------------------------
# Sidebar part 1: add evidence + case actions. Drawn before the empty-state
# check so you can upload logs even when the case is empty.
# ---------------------------------------------------------------------------
SESSION_KEYS = ("f_text", "f_ip", "f_user", "f_source", "f_sev", "f_flagged", "f_time", "nav",
                "verify", "report", "ai_explain", "ai_search", "ai_gaps", "dlg_last")


@st.dialog("Export case", width="large")
def export_dialog() -> None:
    db = database.connect()
    with st.spinner("Packing the case..."):
        bundle = report.build_case_bundle(db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%MZ")
    html_block('<div class="note">One ZIP with the incident report (Markdown + PDF), the full timeline, '
               'detections and parsing gaps as CSV, the evidence copies with their SHA-256 manifest, and '
               'the chain-of-custody log. The export itself is recorded in the custody log.</div>')
    st.download_button(f"Download full case (.zip, {len(bundle) / 1024:.0f} KB)", bundle,
                       file_name=f"forensic_case_{stamp}.zip", mime="application/zip",
                       icon=":material/folder_zip:", type="primary", width="stretch", on_click="ignore")
    c1, c2 = st.columns(2)
    c1.download_button("Timeline only (.csv)", pd.DataFrame(database.all_events(db)).to_csv(index=False),
                       file_name=f"timeline_{stamp}.csv", icon=":material/table:", width="stretch",
                       on_click="ignore")
    c2.download_button("Detections only (.json)", json.dumps(database.get_detections(db), indent=2),
                       file_name=f"detections_{stamp}.json", icon=":material/data_object:",
                       width="stretch", on_click="ignore")
    db.close()


@st.dialog("Delete current session")
def delete_dialog() -> None:
    html_block('<div class="note" style="border-left-color:#EF4444">This permanently removes the '
               'timeline and detections, the reports in <code>output/</code>, the evidence copies and '
               'manifest in <code>evidence/</code>, and files dropped into the dashboard.</div>')
    st.caption("Kept: your original log files, sample_logs/ and the chain-of-custody log (which records "
               "this deletion). Export the case first if you still need it.")
    typed = st.text_input("Type DELETE to confirm", placeholder="DELETE")
    c1, c2 = st.columns(2)
    if c1.button("Cancel", width="stretch"):
        st.rerun()
    if c2.button("Delete session", icon=":material/delete_forever:", type="primary", width="stretch",
                 key="confirm_delete", disabled=typed.strip() != "DELETE"):
        result = pipeline.delete_session()
        for key in SESSION_KEYS:
            st.session_state.pop(key, None)
        st.session_state.upload_round = st.session_state.get("upload_round", 0) + 1
        st.toast(f"Session deleted - {result['evidence_removed']} evidence copies removed",
                 icon=":material/delete:")
        st.rerun()


with st.sidebar:
    html_block('<div class="section">Add evidence</div>')
    # Drag-and-drop upload. A new key after each ingest empties the drop zone.
    st.session_state.setdefault("upload_round", 0)
    dropped = st.file_uploader(
        ":material/upload: Drop auth.log / access.log files here", accept_multiple_files=True,
        key=f"uploader_{st.session_state.upload_round}",
        help="Linux auth.log or Nginx/Apache access.log. Each file is hashed, copied read-only "
             "into evidence/ and recorded in the chain of custody.")
    if dropped:
        u1, u2 = st.columns([1.7, 1])
        upload_tz = u1.selectbox("Time zone", TIMEZONES, index=TIMEZONES.index(config.DEFAULT_TIMEZONE),
                                 help="Used for auth.log lines, which carry no time zone. "
                                      "access.log lines include their own offset.")
        upload_skew = u2.number_input("Skew (s)", value=0, step=30,
                                      help="Seconds ADDED to every time. A clock 3 minutes slow needs 180.")
        if st.button(f"Analyse {len(dropped)} file(s)", icon=":material/rocket_launch:",
                     type="primary", width="stretch"):
            folder = config.UPLOADS_DIR / f"upload_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
            folder.mkdir(parents=True, exist_ok=True)
            saved = []
            for uf in dropped:
                target = folder / Path(uf.name).name          # keep only the file name, never a path
                target.write_bytes(uf.getvalue())
                if target not in saved:                       # same file dropped twice -> once
                    saved.append(target)
            s = analyse_with_loading(
                f"Analysing {len(saved)} log file{'s' if len(saved) != 1 else ''}", len(saved),
                lambda progress: pipeline.ingest(saved, verbose=False, progress=progress,
                                                 overrides={"timezone": upload_tz, "skew_seconds": int(upload_skew)}))
            st.session_state.upload_round += 1
            st.session_state.pop("f_time", None)
            st.session_state.nav = "timeline"
            st.toast(f"Analysed {s['files']} file(s) in {s['seconds']:.2f} s - "
                     f"{s['events']} events, {s['detections']} detections", icon=":material/check_circle:")
            st.rerun()

    with st.expander("More: folder path or sample data"):
        folder_path = st.text_input("File or folder", placeholder=r"C:\cases\web01\logs")
        if st.button("Ingest", icon=":material/upload_file:", width="stretch", disabled=not folder_path.strip()):
            n_files = len(pipeline.find_log_files([folder_path.strip()]))
            s = analyse_with_loading(f"Analysing {folder_path.strip()}", n_files,
                                     lambda progress: pipeline.ingest([folder_path.strip()], verbose=False,
                                                                      progress=progress))
            st.session_state.pop("f_time", None)
            st.toast(f"Ingested {s['files']} file(s) in {s['seconds']:.2f} s")
            st.rerun()
        if st.button("Reload sample scenarios", icon=":material/restart_alt:", width="stretch"):
            load_samples_now()

    html_block('<div class="section" style="margin-top:14px">Case</div>')
    has_case = stats["events"] > 0 or bool(evidence.load_manifest())
    k1, k2 = st.columns(2)
    if k1.button("Export", icon=":material/download:", width="stretch", key="open_export",
                 disabled=stats["events"] == 0, help="Download the whole case as a ZIP, or CSV / JSON"):
        export_dialog()
    if k2.button("Delete", icon=":material/delete:", width="stretch", key="open_delete",
                 disabled=not has_case, help="Wipe the current session (asks for confirmation)"):
        delete_dialog()


if stats["events"] == 0:
    html_block('<div class="note">No timeline yet. Drop log files into <b>Add evidence</b> in the sidebar '
               '(try the files in <code>sample_uploads/</code>), or load the three built-in synthetic '
               'incidents.</div>')
    if st.button("Load sample scenarios", icon=":material/play_arrow:", type="primary"):
        load_samples_now()
    st.stop()

# ---------------------------------------------------------------------------
# Filter state. Every filter lives in st.session_state, so charts, tables and
# buttons can all change it (through on_click / on_select callbacks).
# ---------------------------------------------------------------------------
T_MIN, T_MAX = to_naive(stats["first"]), to_naive(stats["last"])
if T_MAX <= T_MIN:
    T_MAX = T_MIN + timedelta(minutes=1)
T_MIN = T_MIN.replace(second=0)                         # whole minutes for the slider
T_MAX = (T_MAX + timedelta(minutes=1)).replace(second=0)

ALL_IPS = database.distinct_values(conn, "source_ip")
ALL_USERS = database.distinct_values(conn, "username")
ALL_SOURCES = database.distinct_values(conn, "source_file")
DEFAULTS = {"f_text": "", "f_ip": "All", "f_user": "All", "f_source": "All",
            "f_sev": [], "f_flagged": False, "f_time": (T_MIN, T_MAX)}

# Fill in defaults, and repair values that no longer fit the data (e.g. after a new ingest).
for key, value in DEFAULTS.items():
    st.session_state.setdefault(key, value)
if st.session_state.f_ip not in ["All"] + ALL_IPS:
    st.session_state.f_ip = "All"
if st.session_state.f_user not in ["All"] + ALL_USERS:
    st.session_state.f_user = "All"
if st.session_state.f_source not in ["All"] + ALL_SOURCES:
    st.session_state.f_source = "All"
lo, hi = st.session_state.f_time
st.session_state.f_time = (min(max(lo, T_MIN), T_MAX), max(min(hi, T_MAX), T_MIN))


def set_filters(**values):
    """Callback used by pivot buttons: change some filters, keep the others."""
    for key, value in values.items():
        st.session_state[key] = value


def reset_filters(defaults=DEFAULTS):
    for key, value in defaults.items():
        st.session_state[key] = value


def window_around(start_iso, end_iso=None, before_min=5, after_min=15):
    """A time window around an event or detection, clamped to the data range."""
    start = to_naive(start_iso) - timedelta(minutes=before_min)
    end = to_naive(end_iso or start_iso) + timedelta(minutes=after_min)
    return (max(start.replace(second=0), T_MIN), min(end.replace(second=0) + timedelta(minutes=1), T_MAX))


# ---------------------------------------------------------------------------
# Sidebar: filters + case actions
# ---------------------------------------------------------------------------
with st.sidebar:
    st.divider()
    html_block('<div class="section">Search filters</div>')
    st.text_input("Search text", key="f_text", placeholder="e.g. sudo, shell.php, root",
                  help="Matches the event summary and the original log line.")
    st.pills("Severity", SEV_ORDER, selection_mode="multi", key="f_sev")
    st.selectbox("Source IP", ["All"] + ALL_IPS, key="f_ip")
    st.selectbox("User", ["All"] + ALL_USERS, key="f_user")
    st.selectbox("Log source", ["All"] + ALL_SOURCES, key="f_source")
    st.slider("Time window (UTC)", min_value=T_MIN, max_value=T_MAX, key="f_time",
              step=timedelta(minutes=1), format="MMM D, HH:mm")
    st.toggle("Only flagged events", key="f_flagged")
    st.button("Reset all filters", icon=":material/filter_alt_off:", width="stretch", on_click=reset_filters)
    st.caption("Analysis runs locally on read-only, hash-verified copies. Defensive use only.")

# ---------------------------------------------------------------------------
# Apply the filters once; every section below uses the same filtered set.
# ---------------------------------------------------------------------------
f = st.session_state
filtered = database.search(
    conn, ip=None if f.f_ip == "All" else f.f_ip, user=None if f.f_user == "All" else f.f_user,
    severity=f.f_sev or None, after=to_iso(f.f_time[0]), before=to_iso(f.f_time[1]),
    text=f.f_text.strip() or None, flagged_only=f.f_flagged)
if f.f_source != "All":
    filtered = [e for e in filtered if e["source_file"] == f.f_source]
filtered_ids = {e["id"] for e in filtered}

all_detections = database.get_detections(conn)
flagged_ids = database.flagged_event_ids(conn)
detections = [d for d in all_detections if filtered_ids.intersection(d["event_ids"])]

# Active-filter chips + a one-click reset, so it is always clear what you are looking at.
active = []
if f.f_text.strip():
    active.append(f'text "{esc(f.f_text.strip())}"')
for label, key in (("IP", "f_ip"), ("user", "f_user"), ("source", "f_source")):
    if f[key] != "All":
        active.append(f"{label} {esc(f[key])}")
if f.f_sev:
    active.append("severity " + "/".join(f.f_sev))
if f.f_time != (T_MIN, T_MAX):
    active.append(f"{f.f_time[0]:%b %d %H:%M} to {f.f_time[1]:%b %d %H:%M} UTC")
if f.f_flagged:
    active.append("flagged only")
if active:
    c1, c2 = st.columns([6, 1], vertical_alignment="center")
    c1.markdown('<div class="chips"><span class="chip">Filtered by</span>'
                + "".join(f'<span class="chip filter">{a}</span>' for a in active) + "</div>",
                unsafe_allow_html=True)
    c2.button("Clear", icon=":material/close:", on_click=reset_filters, width="stretch")

# ---------------------------------------------------------------------------
# KPI cards (they follow the filters)
# ---------------------------------------------------------------------------
sev_counts = {s: sum(1 for e in filtered if e["severity"] == s) for s in SEVERITIES}
timing = json.loads(config.TIMING_PATH.read_text()) if config.TIMING_PATH.exists() else None


def kpi(label, value, total, sub, colour="#3B82F6") -> str:
    shown = f"{value}<small> / {total}</small>" if active and total is not None else f"{value}"
    return (f'<div class="kpi" style="--k:{colour}"><div class="label">{label}</div>'
            f'<div class="value">{shown}</div><div class="sub">{sub}</div></div>')


html_block('<div class="kpis">'
           + kpi("Events", len(filtered), stats["events"],
                 f"{timing['tool_seconds']:.2f} s triage" if timing else "")
           + kpi("Sources", len({e['source_file'] for e in filtered}), stats["sources"], "log files on one clock")
           + kpi("Detections", len(detections), len(all_detections),
                 f"{len(filtered_ids & flagged_ids)} flagged events", "#8B5CF6")
           + kpi("Critical", sev_counts["CRITICAL"], stats["by_severity"].get("CRITICAL", 0), "events",
                 SEV_COLOR["CRITICAL"])
           + kpi("High", sev_counts["HIGH"], stats["by_severity"].get("HIGH", 0), "events", SEV_COLOR["HIGH"])
           + kpi("Parsing gaps", stats["gaps"], None, "lines kept aside", "#64748B")
           + '</div>')

# ---------------------------------------------------------------------------
# Navigation bar. The chosen section lives in session_state, so it stays put
# when filters change (built-in tabs would jump back to the first tab).
# ---------------------------------------------------------------------------
NAV_ITEMS = [
    ("overview", "Overview", ":material/dashboard:", None),
    ("timeline", "Timeline", ":material/view_timeline:", len(filtered)),
    ("detections", "Detections", ":material/crisis_alert:", len(detections)),
    ("validation", "Validation", ":material/fact_check:", None),
    ("evidence", "Evidence", ":material/verified_user:", None),
    ("gaps", "Gaps", ":material/rule:", stats["gaps"]),
    ("ai", "AI Copilot", ":material/auto_awesome:", None),
]
st.session_state.setdefault("nav", "overview")
NAV = st.session_state.nav

with st.container(key="navbar"):
    nav_cols = st.columns([1, 1.05, 1.15, 1.1, 0.95, 0.85, 1.15], gap="small")
    for col, (name, label, icon, count) in zip(nav_cols, NAV_ITEMS):
        col.button(label if count is None else f"{label} · {count}", icon=icon, key=f"nav_{name}",
                   type="primary" if NAV == name else "secondary", width="stretch",
                   on_click=set_filters, kwargs={"nav": name})

# ---------------------------------------------------------------------------
# Shared event table with clickable rows
# ---------------------------------------------------------------------------
TIMELINE_COLUMNS = {
    "id": st.column_config.NumberColumn("ID", width="small", format="%d"),
    "flagged": st.column_config.CheckboxColumn("Flag", width="small"),
    "timestamp_utc": st.column_config.TextColumn("Time (UTC)", width="medium"),
    "severity": st.column_config.TextColumn("Severity", width="small"),
    "source_file": st.column_config.TextColumn("Source", width="medium"),
    "source_ip": st.column_config.TextColumn("Source IP", width="small"),
    "username": st.column_config.TextColumn("User", width="small"),
    "event_summary": st.column_config.TextColumn("Event", width="large"),
    "raw_log": st.column_config.TextColumn("Raw log line", width="large"),
}


def show_events(rows: list, key: str, selectable: bool = True):
    """Event table: severity coloured, detection rows tinted. Returns the clicked event (or None)."""
    if not rows:
        html_block('<div class="note">No events match the current filters.</div>')
        return None
    df = pd.DataFrame(rows)
    df["flagged"] = df["id"].isin(flagged_ids)
    df = df[list(TIMELINE_COLUMNS)]
    df[["source_ip", "username"]] = df[["source_ip", "username"]].fillna("")

    def row_style(row):
        bg = SEV_ROW_BG.get(row["severity"], "") if row["flagged"] else ""
        return [f"background-color:{bg}" if bg else "" for _ in row]

    styled = (df.style.apply(row_style, axis=1)
              .map(lambda v: f"color:{SEV_FG.get(v, '#64748B')};font-weight:600", subset=["severity"]))
    options = dict(on_select="rerun", selection_mode="single-row") if selectable else {}
    # The key includes the row IDs, so a stale selection is dropped when the filters change.
    event = st.dataframe(styled, column_config=TIMELINE_COLUMNS, hide_index=True, width="stretch",
                         height=min(560, 40 + 35 * len(df)),
                         key=f"{key}_{hash(tuple(df['id']))}", **options)
    if selectable and event.selection.rows:
        return rows[event.selection.rows[0]]
    return None


def event_detail(e: dict, key: str) -> None:
    """Detail card for one event, with pivot buttons that change the filters."""
    related = [d for d in all_detections if e["id"] in d["event_ids"]]
    with st.container(border=True):
        html_block(f'<div class="section">Event #{e["id"]} &nbsp;{badge(e["severity"])}</div>')
        left, right = st.columns([3, 2], gap="large")
        with left:
            html_block('<div class="kv">'
                       f'<span class="k">Time (UTC)</span><span class="v">{esc(e["timestamp_utc"])}</span>'
                       f'<span class="k">Source</span><span class="v">{esc(e["source_file"])}</span>'
                       f'<span class="k">Format</span><span class="v">{esc(e["log_format"])}</span>'
                       f'<span class="k">Source IP</span><span class="v">{esc(e["source_ip"])}</span>'
                       f'<span class="k">User</span><span class="v">{esc(e["username"])}</span>'
                       f'<span class="k">Summary</span><span class="v">{esc(e["event_summary"])}</span>'
                       '</div>')
            st.caption("Original log line (unchanged evidence)")
            st.code(e["raw_log"], language="text", wrap_lines=True)
        with right:
            html_block('<div class="section">Part of detections</div>')
            if related:
                for d in related:
                    html_block(f'<div style="margin-bottom:6px">{badge(d["severity"])} '
                               f'<span class="mitre">{esc(d["mitre"])}</span> {esc(d["title"])}</div>')
            else:
                st.caption("Not part of any detection.")
            html_block('<div class="section" style="margin-top:12px">Pivot the whole dashboard to</div>')
            b1, b2 = st.columns(2)
            b3, b4 = st.columns(2)
            pivots = [
                b1.button("This IP", icon=":material/lan:", key=f"{key}_ip", width="stretch",
                          disabled=not e["source_ip"], on_click=set_filters,
                          kwargs={**DEFAULTS, "f_ip": e["source_ip"] or "All"}),
                b2.button("This user", icon=":material/person:", key=f"{key}_user", width="stretch",
                          disabled=not e["username"], on_click=set_filters,
                          kwargs={**DEFAULTS, "f_user": e["username"] or "All"}),
                b3.button("±15 min", icon=":material/schedule:", key=f"{key}_time", width="stretch",
                          help="Everything from all sources within 15 minutes of this event",
                          on_click=set_filters,
                          kwargs={**DEFAULTS, "f_time": window_around(e["timestamp_utc"], before_min=15)}),
                b4.button("This source", icon=":material/description:", key=f"{key}_src", width="stretch",
                          on_click=set_filters, kwargs={**DEFAULTS, "f_source": e["source_file"]}),
            ]
            if any(pivots):
                st.rerun()          # close the pop-up and redraw every tab with the new filters


@st.dialog("Event details", width="large")
def event_dialog(e: dict) -> None:
    event_detail(e, "dlg")


def open_event_once(e) -> None:
    """Open the pop-up only when a NEW row is clicked (not on every redraw)."""
    picked_id = e["id"] if e else None
    if picked_id != st.session_state.get("dlg_last"):
        st.session_state["dlg_last"] = picked_id
        if e:
            event_dialog(e)


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
def on_brush():
    """Dragging across the activity chart sets the time-window filter."""
    selection = st.session_state.get("activity_chart", {}).get("selection", {})
    span = selection.get("brush", {}).get("bucket")
    if not span or len(span) != 2:
        return
    start, end = (datetime.fromtimestamp(v / 1000, tz=timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
                  if isinstance(v, (int, float)) else to_naive(str(v)) for v in span)
    start, end = max(start, T_MIN), min(end + timedelta(minutes=1), T_MAX)
    if start < end:
        st.session_state.f_time = (start, end)


def on_ip_click():
    """Clicking a bar in the Top IPs chart filters to that IP."""
    selection = st.session_state.get("ip_chart", {}).get("selection", {})
    picked = selection.get("ip_pick", [])
    if picked and picked[0].get("IP") in ALL_IPS:
        st.session_state.f_ip = picked[0]["IP"]


KC_BG = {"CRITICAL": "rgba(239,68,68,.24)", "HIGH": "rgba(249,115,22,.22)", "WARN": "rgba(234,179,8,.20)",
         "INFO": "rgba(100,116,139,.18)"}
GRAPH_PALETTE = {
    "attacker": "#B91C1C", "internal": "#B45309", "host": "#1D4ED8", "shell": "#7C3AED",
    "account": "#0F766E", "privileged": "#BE185D", "sev": SEV_COLOR,
    "border": "#334155" if MODE == "dark" else "#CBD5E1",
    "text": "#94A3B8" if MODE == "dark" else "#475569",
}


def render_kill_chain(dets: list) -> None:
    """MITRE ATT&CK strip: each tactic lights up in the colour of its worst alert."""
    chain = attack_map.kill_chain(dets)
    reached = [t for t in chain if t["count"]]
    html_block('<div class="section">MITRE ATT&amp;CK kill chain</div>'
               f'<div class="hint">The attack reached <b>{len(reached)} of {len(chain)}</b> tactics'
               + (": " + " &rarr; ".join(esc(t["name"]) for t in reached) if reached else "")
               + '. Hover a stage to see the alerts behind it.</div>')
    cells = []
    for t in chain:
        if t["count"]:
            tip = esc("; ".join(t["titles"]))
            cells.append(
                f'<div class="t lit" style="background:{KC_BG[t["severity"]]};--c:{SEV_COLOR[t["severity"]]}" '
                f'title="{tip}"><div class="id">{t["id"]}</div><div class="n">{esc(t["name"])}</div>'
                f'<div class="c">{t["count"]} alert{"s" if t["count"] != 1 else ""} &middot; '
                f'{esc(", ".join(t["techniques"]))}</div></div>')
        else:
            cells.append(f'<div class="t" title="{esc(t["meaning"])}"><div class="id">{t["id"]}</div>'
                         f'<div class="n">{esc(t["name"])}</div><div class="c">not observed</div></div>')
    html_block('<div class="kc">' + "".join(cells) + '</div>')


def render_attack_graph(dets: list) -> None:
    """Who attacked what, what they got, and where they went next."""
    html_block('<div class="section" style="margin-top:14px">Attack graph</div>'
               '<div class="hint">Built from the alerts in view. Edges are coloured by severity; '
               'scroll to zoom, drag to pan.</div>')
    dot = attack_map.attack_graph_dot(conn, dets, GRAPH_PALETTE)
    if not dot:
        html_block('<div class="note">No attacker activity in the current view.</div>')
        return
    with st.container(border=True):
        st.graphviz_chart(dot, width="content")        # natural size: readable, not blown up
        legend = [("Attacker IP", "attacker"), ("Internal IP (pivot)", "internal"), ("Host", "host"),
                  ("Web shell", "shell"), ("Account", "account"), ("Privileged account", "privileged")]
        html_block('<div class="chips" style="justify-content:center">' + "".join(
            f'<span class="chip"><span style="color:{GRAPH_PALETTE[k]}">&#9632;</span> {label}</span>'
            for label, k in legend) + '</div>')


if NAV == "overview":
    if not filtered:
        html_block('<div class="note">No events match the current filters.</div>')
    else:
        render_kill_chain(detections)
        render_attack_graph(detections)
        st.write("")
        left, right = st.columns([2.1, 1], gap="large")
        df_f = pd.DataFrame(filtered)
        with left:
            # Finer buckets when zoomed in: 1 min under 1 hour, 5 min under 6 hours, else 10 min.
            span_h = (f.f_time[1] - f.f_time[0]).total_seconds() / 3600
            bucket = 1 if span_h <= 1 else 5 if span_h <= 6 else 10
            html_block(f'<div class="section">Activity over time ({bucket}-minute buckets, UTC)</div>'
                       '<div class="hint">Drag across the chart to zoom the time window. '
                       'Click a legend entry to highlight a severity.</div>')
            df_f["bucket"] = (pd.to_datetime(df_f["timestamp_utc"]).dt.floor(f"{bucket}min")
                              .dt.strftime("%Y-%m-%dT%H:%M:%SZ"))       # explicit UTC for the chart
            counts = df_f.groupby(["bucket", "severity"]).size().reset_index(name="events")
            brush = alt.selection_interval(name="brush", encodings=["x"])
            legend_pick = alt.selection_point(name="sev_pick", fields=["severity"], bind="legend")
            chart = (alt.Chart(counts).mark_bar(size=7, cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
                     .encode(x=alt.X("bucket:T", title=None, scale=alt.Scale(type="utc"),
                                     axis=alt.Axis(format="%d %b %H:%M", labelAngle=0)),
                             y=alt.Y("sum(events):Q", title="Events"),
                             color=alt.Color("severity:N", title=None,
                                             scale=alt.Scale(domain=SEV_ORDER,
                                                             range=[SEV_COLOR[s] for s in SEV_ORDER]),
                                             legend=alt.Legend(orient="top", direction="horizontal")),
                             opacity=alt.condition(legend_pick, alt.value(1), alt.value(0.15)),
                             tooltip=[alt.Tooltip("bucket:T", title="From (UTC)", format="%Y-%m-%d %H:%M"),
                                      "severity:N", alt.Tooltip("sum(events):Q", title="Events")])
                     .add_params(brush, legend_pick)
                     .properties(height=260))
            st.altair_chart(chart, width="stretch", key="activity_chart",
                            on_select=on_brush, selection_mode=["brush"])

            html_block('<div class="section" style="margin-top:6px">Attack chain - detections in UTC order</div>'
                       '<div class="hint">Investigate focuses every tab on that detection\'s IP and time.</div>')
            if not detections:
                html_block('<div class="note">No detections in the current view.</div>')
            for i, d in enumerate(detections):
                with st.container(border=True):
                    c1, c2 = st.columns([4.4, 1.6], vertical_alignment="center")
                    ids =", ".join(f"#{x}" for x in d["event_ids"][:6]) + (" ..." if len(d["event_ids"]) > 6 else "")
                    who = " &middot; ".join(x for x in (f"IP {esc(d['source_ip'])}" if d["source_ip"] else "",
                                                        f"user {esc(d['username'])}" if d["username"] else "") if x)
                    c1.markdown(
                        f'<div class="step" style="--dot:{SEV_COLOR[d["severity"]]}"><div class="row">'
                        f'<span class="when">{short_time(d["first_seen"])}</span>{badge(d["severity"])}'
                        f'<span class="mitre">{esc(d["mitre"])}</span></div>'
                        f'<div class="what">{esc(d["title"])}</div>'
                        f'<div class="detail">{esc(d["description"])}</div>'
                        f'<div class="meta">{who + " &middot; " if who else ""}events {ids}</div></div>',
                        unsafe_allow_html=True)
                    focus = {**DEFAULTS, "f_time": window_around(d["first_seen"], d["last_seen"])}
                    if d["source_ip"]:
                        focus["f_ip"] = d["source_ip"]
                    c2.button("Investigate", icon=":material/search:", key=f"inv_{d['id']}",
                              width="stretch", on_click=set_filters, kwargs=focus)

        with right:
            html_block('<div class="section">Severity breakdown</div>'
                       '<div class="hint">Click a severity to filter.</div>')
            total = max(len(filtered), 1)
            for s in SEV_ORDER:
                c1, c2 = st.columns([1.1, 3], vertical_alignment="center")
                c1.button(s, key=f"sev_{s}", width="stretch", on_click=set_filters,
                          kwargs={"f_sev": [s]}, type="tertiary")
                c2.markdown(f'<div class="sevrow" style="grid-template-columns:1fr 40px;margin:0">'
                            f'<div class="bar"><div style="width:{100 * sev_counts[s] / total:.1f}%;'
                            f'background:{SEV_COLOR[s]}"></div></div>'
                            f'<span style="text-align:right">{sev_counts[s]}</span></div>',
                            unsafe_allow_html=True)

            html_block('<div class="section" style="margin-top:18px">Top source IPs</div>'
                       '<div class="hint">Click a bar to filter by that IP.</div>')
            ip_df = df_f[df_f["source_ip"].notna()].copy()
            if not ip_df.empty:
                ip_df["flagged"] = ip_df["id"].isin(flagged_ids).map({True: "Flagged", False: "Other"})
                top_ips = ip_df.groupby("source_ip").size().sort_values(ascending=False).head(6).index
                ip_counts = (ip_df[ip_df["source_ip"].isin(top_ips)]
                             .groupby(["source_ip", "flagged"]).size().reset_index(name="events")
                             .rename(columns={"source_ip": "IP"}))
                ip_pick = alt.selection_point(name="ip_pick", fields=["IP"])
                ip_chart = (alt.Chart(ip_counts).mark_bar(cornerRadiusEnd=2)
                            .encode(y=alt.Y("IP:N", sort="-x", title=None,
                                            axis=alt.Axis(labelOverlap=False, labelLimit=0)),
                                    x=alt.X("sum(events):Q", title="Events"),
                                    color=alt.Color("flagged:N", title=None,
                                                    scale=alt.Scale(domain=["Flagged", "Other"],
                                                                    range=["#F97316", "#475569"]),
                                                    legend=alt.Legend(orient="top")),
                                    tooltip=["IP:N", "flagged:N", alt.Tooltip("sum(events):Q", title="Events")])
                            .add_params(ip_pick)
                            .properties(height=max(130, 34 * len(top_ips) + 60)))
                st.altair_chart(ip_chart, width="stretch", key="ip_chart",
                                on_select=on_ip_click, selection_mode=["ip_pick"])

            html_block('<div class="section" style="margin-top:12px">Sources</div>')
            notes = database.get_source_notes(conn)
            per_source = pd.Series([e["source_file"] for e in filtered]).value_counts()
            for src in database.source_summary(conn):
                skew = next((n for n in notes.get(src["source_file"], []) if "skew" in n), "")
                c1, c2 = st.columns([5, 1], vertical_alignment="center")
                c1.markdown(
                    f'<div class="src"><div class="name">{esc(src["source_file"])}</div>'
                    f'<div class="info">{esc(src["log_format"])} &middot; '
                    f'{per_source.get(src["source_file"], 0)} of {src["events"]} events &middot; '
                    f'{src["gaps"]} gaps{" &middot; " + esc(skew) if skew else ""}</div></div>',
                    unsafe_allow_html=True)
                c2.button("Filter", key=f"src_{src['source_file']}", type="tertiary",
                          help="Show only this source", on_click=set_filters,
                          kwargs={"f_source": src["source_file"]})

# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
if NAV == "timeline":
    c1, c2 = st.columns([3, 1], vertical_alignment="center")
    c1.markdown(f"**{len(filtered)}** of {stats['events']} events &middot; sorted by UTC time &middot; "
                "tinted rows belong to a detection &middot; **click a row** for details and pivots")
    if filtered:
        c2.download_button("Export view (CSV)", pd.DataFrame(filtered).to_csv(index=False).encode(),
                           file_name="timeline_filtered.csv", icon=":material/download:", width="stretch")
    open_event_once(show_events(filtered, "timeline"))

# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------
if NAV == "detections":
    html_block('<div class="note">Rule-based detections (no AI), labelled with MITRE ATT&amp;CK techniques. '
               '<b>Click a row</b> to see its events and the original log lines.</div>')
    if not detections:
        st.write("No detections in the current view.")
    else:
        det_df = pd.DataFrame([{
            "#": i, "First seen (UTC)": d["first_seen"], "Severity": d["severity"],
            "MITRE": d["mitre"], "Detection": d["title"], "Source IP": d["source_ip"] or "",
            "User": d["username"] or "", "Events": len(d["event_ids"]), "Details": d["description"],
        } for i, d in enumerate(detections, 1)])
        det_event = st.dataframe(
            det_df.style.map(lambda v: f"color:{SEV_FG.get(v, '#64748B')};font-weight:600",
                             subset=["Severity"]),
            hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
            key=f"det_table_{hash(tuple(d['id'] for d in detections))}",
            column_config={"Details": st.column_config.TextColumn(width="large"),
                           "#": st.column_config.NumberColumn(width="small")})
        if det_event.selection.rows:
            d = detections[det_event.selection.rows[0]]
            with st.container(border=True):
                c1, c2 = st.columns([5, 1.3], vertical_alignment="center")
                c1.markdown(f'{badge(d["severity"])} <span class="mitre">{esc(d["mitre"])}</span> '
                            f'&nbsp;<b>{esc(d["title"])}</b> - {esc(d["description"])}',
                            unsafe_allow_html=True)
                focus = {**DEFAULTS, "f_time": window_around(d["first_seen"], d["last_seen"])}
                if d["source_ip"]:
                    focus["f_ip"] = d["source_ip"]
                c2.button("Investigate", icon=":material/search:", key="det_focus", width="stretch",
                          on_click=set_filters, kwargs=focus)
                related = database.get_events_by_ids(conn, d["event_ids"])
                show_events(related, "detection_events", selectable=False)
                st.caption("Original log lines (unchanged evidence):")
                st.code("\n".join(e["raw_log"] for e in related), language="text", wrap_lines=True)

# ---------------------------------------------------------------------------
# Evidence & report
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Validation: scorecard (highlighted) + why UTC matters
# ---------------------------------------------------------------------------
def run_validation() -> dict | None:
    """Score the tool in a separate process, so the throwaway case never mixes with this one."""
    try:
        proc = subprocess.run([sys.executable, "-m", "src.validate", "--json"], cwd=config.PROJECT_DIR,
                              capture_output=True, text=True, timeout=180)
        return json.loads(proc.stdout)
    except (subprocess.SubprocessError, ValueError, OSError):
        return None


if NAV == "validation":
    if "validation" not in st.session_state:
        with st.spinner("Re-running the three scenarios and the real-world logs in a throwaway case..."):
            st.session_state["validation"] = run_validation()
    v = st.session_state["validation"]

    if not v or not v.get("scenarios"):
        st.error("Validation could not run. Check that sample_logs/ is present, then try again.")
    else:
        all_ok = v["passed"] == v["total"]
        speedup = (v["manual_minutes"] * 60) / max(v["tool_seconds"], 0.001)
        hashes_ok = sum(r["hashes_ok"] for r in v["scenarios"])
        hashes = sum(r["hashes"] for r in v["scenarios"])
        html_block(
            '<div class="score-hero"><div class="top"><div>'
            '<div class="t">&#10003; Validation scorecard</div>'
            '<div class="hint" style="margin:2px 0 0">Re-runs the three synthetic scenarios from scratch in a '
            'throwaway case (your current case is untouched) and compares the result with what should be found.</div>'
            f'</div><span class="verdict{"" if all_ok else " fail"}">'
            f'{"ALL SCENARIOS PASS" if all_ok else "CHECK FAILURES BELOW"}</span></div>'
            '<div class="score-grid">'
            f'<div class="m"><div class="v">{v["passed"]}<small> / {v["total"]}</small></div><div class="l">Scenarios passed</div></div>'
            f'<div class="m"><div class="v">{v["alerts_found"]}<small> / {v["alerts_expected"]}</small></div><div class="l">Expected alerts found</div></div>'
            f'<div class="m"><div class="v">{v["false_positives"]}</div><div class="l">False positives</div></div>'
            f'<div class="m"><div class="v">{hashes_ok}<small> / {hashes}</small></div><div class="l">Evidence hashes OK</div></div>'
            f'<div class="m"><div class="v">{v["tool_seconds"]:.2f}<small> s</small></div>'
            f'<div class="l">vs ~{v["manual_minutes"]} min manual</div></div>'
            '</div></div>')

        r1, r2 = st.columns([5, 1], vertical_alignment="center")
        r1.caption(f"Last run {v['ran_utc']} - also available as  python run.py validate")
        if r2.button("Re-run", icon=":material/replay:", width="stretch", key="rerun_validation"):
            with st.spinner("Re-running..."):
                st.session_state["validation"] = run_validation()
            st.rerun()

        # One card per scenario: expected alerts ticked off, plus gaps, hashes and time.
        cols = st.columns(len(v["scenarios"]), gap="medium")
        for col, r in zip(cols, v["scenarios"]):
            colour = "#10B981" if r["passed"] else "#EF4444"
            chips = "".join(f'<span class="rule {"miss" if rule in r["missing"] else "ok"}">'
                            f'{"&#10007;" if rule in r["missing"] else "&#10003;"} '
                            f'{esc(v["rule_names"].get(rule, rule))}</span>' for rule in r["expected"])
            chips += "".join(f'<span class="rule extra">+ {esc(v["rule_names"].get(rule, rule))}</span>'
                             for rule in r["unexpected"])
            col.markdown(
                f'<div class="scard" style="--c:{colour}"><div class="h"><span>{esc(r["title"])}</span>'
                f'<span class="p">{"PASS" if r["passed"] else "FAIL"}</span></div>'
                f'<div style="margin-top:8px">{chips}</div>'
                f'<div class="facts">Alerts {len(r["expected"]) - len(r["missing"])}/{len(r["expected"])} '
                f'&middot; false positives {len(r["unexpected"])}<br>'
                f'Events {r["events"]} &middot; gaps logged {r["gaps"]}/{r["gaps_expected"]} '
                f'&middot; hashes {r["hashes_ok"]}/{r["hashes"]}<br>'
                f'Triage <b>{r["seconds"]:.2f} s</b> vs ~{r["manual_minutes"]} min by hand</div></div>',
                unsafe_allow_html=True)

        # Real-world logs: public data from real servers, every result cross-checked independently.
        rw = v.get("real_world") or {"datasets": []}
        if rw["datasets"]:
            html_block(
                '<div class="score-hero" style="margin-top:20px"><div class="top"><div>'
                '<div class="t">&#127760; Real-world test</div>'
                '<div class="hint" style="margin:2px 0 0">Public logs from <b>real servers</b> (not our synthetic data). '
                'Real logs have no answer key, so every result is cross-checked against an independent count '
                '(plain regex that does not use the tool\'s parser or rules).</div></div>'
                f'<span class="verdict{"" if rw["passed"] == rw["total"] else " fail"}">'
                f'{rw["passed"]} / {rw["total"]} DATASETS VERIFIED</span></div></div>')
            cols = st.columns(len(rw["datasets"]), gap="medium")
            for col, d in zip(cols, rw["datasets"]):
                if d.get("missing"):
                    col.warning(f"{d['title']}: `{d['file']}` not found. See real_logs/README.md to download it.")
                    continue
                checks = "".join(
                    f'<div style="margin:4px 0;font-size:.78rem">'
                    f'<span class="rule {"ok" if c["ok"] else "miss"}">{"&#10003;" if c["ok"] else "&#10007;"}</span> '
                    f'{esc(c["name"])} <span style="color:var(--faint)">({esc(c["actual"])})</span></div>'
                    for c in d["checks"])
                h = d["highlights"]
                if d["kind"] == "ssh":
                    story = (f'<b>{len(h["attackers"])} real brute-force attackers</b> found among '
                             f'{h["failed_total"]:,} failed logins. Worst: '
                             + ", ".join(f'{esc(a["ip"])} ({a["failures"]})' for a in h["attackers"][:3])
                             + '. Usernames tried: '
                             + ", ".join(esc(u) for u, _ in h["top_usernames"][:6]) + '.')
                else:
                    story = (f'{h["clients"]:,} real clients, {h["count_404"]:,} "not found" responses, '
                             f'<b>{h["alerts"]} false alarms</b>. A naive "10 x 404 = scan" rule would have flagged '
                             f'<b>{h["naive_alarms"]} innocent clients</b> here (update tools re-requesting '
                             + ", ".join(esc(p) for p, _ in h["top_404_paths"][:2])
                             + ') - so rule R3 now also needs 8+ different paths.')
                col.markdown(
                    f'<div class="scard" style="--c:{"#10B981" if d["passed"] else "#EF4444"}">'
                    f'<div class="h"><span>{esc(d["title"])}</span><span class="p">'
                    f'{"VERIFIED" if d["passed"] else "CHECK"}</span></div>'
                    f'<div class="facts" style="margin-top:6px">{d["lines"]:,} lines &middot; {d["events"]:,} events '
                    f'&middot; {d["gaps"]} gaps &middot; {d["alerts"]} alerts &middot; <b>{d["seconds"]:.2f} s</b><br>'
                    f'{short_time(d["first"])} &rarr; {short_time(d["last"])} UTC</div>'
                    f'<div class="facts">{story}</div>'
                    f'<div style="margin-top:8px">{checks}</div>'
                    f'<div class="facts" style="font-size:.7rem">Source: {esc(d["source"])}<br>'
                    f'{esc(d["assumption"])}</div></div>',
                    unsafe_allow_html=True)

        # Triage time race: the tool's bar is drawn to scale, so it is (almost) invisible.
        tool_pct = max(100 * v["tool_seconds"] / (v["manual_minutes"] * 60), 0.4)
        html_block(
            '<div class="section" style="margin-top:20px">Triage time vs manual baseline</div>'
            f'<div class="hint">Bars to scale. The tool is about <b>{speedup:,.0f}x faster</b> than the manual '
            'baseline (set per scenario in config.py - replace it with your own stopwatch time).</div>'
            '<div class="race">'
            f'<div class="row"><span>Analyst by hand</span><div class="track"><div class="fill" '
            f'style="width:100%;background:#64748B"></div></div><span>~{v["manual_minutes"]} min</span></div>'
            f'<div class="row"><span><b>ARIXA</b></span><div class="track"><div class="fill" '
            f'style="width:{tool_pct:.2f}%;background:#10B981"></div></div><span><b>{v["tool_seconds"]:.2f} s</b></span></div>'
            '</div>')

    # Proof 2: the same events read three ways.
    cmp = validate.clock_comparison()
    html_block('<div class="section" style="margin-top:22px">Why UTC + clock-skew correction matters '
               '(scenario 3)</div>'
               '<div class="hint">The web server logs India time with an offset; the database server logs New York '
               'time with no offset and its clock runs 3 minutes slow. Same events, read three ways:</div>')
    src_line = " &middot; ".join(
        f'<b>{esc(s["host"])}</b>: {esc(s["zone"])}'
        + (f', clock fix {s["skew"]:+d} s' if s["skew"] else "") for s in cmp["sources"])
    html_block(f'<div class="note">{src_line}</div>')

    titles = {"local": ("1 &middot; Raw local time", "Sorted by the time printed in each file"),
              "utc_raw": ("2 &middot; UTC, no clock fix", "Time zones converted, skew ignored"),
              "utc_fixed": ("3 &middot; UTC + clock fix", "What this tool does")}
    columns = []
    for key in ("local", "utc_raw", "utc_fixed"):
        view = cmp["views"][key]
        rows = "".join(
            f'<div class="ev{" attack" if e["role"] == "attack" else ""}{" shell" if e["kind"] == "webshell" else ""}">'
            f'<span class="tm">{e["time"]}</span><span class="hs">{esc(e["host"])}</span>'
            f'<span>{esc(e["what"])}</span></div>' for e in view["order"])
        ok = view["verdict"]["detected"]
        columns.append(
            f'<div class="cmpcol"><div class="h">{titles[key][0]}</div><div class="s">{titles[key][1]}</div>'
            f'{rows}<div class="vd {"ok" if ok else "bad"}">{"&#10003; Pivot DETECTED" if ok else "&#10007; Pivot MISSED"}'
            f' - {esc(view["verdict"]["text"].split(" - ")[0])}</div></div>')
    html_block('<div class="cmp">' + "".join(columns) + '</div>')
    st.caption("Purple = web-shell commands on the web server; orange = the attacker's login and commands on the "
               "database server. Only view 3 puts the login after the web shell, so only view 3 reveals the pivot.")


if NAV == "evidence":
    a1, a2, _ = st.columns([1, 1, 2])
    if a1.button("Verify integrity", icon=":material/verified_user:", type="primary", width="stretch"):
        st.session_state["verify"] = evidence.verify()          # logged in the chain of custody
        st.toast("Integrity check complete")
    if a2.button("Export report", icon=":material/description:", width="stretch"):
        st.session_state["report"] = report.export(conn)
        st.toast("Report exported")

    if "verify" in st.session_state:
        res = st.session_state["verify"]
        if res and all(r["status"] == "OK" for r in res):
            st.success(f"All {len(res)} evidence files match their recorded SHA-256 hashes.",
                       icon=":material/check_circle:")
        else:
            st.error("Integrity failure: at least one evidence file no longer matches its hash.",
                     icon=":material/error:")
    if "report" in st.session_state:
        out = st.session_state["report"]
        r1, r2, _ = st.columns([1, 1, 2])
        r1.download_button("Download report (.md)", out["markdown"].read_bytes(),
                           file_name="incident_report.md", icon=":material/download:", width="stretch")
        if out["pdf"]:
            r2.download_button("Download report (.pdf)", out["pdf"].read_bytes(),
                               file_name="incident_report.pdf", icon=":material/picture_as_pdf:",
                               width="stretch")

    html_block('<div class="section" style="margin-top:12px">Evidence manifest</div>')
    status = {c["evidence_file"]: c["status"] for c in checks}
    manifest = evidence.load_manifest()
    if manifest:
        mdf = pd.DataFrame([{
            "Status": status.get(m["evidence_file"], "?"), "Source": m["source_label"],
            "SHA-256": m["sha256"], "Size (bytes)": m["size_bytes"],
            "Collected (UTC)": m["ingested_utc"], "Evidence copy": m["evidence_file"],
        } for m in manifest])
        st.dataframe(mdf.style.map(lambda v: f"color:{OK_FG};font-weight:600" if v == "OK"
                                   else f"color:{BAD_FG};font-weight:600", subset=["Status"]),
                     hide_index=True, width="stretch")

    html_block('<div class="section" style="margin-top:12px">Chain of custody (newest first)</div>')
    custody = []
    for line in reversed(evidence.read_custody_log()[-300:]):
        parts = line.split(" | ", 2)
        if len(parts) == 3:
            custody.append({"Time (UTC)": parts[0], "Action": parts[1], "Details": parts[2]})
    if custody:
        actions = sorted({c["Action"] for c in custody})
        show = st.pills("Action type", actions, selection_mode="multi", key="custody_filter")
        rows = [c for c in custody if not show or c["Action"] in show]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=320,
                     column_config={"Details": st.column_config.TextColumn(width="large")})

# ---------------------------------------------------------------------------
# Parsing gaps
# ---------------------------------------------------------------------------
if NAV == "gaps":
    gaps = database.get_gaps(conn)
    html_block(f'<div class="note">{len(gaps)} line(s) did not match a supported format. They are kept '
               'here and in <code>output/parsing_gaps.jsonl</code> instead of being silently dropped.</div>')
    if gaps:
        st.dataframe(pd.DataFrame(gaps)[["source_file", "line_number", "reason", "raw_line"]],
                     hide_index=True, width="stretch",
                     column_config={"source_file": "Source", "line_number": "Line",
                                    "reason": "Why it was not parsed",
                                    "raw_line": st.column_config.TextColumn("Raw line", width="large")})
    html_block('<div class="section" style="margin-top:12px">Time normalisation assumptions</div>')
    for src, items in database.get_source_notes(conn).items():
        html_block(f'<div class="src"><div class="name">{esc(src)}</div>'
                   + "".join(f'<div class="info">&bull; {esc(n)}</div>' for n in items) + '</div>')


# ---------------------------------------------------------------------------
# AI assistant (optional)
# ---------------------------------------------------------------------------
def apply_ai_filter(flt: dict):
    """Copy a validated AI filter into the sidebar filters."""
    values = {**DEFAULTS}
    if flt.get("ip") in ALL_IPS:
        values["f_ip"] = flt["ip"]
    if flt.get("user") in ALL_USERS:
        values["f_user"] = flt["user"]
    if flt.get("severity"):
        values["f_sev"] = [s for s in SEV_ORDER if s in flt["severity"]]
    if flt.get("text"):
        values["f_text"] = flt["text"]
    start = to_naive(flt["after_time"]).replace(second=0) if flt.get("after_time") else T_MIN
    end = to_naive(flt["before_time"]) if flt.get("before_time") else T_MAX
    values["f_time"] = (max(start, T_MIN), min(end, T_MAX))
    values["nav"] = "timeline"                  # jump to the filtered timeline
    set_filters(**values)


if NAV == "ai":
    html_block('<div class="ai-hero"><div class="t">&#10022; AI Copilot</div>'
               '<div class="d">Turns the flagged evidence into a plain-English incident story, answers '
               'questions about the timeline, and proposes parsers for lines the tool could not read. '
               'Every answer is checked against the database before it is shown.</div>'
               '<div class="ai-pills"><span class="ai-pill">IPs and users redacted before sending</span>'
               '<span class="ai-pill">Event IDs verified</span>'
               '<span class="ai-pill">Every call in the chain of custody</span>'
               '<span class="ai-pill">Optional - the tool works without it</span></div></div>')
    if not ai_on:
        html_block(f'<div class="note">{esc(ai_msg)}. Everything else works without AI. To enable it, '
                   'copy <code>.env.example</code> to <code>.env</code> and add a Gemini API key.</div>')
    else:
        html_block(f'<div class="ailabel">{esc(ai_msg)} &middot; {esc(report.AI_LABEL)}</div>')
        s1, s2, s3 = st.tabs([":material/auto_stories: Explain the incident",
                              ":material/forum: Ask in plain English",
                              ":material/build: Parsing-gap helper"])

        with s1:
            if st.button("Generate incident narrative", icon=":material/auto_awesome:", type="primary", key="ai_go_explain"):
                with st.spinner("Asking Gemini..."):
                    st.session_state["ai_explain"] = ai_helper.explain_incident(conn)
            out = st.session_state.get("ai_explain")
            if out:
                if out["source"] == "ai":
                    st.caption(f"Model: {out['model']} - every cited event ID was checked against the "
                               "database. Saved for the next report export.")
                else:
                    st.warning("AI answer unavailable or failed validation. Showing the rule-based summary.")
                with st.container(border=True):
                    st.markdown(out["text"])

        with s2:
            with st.form("ai_question", border=False):
                q1, q2 = st.columns([4, 1])
                question = q1.text_input("Question", label_visibility="collapsed",
                                         placeholder="e.g. what did 203.0.113.45 do after the first successful login?")
                asked = q2.form_submit_button("Ask", icon=":material/auto_awesome:", width="stretch", type="primary", key="ai_go_ask")
            if asked and question.strip():
                with st.spinner("Asking Gemini for a filter..."):
                    st.session_state["ai_search"] = ai_helper.natural_language_search(conn, question)
            out = st.session_state.get("ai_search")
            if out:
                st.caption(out["message"])
                if out["filter"]:
                    c1, c2 = st.columns([4, 1.3])
                    c1.caption("Filter proposed by the AI (the query itself was run by this tool):")
                    c1.json(out["filter"])
                    if out["ok"]:
                        c2.button("Apply as filters", icon=":material/filter_alt:", width="stretch",
                                  on_click=apply_ai_filter, args=(out["filter"],),
                                  help="Copy this filter into the sidebar so every tab follows it")
                if out["ok"]:
                    show_events(out["results"], "ai_results", selectable=False)

        with s3:
            if st.button("Suggest parsers for gap lines", icon=":material/auto_awesome:", type="primary", key="ai_go_gaps"):
                with st.spinner("Asking Gemini..."):
                    st.session_state["ai_gaps"] = ai_helper.suggest_gap_regex(conn)
            out = st.session_state.get("ai_gaps")
            if out is not None:
                if not out:
                    st.warning("No usable suggestions returned.")
                for s in out:
                    with st.expander(f"{s['source_file']}, line {s['line_number']} - {s['likely_format']}"):
                        st.code(s["raw_line"], language="text", wrap_lines=True)
                        st.code(s["regex"], language="regex", wrap_lines=True)
                        st.caption(f"Compiles: {'yes' if s['regex_compiles'] else 'no'}  |  "
                                   f"Matches this line: {'yes' if s['matches_sample'] else 'no'}  |  "
                                   f"{s['explanation']}  |  Suggestion only, not applied.")

html_block('<div class="footer"><span>ARIXA Forensic Timeline &middot; defensive, read-only log analysis '
           '&middot; NIST SP 800-86 aligned</span><span>Synthetic sample data &middot; not a forensic '
           'certification</span></div>')
conn.close()
