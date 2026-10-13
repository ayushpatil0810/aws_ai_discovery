"""UI styling tokens, custom CSS, and badge components for the Streamlit dashboard."""

CUSTOM_CSS = """
<style>
/* Modern typography and theme styling */
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
}

code, pre {
    font-family: 'JetBrains+Mono', monospace !important;
}

/* Header gradient banner */
.hero-banner {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #311042 100%);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 16px;
    padding: 24px 32px;
    margin-bottom: 24px;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
}

.hero-title {
    color: #f8fafc;
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 12px;
}

.hero-subtitle {
    color: #94a3b8;
    font-size: 14px;
    font-weight: 400;
    margin-top: 6px;
}

/* KPI Metric Cards */
.kpi-card {
    background: rgba(30, 41, 59, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 14px;
    padding: 18px 20px;
    transition: all 0.2s ease-in-out;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
}

.kpi-card:hover {
    transform: translateY(-2px);
    border-color: rgba(99, 102, 241, 0.4);
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
}

.kpi-label {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
    color: #94a3b8;
}

.kpi-value {
    font-size: 30px;
    font-weight: 800;
    color: #f8fafc;
    margin-top: 4px;
    letter-spacing: -1px;
}

.kpi-delta {
    font-size: 12px;
    font-weight: 500;
    margin-top: 4px;
}

/* Badge styling */
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

.badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
.badge-high { background-color: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
.badge-medium { background-color: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
.badge-low { background-color: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }
.badge-info { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }

.badge-approved { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
.badge-unregistered { background-color: rgba(244, 63, 94, 0.2); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.4); }

.badge-active { background-color: rgba(14, 165, 233, 0.2); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.4); }
.badge-idle { background-color: rgba(148, 163, 184, 0.2); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.4); }

/* Finding Card */
.finding-box {
    background: rgba(30, 41, 59, 0.6);
    border-left: 4px solid #ef4444;
    border-radius: 8px 12px 12px 8px;
    padding: 16px 20px;
    margin-bottom: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    border-right: 1px solid rgba(255, 255, 255, 0.05);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.finding-box-critical { border-left-color: #ef4444; }
.finding-box-high { border-left-color: #f97316; }
.finding-box-medium { border-left-color: #eab308; }
.finding-box-low { border-left-color: #3b82f6; }

/* Detail metadata container */
.detail-card {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 20px;
    margin-top: 12px;
}
</style>
"""


def render_badge(text: str, badge_type: str = "info") -> str:
    """Render an HTML pill badge."""
    return f'<span class="badge badge-{badge_type}">{text}</span>'


def render_kpi_card(title: str, value: str, delta_text: str = "", delta_color: str = "#94a3b8") -> str:
    """Render a modern glassmorphic KPI metric card."""
    return f"""
    <div class="kpi-card">
        <div class="kpi-label">{title}</div>
        <div class="kpi-value">{value}</div>
        <div class="kpi-delta" style="color: {delta_color};">{delta_text}</div>
    </div>
    """
