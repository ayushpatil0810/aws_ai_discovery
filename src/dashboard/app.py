import os
import sys

# Ensure repository root is on sys.path regardless of execution context
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json
import pandas as pd
import streamlit as st
from datetime import datetime

from src.config import (
    Settings,
    ScanMode,
    RiskLevel,
    AICategory,
    ApprovalStatus,
    ActivityStatus,
    setup_logging
)
from src.inventory.database import init_db, get_db
from src.inventory.repository import InventoryRepository
from src.inventory.schema import ApprovedAIResourceCreate
from src.discovery.engine import DiscoveryEngine
from src.discovery.registry import generate_iam_policy
from src.governance.shadow_ai import ShadowAIEngine
from src.governance.allowlist import register_approved_resource
from src.dashboard.components import CUSTOM_CSS, render_kpi_card, render_badge

logger = setup_logging()

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="AWS AI Discovery & Governance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject Modern CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_settings():
    s = Settings()
    init_db(s.database_url)
    return s


settings = get_settings()


# Sidebar Navigation
st.sidebar.markdown("""
<div style="padding: 10px 0 20px 0;">
    <h2 style="color: #6366f1; margin: 0; font-weight: 800; font-size: 20px;">🛡️ AWS AI DISCOVERY</h2>
    <p style="color: #94a3b8; margin: 0; font-size: 12px;">Cloud AI Inventory & Shadow AI Governance</p>
</div>
""", unsafe_allow_html=True)

nav_page = st.sidebar.radio(
    "Navigation",
    ["📊 Executive Overview", "📦 AI Inventory", "⚠️ Potential Shadow AI", "📜 Scan History", "⚙️ Configuration & Scan"],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.caption(f"**Storage Engine:** SQLite (`ai_discovery.db`)")
st.sidebar.caption(f"**Read-Only Security:** Strictly Enforced")


# Helper to fetch resources
def load_inventory_data():
    with get_db(settings.database_url) as session:
        repo = InventoryRepository(session)
        resources = repo.query_inventory()
        allowlist = [a.resource_key for a in repo.list_allowlist()]
        scans = repo.list_scan_runs(limit=10)
        return resources, allowlist, scans


resources, allowlist_keys, scan_history = load_inventory_data()


# ==========================================
# PAGE 1: EXECUTIVE OVERVIEW
# ==========================================
if nav_page == "📊 Executive Overview":
    st.markdown("""
    <div class="hero-banner">
        <h1 class="hero-title">🛡️ AWS Cloud AI Inventory & Governance POC</h1>
        <div class="hero-subtitle">Automated read-only discovery of managed AI services, custom models, GPU infrastructure, and external AI integrations.</div>
    </div>
    """, unsafe_allow_html=True)

    if not resources:
        st.warning("⚠️ No AI resources discovered yet. Head over to **Configuration & Scan** to run a discovery scan.")
    else:
        # Key Metrics
        total_count = len(resources)
        confirmed_ai = sum(1 for r in resources if r.ai_usage_status == "confirmed")
        suspected_infra = sum(1 for r in resources if r.ai_category == "potential_ai_infrastructure")
        unregistered_count = sum(1 for r in resources if r.approval_status != "approved")
        unknown_owner = sum(1 for r in resources if r.owner == "unknown")
        critical_risk = sum(1 for r in resources if r.risk_level == "critical")

        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(render_kpi_card("Total Discovered AI Assets", str(total_count), "Normalized Inventory", "#818cf8"), unsafe_allow_html=True)
        with c2:
            st.markdown(render_kpi_card("Confirmed AI Models/Services", str(confirmed_ai), f"{confirmed_ai}/{total_count} Verified", "#34d399"), unsafe_allow_html=True)
        with c3:
            st.markdown(render_kpi_card("Potential AI Infrastructure", str(suspected_infra), "GPU / ML Containers", "#fbbf24"), unsafe_allow_html=True)
        with c4:
            st.markdown(render_kpi_card("Unregistered Assets", str(unregistered_count), "Missing from Allowlist", "#f87171"), unsafe_allow_html=True)
        with c5:
            st.markdown(render_kpi_card("Unknown Ownership", str(unknown_owner), "Missing Owner Tag", "#fb923c"), unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Charts Section
        col_left, col_right = st.columns([1, 1])

        df = pd.DataFrame([{
            "Name": r.resource_name,
            "Service": r.service_name.upper(),
            "Region": r.region,
            "Category": r.ai_category,
            "Risk": r.risk_level.upper(),
            "Approval": r.approval_status.upper(),
            "Owner": r.owner
        } for r in resources])

        with col_left:
            st.subheader("Discovered AI Assets by AWS Service")
            service_counts = df["Service"].value_counts().reset_index()
            service_counts.columns = ["AWS Service", "Asset Count"]
            st.bar_chart(service_counts.set_index("AWS Service"), color="#6366f1")

        with col_right:
            st.subheader("Assets by Governance Risk Level")
            risk_counts = df["Risk"].value_counts().reset_index()
            risk_counts.columns = ["Risk Level", "Asset Count"]
            st.bar_chart(risk_counts.set_index("Risk Level"), color="#ef4444")

        # Regional & Category breakdown
        st.markdown("---")
        st.subheader("Regional Coverage & Architecture Classification")
        c_reg, c_cat = st.columns(2)
        with c_reg:
            reg_counts = df["Region"].value_counts().reset_index()
            reg_counts.columns = ["Region", "Count"]
            st.dataframe(reg_counts, use_container_width=True, hide_index=True)
        with c_cat:
            cat_counts = df["Category"].value_counts().reset_index()
            cat_counts.columns = ["AI Category", "Count"]
            st.dataframe(cat_counts, use_container_width=True, hide_index=True)


# ==========================================
# PAGE 2: AI INVENTORY
# ==========================================
elif nav_page == "📦 AI Inventory":
    st.title("📦 Discovered Cloud AI Inventory")
    st.caption("Complete, deduplicated ledger of all AI services, custom models, and integrations.")

    if not resources:
        st.info("Inventory is empty. Run a scan from Configuration & Scan.")
    else:
        # Search & Filter Controls
        with st.expander("🔍 Filter & Search Inventory", expanded=True):
            fc1, fc2, fc3, fc4 = st.columns(4)
            with fc1:
                services_list = ["All"] + sorted(list({r.service_name for r in resources}))
                sel_service = st.selectbox("Service", services_list)
            with fc2:
                regions_list = ["All"] + sorted(list({r.region for r in resources}))
                sel_region = st.selectbox("Region", regions_list)
            with fc3:
                cats_list = ["All"] + sorted(list({r.ai_category for r in resources}))
                sel_cat = st.selectbox("AI Category", cats_list)
            with fc4:
                risks_list = ["All"] + sorted(list({r.risk_level for r in resources}))
                sel_risk = st.selectbox("Risk Level", risks_list)

            search_query = st.text_input("Search (by Name, ID, ARN, or Model ID)", placeholder="e.g. claude, sagemaker, openai, g5")

        # Apply filtering in memory
        filtered = resources
        if sel_service != "All":
            filtered = [r for r in filtered if r.service_name == sel_service]
        if sel_region != "All":
            filtered = [r for r in filtered if r.region == sel_region]
        if sel_cat != "All":
            filtered = [r for r in filtered if r.ai_category == sel_cat]
        if sel_risk != "All":
            filtered = [r for r in filtered if r.risk_level == sel_risk]
        if search_query:
            q = search_query.lower()
            filtered = [
                r for r in filtered
                if q in r.resource_name.lower() or q in r.resource_id.lower() or q in (r.resource_arn or "").lower() or q in (r.model_id or "").lower()
            ]

        st.markdown(f"**Showing {len(filtered)} matching assets**")

        # Table Display
        display_data = []
        for r in filtered:
            display_data.append({
                "Key": r.resource_key,
                "Resource Name": r.resource_name,
                "Service": r.service_name,
                "Region": r.region,
                "Category": r.ai_category,
                "Usage": r.ai_usage_status,
                "Owner": r.owner,
                "Approval": r.approval_status.upper(),
                "Risk": r.risk_level.upper(),
                "Confidence": f"{r.confidence_score:.2f}",
                "Activity": r.activity_status
            })

        df_display = pd.DataFrame(display_data)
        st.dataframe(
            df_display.drop(columns=["Key"]),
            use_container_width=True,
            hide_index=True
        )

        # Drill-down Resource Inspector
        st.markdown("---")
        st.subheader("🔍 Deep Resource Inspector")
        resource_keys = [r.resource_key for r in filtered]
        selected_key = st.selectbox(
            "Select resource to inspect detailed evidence, tags, and limitations:",
            resource_keys,
            format_func=lambda k: next(r.resource_name for r in filtered if r.resource_key == k) + f" ({k})"
        )

        selected_res = next(r for r in filtered if r.resource_key == selected_key)

        st.markdown(f"""
        <div class="detail-card">
            <h3 style="margin-top:0;">{selected_res.resource_name}</h3>
            <p><strong>ARN:</strong> <code>{selected_res.resource_arn or 'N/A'}</code></p>
            <p><strong>Canonical Key:</strong> <code>{selected_res.resource_key}</code></p>
            <p><strong>Description:</strong> {selected_res.description or 'No description available'}</p>
        </div>
        """, unsafe_allow_html=True)

        d1, d2 = st.columns(2)
        with d1:
            st.markdown("#### 🏷️ Resource Tags & Ownership")
            st.write(f"**Owner:** `{selected_res.owner}` (Resolved via: `{selected_res.owner_source}`)")
            tags = selected_res.get_tags()
            if tags:
                st.json(tags)
            else:
                st.caption("No resource tags attached.")

            st.markdown("#### ⚙️ Configuration Summary")
            st.json(selected_res.get_configuration_summary())

        with d2:
            st.markdown("#### 🔎 Discovery Evidence Trail")
            ev_list = selected_res.get_evidence()
            if ev_list:
                for ev in ev_list:
                    st.info(f"**[{ev.get('evidence_source')}]** {ev.get('sanitized_summary')}\n*(Confidence: {ev.get('confidence')})*")
            else:
                st.caption("No direct evidence items.")

            st.markdown("#### ⚠️ Documented Coverage Limitations")
            lim_list = selected_res.get_limitations()
            if lim_list:
                for lim in lim_list:
                    st.warning(f"**[{lim.get('limitation_code')}]** {lim.get('message')}\n\n*Impact:* {lim.get('potential_impact')}")
            else:
                st.caption("No specific limitations recorded for this resource.")

        # Quick Allowlist Action
        if selected_res.approval_status != "approved":
            st.markdown("---")
            st.markdown("#### 🛡️ Governance Action: Register in Approved Inventory")
            with st.form(f"approve_form_{selected_res.id}"):
                app_owner = st.text_input("Designated Owner", value=selected_res.owner if selected_res.owner != "unknown" else "")
                app_ref = st.text_input("Approval Reference / JIRA Ticket", value="SEC-AI-REVIEW-2026")
                app_notes = st.text_area("Governance Review Notes", value="Reviewed and validated for enterprise compliance.")
                submit_app = st.form_submit_button("✅ Mark as Approved AI Resource")
                if submit_app:
                    register_approved_resource(
                        resource_key=selected_res.resource_key,
                        resource_name=selected_res.resource_name,
                        owner=app_owner or "governance-team",
                        approval_reference=app_ref,
                        notes=app_notes,
                        database_url=settings.database_url
                    )
                    st.success(f"Resource '{selected_res.resource_name}' is now registered in the approved inventory!")
                    st.rerun()


# ==========================================
# PAGE 3: POTENTIAL SHADOW AI
# ==========================================
elif nav_page == "⚠️ Potential Shadow AI":
    st.title("⚠️ Potential Shadow AI & Governance Findings")
    st.caption("Transparent, rules-based security analysis flagging unregistered, unowned, or external AI integrations.")

    if not resources:
        st.info("Run a discovery scan to evaluate Shadow AI findings.")
    else:
        engine = ShadowAIEngine()
        findings = engine.evaluate_inventory(resources, approved_keys=allowlist_keys)

        if not findings:
            st.success("🎉 No Shadow AI findings detected! All discovered assets are registered, owned, and compliant.")
        else:
            critical_f = [f for f in findings if f.severity == RiskLevel.CRITICAL]
            high_f = [f for f in findings if f.severity == RiskLevel.HIGH]
            med_f = [f for f in findings if f.severity == RiskLevel.MEDIUM]
            low_f = [f for f in findings if f.severity == RiskLevel.LOW]

            sf1, sf2, sf3, sf4 = st.columns(4)
            with sf1:
                st.markdown(render_kpi_card("Critical Findings", str(len(critical_f)), "External AI Exfiltration", "#ef4444"), unsafe_allow_html=True)
            with sf2:
                st.markdown(render_kpi_card("High Findings", str(len(high_f)), "Unregistered Models/Endpoints", "#fb923c"), unsafe_allow_html=True)
            with sf3:
                st.markdown(render_kpi_card("Medium Findings", str(len(med_f)), "Unowned or Suspected Hosting", "#facc15"), unsafe_allow_html=True)
            with sf4:
                st.markdown(render_kpi_card("Low Findings", str(len(low_f)), "Activity / Telemetry Gaps", "#60a5fa"), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            for f in findings:
                box_class = f"finding-box-{f.severity.value}"
                badge_type = f.severity.value
                
                st.markdown(f"""
                <div class="finding-box {box_class}">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <h4 style="margin:0; color:#f8fafc;">{f.title}</h4>
                        {render_badge(f.severity.value, badge_type)}
                    </div>
                    <p style="margin: 8px 0 4px 0; color:#cbd5e1; font-size:14px;"><strong>Rationale:</strong> {f.rationale}</p>
                    <p style="margin: 4px 0; color:#94a3b8; font-size:13px;"><strong>Evidence:</strong> {f.evidence_summary}</p>
                    <p style="margin: 4px 0 0 0; color:#a5b4fc; font-size:12px;"><strong>Resource:</strong> <code>{f.resource_key}</code> ({f.service_name} | {f.region})</p>
                </div>
                """, unsafe_allow_html=True)

                with st.expander(f"Recommended Actions for {f.resource_name}"):
                    for act in f.recommended_actions:
                        st.markdown(f"- {act}")


# ==========================================
# PAGE 4: SCAN HISTORY
# ==========================================
elif nav_page == "📜 Scan History":
    st.title("📜 Discovery Scan Execution History")
    st.caption("Audit log of historical scan runs, regional coverage, and API performance.")

    if not scan_history:
        st.info("No scan runs recorded yet.")
    else:
        history_table = []
        for s in scan_history:
            history_table.append({
                "Scan ID": s.scan_id,
                "Mode": s.mode.upper(),
                "Account ID": s.account_id,
                "Status": s.scan_status.upper(),
                "Discovered": s.resources_discovered,
                "Updated": s.resources_updated,
                "API Calls (Attempted/Failed)": f"{s.api_calls_attempted} / {s.api_calls_failed}",
                "Start Time": s.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            })

        st.dataframe(pd.DataFrame(history_table), use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("🔍 Scan Execution Details")
        selected_scan_id = st.selectbox("Select a scan run to inspect errors, warnings, and configuration:", [s.scan_id for s in scan_history])
        selected_run = next(s for s in scan_history if s.scan_id == selected_scan_id)

        sc1, sc2 = st.columns(2)
        with sc1:
            st.markdown("#### Scanned Regions")
            st.write(selected_run.get_scanned_regions())
            st.markdown("#### Configuration Summary")
            st.json(selected_run.configuration_summary_json)

        with sc2:
            st.markdown("#### Errors & Exceptions")
            errors = selected_run.get_errors()
            if errors:
                st.error(f"{len(errors)} errors recorded during this run:")
                st.json(errors)
            else:
                st.success("No errors recorded during this scan.")

            st.markdown("#### Warnings & Gaps")
            warnings = selected_run.get_warnings()
            if warnings:
                st.warning(f"{len(warnings)} warnings recorded:")
                st.json(warnings)
            else:
                st.info("No warnings recorded.")


# ==========================================
# PAGE 5: CONFIGURATION & SCAN TRIGGER
# ==========================================
elif nav_page == "⚙️ Configuration & Scan":
    st.title("⚙️ Discovery Configuration & Execution")
    st.caption("Configure scan parameters and launch read-only discovery runs.")

    st.markdown("""
    <div style="background: rgba(30, 41, 59, 0.5); padding: 16px; border-radius: 10px; margin-bottom: 20px;">
        <h4 style="margin: 0; color: #38bdf8;">🔒 Read-Only Safety Guarantee</h4>
        <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 13px;">
            This tool performs strictly read-only Describe/List/Get operations. It never invokes model inference, 
            never incurs AI token charges, never modifies cloud resources, and never reads customer data or secrets.
        </p>
    </div>
    """, unsafe_allow_html=True)

    with st.form("scan_trigger_form"):
        st.subheader("Launch New Discovery Scan")
        
        mode_choice = st.radio(
            "Scan Mode:",
            ["Mock Mode (Offline synthetic dataset - No AWS credentials required)",
             "Real AWS Account Scan (Live Boto3 calls against authorized AWS account)"],
            index=0
        )
        is_mock_selected = "Mock" in mode_choice

        col_cfg1, col_cfg2 = st.columns(2)
        with col_cfg1:
            target_regs_input = st.text_input(
                "Target Regions (comma-separated):",
                value="us-east-1,us-west-2,ap-south-1",
                help="Leave empty to auto-detect enabled regions via ec2:DescribeRegions."
            )
            profile_input = st.text_input(
                "AWS Profile Name (Optional):",
                value=settings.aws_profile or "default",
                disabled=is_mock_selected,
                help="Named profile from ~/.aws/credentials"
            )

        with col_cfg2:
            st.markdown("**Enabled Discovery Modules:**")
            m_bedrock = st.checkbox("Amazon Bedrock", value=True)
            m_sagemaker = st.checkbox("Amazon SageMaker", value=True)
            m_managed_ai = st.checkbox("Managed AI Suite (Comprehend, Rekognition, etc.)", value=True)
            m_infra = st.checkbox("Infrastructure (EC2 GPU, ECS, Lambda)", value=True)
            m_integ = st.checkbox("Integrations (Lambda Env Keys, Step Functions)", value=True)
            m_re = st.checkbox("Resource Explorer 2 Cross-Index", value=True)
            m_activity = st.checkbox("CloudTrail Activity Telemetry", value=True)

        launch_btn = st.form_submit_button("🚀 Start AI Discovery Scan", type="primary")

        if launch_btn:
            selected_mode = ScanMode.MOCK if is_mock_selected else ScanMode.AWS
            reg_list = [r.strip() for r in target_regs_input.split(",") if r.strip()] if target_regs_input else None

            # Update settings dynamically for this run
            scan_settings = Settings(
                discovery_mode=selected_mode,
                aws_profile=profile_input if not is_mock_selected else None,
                module_bedrock=m_bedrock,
                module_sagemaker=m_sagemaker,
                module_managed_ai=m_managed_ai,
                module_infrastructure=m_infra,
                module_integrations=m_integ,
                module_resource_explorer=m_re,
                module_activity=m_activity
            )

            with st.spinner(f"Executing {selected_mode.value.upper()} discovery scan across regions..."):
                engine = DiscoveryEngine(scan_settings)
                try:
                    result = engine.run_scan(
                        mode=selected_mode,
                        regions=reg_list,
                        profile=profile_input if not is_mock_selected else None
                    )
                    st.success(f"Scan [{result['scan_id']}] finished successfully with status: {result['status'].upper()}!")
                    st.write(f"**Discovered:** {result['discovered_count']} new | **Updated:** {result['updated_count']}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Scan failed: {e}")

    # IAM Policy Viewer
    st.markdown("---")
    st.subheader("📋 Generated Least-Privilege IAM Policy")
    st.caption("Use this read-only IAM policy to grant necessary discovery permissions to your AWS profile or role.")
    policy_doc = generate_iam_policy()
    st.json(policy_doc)
