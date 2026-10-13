"""Command-line interface for AWS AI Discovery Agent."""

import sys
import json
import csv
import io
from datetime import datetime
from typing import Optional
import click
from tabulate import tabulate

from src.config import Settings, ScanMode, RiskLevel, AICategory, setup_logging, utc_now
from src.inventory.database import init_db, get_db
from src.inventory.repository import InventoryRepository
from src.discovery.engine import DiscoveryEngine
from src.discovery.registry import write_iam_policy_file
from src.governance.shadow_ai import ShadowAIEngine
from src.governance.allowlist import register_approved_resource, list_approved_resources

logger = setup_logging()


@click.group()
def cli():
    """AWS AI Discovery Agent - Read-Only Cloud AI Inventory and Governance POC."""
    pass


@cli.command("init-db")
@click.option("--db-url", default=None, help="Database connection URL (defaults to DATABASE_URL)")
def init_database_cmd(db_url):
    """Initialize SQLite database tables and schema."""
    init_db(db_url)
    click.echo(click.style("Database initialized successfully.", fg="green"))


@cli.command("scan")
@click.option("--mode", type=click.Choice(["mock", "aws"], case_sensitive=False), default="mock", help="Scan mode: mock (offline demo) or aws (live AWS account)")
@click.option("--profile", default=None, help="AWS CLI profile name (AWS mode only)")
@click.option("--regions", default=None, help="Comma-separated target regions (e.g. us-east-1,us-west-2,ap-south-1)")
def scan_cmd(mode, profile, regions):
    """Execute AI discovery scan across target regions and services."""
    settings = Settings()
    init_db(settings.database_url)

    scan_mode = ScanMode.MOCK if mode.lower() == "mock" else ScanMode.AWS
    region_list = [r.strip() for r in regions.split(",") if r.strip()] if regions else None

    engine = DiscoveryEngine(settings)
    click.echo(click.style(f"Starting discovery scan in {scan_mode.value.upper()} mode...", fg="cyan", bold=True))

    try:
        result = engine.run_scan(mode=scan_mode, regions=region_list, profile=profile)
        
        status_color = "green" if result["status"] == "completed" else ("yellow" if result["status"] == "partial" else "red")
        click.echo(click.style(f"\nScan Run {result['scan_id']} Finished - Status: {result['status'].upper()}", fg=status_color, bold=True))
        
        summary_rows = [
            ["Scan ID", result["scan_id"]],
            ["Mode", result["mode"].upper()],
            ["Account ID", result["account_id"]],
            ["Scanned Regions", ", ".join(result["scanned_regions"])],
            ["Discovered (New)", result["discovered_count"]],
            ["Updated", result["updated_count"]],
            ["API Calls Attempted", result["api_calls_attempted"]],
            ["API Calls Failed", result["api_calls_failed"]],
        ]
        click.echo(tabulate(summary_rows, tablefmt="grid"))

        if result.get("errors"):
            click.echo(click.style(f"\nEncountered {len(result['errors'])} errors during scan:", fg="yellow"))
            for err in result["errors"][:5]:
                click.echo(f" - [{err.get('service', 'unknown')}] {err.get('error', err.get('message', ''))}")

    except Exception as e:
        click.echo(click.style(f"\nScan execution failed: {e}", fg="red", bold=True))
        sys.exit(1)


@cli.group("inventory")
def inventory_group():
    """Query, inspect, and export discovered AI inventory."""
    pass


@inventory_group.command("list")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format")
@click.option("--service", default=None, help="Filter by AWS service name (e.g. bedrock, sagemaker)")
@click.option("--region", default=None, help="Filter by AWS region")
@click.option("--category", default=None, help="Filter by AI category (managed_ai, custom_model_hosting, etc.)")
@click.option("--risk", default=None, help="Filter by risk level (critical, high, medium, low)")
@click.option("--owner", default=None, help="Filter by owner or 'unknown'")
@click.option("--search", default=None, help="Search term across name, ARN, ID, or description")
def inventory_list_cmd(fmt, service, region, category, risk, owner, search):
    """List discovered AI resources with composite filters."""
    settings = Settings()
    init_db(settings.database_url)

    with get_db(settings.database_url) as session:
        repo = InventoryRepository(session)
        resources = repo.query_inventory(
            service_name=service,
            region=region,
            ai_category=category,
            risk_level=risk,
            owner=owner,
            search_query=search
        )

        if not resources:
            click.echo(click.style("No AI resources found matching criteria. Run 'scan' first.", fg="yellow"))
            return

        if fmt == "table":
            headers = ["Name", "Service", "Region", "Category", "Usage", "Owner", "Approval", "Risk", "Confidence"]
            rows = []
            for r in resources:
                rows.append([
                    r.resource_name[:30],
                    r.service_name,
                    r.region,
                    r.ai_category,
                    r.ai_usage_status,
                    r.owner[:20],
                    r.approval_status,
                    r.risk_level.upper(),
                    f"{r.confidence_score:.2f}"
                ])
            click.echo(tabulate(rows, headers=headers, tablefmt="github"))
            click.echo(f"\nTotal Discovered Assets: {len(resources)}")

        elif fmt == "json":
            out = []
            for r in resources:
                out.append({
                    "resource_key": r.resource_key,
                    "name": r.resource_name,
                    "service": r.service_name,
                    "region": r.region,
                    "arn": r.resource_arn,
                    "category": r.ai_category,
                    "usage_status": r.ai_usage_status,
                    "owner": r.owner,
                    "approval_status": r.approval_status,
                    "risk_level": r.risk_level,
                    "confidence_score": r.confidence_score,
                    "activity_status": r.activity_status,
                    "tags": r.get_tags(),
                    "configuration_summary": r.get_configuration_summary()
                })
            click.echo(json.dumps(out, indent=2))

        elif fmt == "csv":
            writer = csv.writer(sys.stdout)
            writer.writerow(["Resource Key", "Name", "Service", "Region", "Category", "Usage", "Owner", "Approval", "Risk", "Confidence"])
            for r in resources:
                writer.writerow([r.resource_key, r.resource_name, r.service_name, r.region, r.ai_category, r.ai_usage_status, r.owner, r.approval_status, r.risk_level, r.confidence_score])


@inventory_group.command("export")
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv", help="Export format")
@click.option("--output", default=None, help="File path to save export (defaults to stdout or export_timestamp.ext)")
def inventory_export_cmd(fmt, output):
    """Export the complete AI resource inventory to CSV or JSON."""
    settings = Settings()
    init_db(settings.database_url)

    with get_db(settings.database_url) as session:
        repo = InventoryRepository(session)
        resources = repo.query_inventory()

        if not resources:
            click.echo(click.style("Inventory is empty. Run a scan first.", fg="yellow"))
            return

        ts = utc_now().strftime("%Y%m%d_%H%M%S")
        out_filename = output or f"ai_inventory_export_{ts}.{fmt}"

        if fmt == "csv":
            with open(out_filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "resource_key", "resource_name", "service_name", "region", "account_id",
                    "resource_arn", "ai_category", "ai_usage_status", "owner", "owner_source",
                    "approval_status", "risk_level", "confidence_score", "activity_status",
                    "detection_method", "first_discovered_at", "last_scanned_at"
                ])
                for r in resources:
                    writer.writerow([
                        r.resource_key, r.resource_name, r.service_name, r.region, r.account_id,
                        r.resource_arn or "", r.ai_category, r.ai_usage_status, r.owner, r.owner_source,
                        r.approval_status, r.risk_level, r.confidence_score, r.activity_status,
                        r.detection_method, str(r.first_discovered_at), str(r.last_scanned_at)
                    ])
            click.echo(click.style(f"Successfully exported {len(resources)} resources to {out_filename}", fg="green"))

        elif fmt == "json":
            payload = []
            for r in resources:
                payload.append({
                    "resource_key": r.resource_key,
                    "name": r.resource_name,
                    "service": r.service_name,
                    "region": r.region,
                    "account_id": r.account_id,
                    "arn": r.resource_arn,
                    "category": r.ai_category,
                    "usage_status": r.ai_usage_status,
                    "owner": r.owner,
                    "owner_source": r.owner_source,
                    "approval_status": r.approval_status,
                    "risk_level": r.risk_level,
                    "confidence_score": r.confidence_score,
                    "activity_status": r.activity_status,
                    "tags": r.get_tags(),
                    "configuration_summary": r.get_configuration_summary(),
                    "evidence": r.get_evidence(),
                    "limitations": r.get_limitations(),
                    "first_discovered_at": str(r.first_discovered_at),
                    "last_scanned_at": str(r.last_scanned_at)
                })
            with open(out_filename, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            click.echo(click.style(f"Successfully exported {len(resources)} resources to {out_filename}", fg="green"))


@cli.command("scan-history")
@click.option("--limit", default=10, help="Number of historical scan runs to display")
def scan_history_cmd(limit):
    """View historical discovery scan executions and outcomes."""
    settings = Settings()
    init_db(settings.database_url)

    with get_db(settings.database_url) as session:
        repo = InventoryRepository(session)
        runs = repo.list_scan_runs(limit=limit)

        if not runs:
            click.echo(click.style("No previous scan runs recorded.", fg="yellow"))
            return

        headers = ["Scan ID", "Mode", "Account", "Status", "Discovered", "Updated", "Errors", "Start Time"]
        table_rows = []
        for run in runs:
            table_rows.append([
                run.scan_id,
                run.mode.upper(),
                run.account_id,
                run.scan_status.upper(),
                run.resources_discovered,
                run.resources_updated,
                len(run.get_errors()),
                run.start_time.strftime("%Y-%m-%d %H:%M:%S")
            ])
        click.echo(tabulate(table_rows, headers=headers, tablefmt="grid"))


@cli.command("shadow-ai")
def shadow_ai_cmd():
    """Evaluate discovered inventory against security rules to identify Shadow AI findings."""
    settings = Settings()
    init_db(settings.database_url)

    with get_db(settings.database_url) as session:
        repo = InventoryRepository(session)
        resources = repo.query_inventory()
        allowlist = [a.resource_key for a in repo.list_allowlist()]

        engine = ShadowAIEngine()
        findings = engine.evaluate_inventory(resources, approved_keys=allowlist)

        if not findings:
            click.echo(click.style("No Shadow AI or governance findings detected.", fg="green"))
            return

        click.echo(click.style(f"\nDetected {len(findings)} Potential Shadow AI & Governance Findings:\n", fg="red", bold=True))
        
        headers = ["Severity", "Type", "Resource Name", "Service", "Region", "Rationale"]
        rows = []
        for f in findings:
            rows.append([
                f.severity.value.upper(),
                f.finding_type,
                f.resource_name[:25],
                f.service_name,
                f.region,
                f.rationale[:60] + "..."
            ])
        click.echo(tabulate(rows, headers=headers, tablefmt="grid"))


@cli.group("allowlist")
def allowlist_group():
    """Manage officially approved AI resource allowlist."""
    pass


@allowlist_group.command("add")
@click.option("--key", required=True, help="Canonical resource key or ARN")
@click.option("--name", required=True, help="Friendly resource name")
@click.option("--owner", required=True, help="Designated business/technical owner")
@click.option("--reference", default=None, help="Approval ticket / PR / reference")
@click.option("--notes", default=None, help="Governance review notes")
def allowlist_add_cmd(key, name, owner, reference, notes):
    """Register an approved AI resource in the allowlist."""
    reg = register_approved_resource(
        resource_key=key,
        resource_name=name,
        owner=owner,
        approval_reference=reference,
        notes=notes
    )
    click.echo(click.style(f"Resource '{name}' ({key}) registered as APPROVED.", fg="green"))


@allowlist_group.command("list")
def allowlist_list_cmd():
    """List all registered approved AI resources."""
    items = list_approved_resources()
    if not items:
        click.echo(click.style("Allowlist is currently empty.", fg="yellow"))
        return

    headers = ["Resource Name", "Resource Key", "Owner", "Reference", "Reviewed At"]
    rows = [[i.resource_name, i.resource_key, i.owner, i.approval_reference or "N/A", str(i.last_reviewed_at)[:19]] for i in items]
    click.echo(tabulate(rows, headers=headers, tablefmt="github"))


@cli.command("generate-policy")
@click.option("--output", default="aws_discovery_iam_policy.json", help="Destination file path")
def generate_policy_cmd(output):
    """Generate the least-privilege read-only IAM policy document."""
    write_iam_policy_file(output)
    click.echo(click.style(f"Least-privilege IAM policy written to {output}", fg="green"))


def main():
    cli()


if __name__ == "__main__":
    main()
