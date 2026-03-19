import typer
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from finapi_sentinel.parser import parse_openapi
from finapi_sentinel.rules import RULES

# Initialize Typer with help text
app = typer.Typer(
    help="FinAPI Sentinel: Security & Compliance Scanner for Fintech APIs",
    no_args_is_help=True
)
console = Console()

@app.callback()
def main():
    """
    FinAPI Sentinel helps security teams at Fintechs audit OpenAPI specs
    for PCI DSS, NDPA, and SOC2 compliance.
    """
    pass

@app.command(name="scan")
def scan(
    file: Path = typer.Argument(..., exists=True, help="Path to the OpenAPI YAML/JSON file"),
    json_output: bool = typer.Option(False, "--json", help="Output results in raw JSON format")
):
    """
    Scan an OpenAPI file for security vulnerabilities and compliance gaps.
    """
    try:
        spec = parse_openapi(file)
        findings = []
        
        # Execute all security rules defined in rules.py
        for rule in RULES:
            findings.extend(rule(spec))

        # Build the final report object
        report = {
            "scan_time": datetime.utcnow().isoformat(),
            "total_endpoints": len(spec.get("paths", {})),
            "total_findings": len(findings),
            "summary": {
                "critical": len([f for f in findings if f.risk == "CRITICAL"]),
                "high": len([f for f in findings if f.risk == "HIGH"]),
                "medium": len([f for f in findings if f.risk == "MEDIUM"]),
                "low": len([f for f in findings if f.risk == "LOW"]),
            },
            "findings": [f.model_dump() for f in findings]
        }

        if json_output:
            # Clean JSON output for CI/CD pipelines
            print(json.dumps(report, indent=2))
        else:
            # Beautifully formatted CLI output for humans
            console.print("\n[bold green] FinAPI Sentinel Scan Complete[/bold green]\n")
            
            if not findings:
                console.print("[bold blue]No issues found! Your API spec looks solid.[/bold blue]")
            else:
                for f in findings:
                    # Use .value to print the string instead of RiskLevel.CRITICAL
                    console.print(
                        f"[bold red]{f.risk.value}[/bold red] {f.method} {f.endpoint}\n"
                        f"  → [yellow]Issue:[/yellow] {f.issue}\n"
                        f"  → [cyan]Control:[/cyan] {f.control}\n"
                    )
                
                console.print(f"[bold]Total Findings:[/bold] {len(findings)}\n")

    except Exception as e:
        console.print(f"[bold red]ERROR:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()