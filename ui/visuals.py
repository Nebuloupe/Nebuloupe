import plotly.graph_objects as go
import html


def build_severity_pie(total_findings, severity_counts, severity_order):
    """Create the donut chart used in the dashboard."""
    fig = go.Figure(
        data=[
            go.Pie(
                labels=severity_order,
                values=[severity_counts[s] for s in severity_order],
                hole=0.6,
                marker=dict(
                    colors=["#ef4444", "#f97316", "#eab308", "#22c55e"],
                    line=dict(color="#030712", width=3),
                ),
                textinfo="none",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.add_annotation(
        text=(
            f"<span style='font-size:30px;color:#f1f5f9;"
            "font-family:\"Space Grotesk\",sans-serif;font-weight:800;'>"
            f"{total_findings}</span>"
        ),
        x=0.5,
        y=0.5,
        showarrow=False,
    )
    fig.update_layout(
        height=220,
        margin=dict(l=0, r=0, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=0.82,
            font=dict(color="#cbd5e1", size=12, family="JetBrains Mono"),
        ),
    )
    return fig


def build_pass_fail_donut(passed, failed):
    """Create a donut chart for pass vs fail findings."""
    total = int(passed) + int(failed)

    if total == 0:
        labels = ["No Findings"]
        values = [1]
        colors = ["#334155"]
    else:
        labels = ["Fail Findings", "Pass Findings"]
        values = [int(failed), int(passed)]
        colors = ["#ff2d6f", "#12d984"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.74,
                marker=dict(
                    colors=colors,
                    line=dict(color="#030712", width=2),
                ),
                textinfo="none",
                hoverinfo="label+value+percent",
                sort=False,
                direction="clockwise",
            )
        ]
    )

    fig.add_annotation(
        text=(
            f"<span style='font-size:40px;color:#f1f5f9;"
            "font-family:\"Space Grotesk\",sans-serif;font-weight:800;'>"
            f"{total:,}</span>"
            "<br><span style='font-size:18px;color:#cbd5e1;font-family:Inter,sans-serif;'>"
            "Total Findings</span>"
        ),
        x=0.5,
        y=0.5,
        showarrow=False,
    )

    fig.update_layout(
        height=320,
        margin=dict(l=0, r=0, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
    )
    return fig


def build_severity_score_gauge(severity_score_total, total_findings):
    """Create a gauge chart for Severity Score."""
    max_score = max(100, int(total_findings) * 10)

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=float(severity_score_total),
            number={"font": {"size": 44, "color": "#f1f5f9", "family": "Space Grotesk"}},
            gauge={
                "axis": {"range": [0, max_score], "tickwidth": 0, "tickcolor": "rgba(0,0,0,0)"},
                "bar": {"color": "#f97316", "thickness": 0.34},
                "bgcolor": "#101826",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, max_score * 0.35], "color": "#12d984"},
                    {"range": [max_score * 0.35, max_score * 0.70], "color": "#facc15"},
                    {"range": [max_score * 0.70, max_score], "color": "#ff2d6f"},
                ],
            },
        )
    )

    fig.update_layout(
        height=320,
        margin=dict(l=8, r=8, t=8, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def build_findings_rows_html(filtered_findings):
        """Render findings rows and remediation modals HTML for the dashboard table."""
        cloud_icons = {"aws": "🟠", "azure": "🔵", "gcp": "🟢"}
        rows_html = ""
        modals_html = ""

        for idx, finding in enumerate(filtered_findings):
                cloud = finding.get("cloud_provider", "unknown")
                severity = finding.get("severity", "Unknown")
                status = finding.get("status", "FAIL")
                cloud_icon = cloud_icons.get(cloud, "⚪")
                description = finding.get("description", "")
                remediation = finding.get(
                        "remediation", "No remediation guidance provided for this finding."
                )
                modal_id = f"nb-rem-modal-{idx}"

                check = html.escape(str(finding.get("check", "N/A")))
                rule_id = html.escape(str(finding.get("rule_id", "N/A")))
                resource_id = html.escape(str(finding.get("resource_id", "N/A")))
                region = html.escape(str(finding.get("region", "global")))
                category = html.escape(str(finding.get("category", "N/A")))
                description = html.escape(str(description))
                remediation = html.escape(str(remediation))

                rows_html += f"""<tr>
    <td><span class="nb-pill {severity}">{severity}</span></td>
    <td><span class="nb-cloud-badge {cloud}">{cloud_icon} {cloud.upper()}</span></td>
        <td style="color:#dbe5f0;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:12px;">{rule_id}</td>
        <td style="color:#e5edf8;font-size:13px;font-weight:600;max-width:180px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;">{check}</td>
        <td style="color:#dbe5f0;font-size:12px;max-width:340px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;">{resource_id}</td>
        <td style="color:#cbd5e1;font-size:12px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;">{region}</td>
        <td style="color:#cbd5e1;font-size:12px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;">{category}</td>
        <td style="color:#dbe5f0;max-width:320px;font-size:12px;line-height:1.55;white-space:normal;overflow-wrap:anywhere;word-break:break-word;">{description}</td>
        <td><a class="nb-rem-btn" href="#{modal_id}">View</a></td>
    <td><span class="nb-status-pill {status}">{status}</span></td>
</tr>"""

                modals_html += f"""
<div id="{modal_id}" class="nb-rem-modal">
    <div class="nb-rem-modal-card">
        <a href="#" class="nb-rem-close" aria-label="Close remediation">&times;</a>
        <div class="nb-rem-title">Remediation</div>
        <div class="nb-rem-meta">{rule_id} • {check}</div>
        <div class="nb-rem-body">{remediation}</div>
    </div>
</div>
"""

        return rows_html, modals_html

