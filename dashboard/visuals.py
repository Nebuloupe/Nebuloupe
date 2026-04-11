import plotly.graph_objects as go


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
            font=dict(color="#475569", size=11, family="JetBrains Mono"),
        ),
    )
    return fig


def build_findings_rows_html(filtered_findings):
    """Render findings rows HTML for the dashboard table."""
    cloud_icons = {"aws": "🟠", "azure": "🔵", "gcp": "🟢"}
    rows_html = ""

    for finding in filtered_findings:
        cloud = finding.get("cloud_provider", "unknown")
        severity = finding.get("severity", "Unknown")
        status = finding.get("status", "FAIL")
        cloud_icon = cloud_icons.get(cloud, "⚪")
        description = finding.get("description", "")
        rows_html += f"""<tr>
  <td><span class="nb-pill {severity}">{severity}</span></td>
  <td><span class="nb-cloud-badge {cloud}">{cloud_icon} {cloud.upper()}</span></td>
  <td style="color:#94a3b8;font-weight:600;font-family:'JetBrains Mono',monospace;font-size:11px;">{finding.get('rule_id', 'N/A')}</td>
  <td style="color:#cbd5e1;font-size:12px;">{finding.get('check', 'N/A')}</td>
  <td style="color:#475569;font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{finding.get('resource_id', 'N/A')}</td>
  <td style="color:#334155;font-size:11px;">{finding.get('region','global')}</td>
  <td style="color:#475569;font-size:11px;">{finding.get('category','N/A')}</td>
  <td style="color:#334155;max-width:260px;font-size:11px;">{description[:80]}{'…' if len(description)>80 else ''}</td>
  <td><span class="nb-status-pill {status}">{status}</span></td>
</tr>"""

    return rows_html

