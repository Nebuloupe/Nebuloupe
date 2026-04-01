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
                    colors=["#f85149", "#e3703b", "#e3b341", "#3fb950"],
                    line=dict(color="#080b10", width=4),
                ),
                textinfo="none",
                hoverinfo="label+value+percent",
            )
        ]
    )
    fig.add_annotation(
        text=(
            "<span style='font-size:32px; color:white; "
            "font-family:\"Syne\", sans-serif; font-weight:800;'>"
            f"{total_findings}</span>"
        ),
        x=0.5,
        y=0.5,
        showarrow=False,
    )
    fig.update_layout(
        height=200,
        margin=dict(l=0, r=0, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=0.8,
            font=dict(color="#8b949e", size=11, family="JetBrains Mono"),
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
  <td style="color:#c9d1d9;font-weight:500;">{finding.get('rule_id', 'N/A')}</td>
  <td class="resource">{finding.get('check', 'N/A')}</td>
  <td style="color:#58a6a6;font-size:11px;">{finding.get('resource_type', 'N/A')}</td>
  <td style="color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{finding.get('resource_id', 'N/A')}</td>
  <td style="color:#444c56;">{finding.get('region','global')}</td>
  <td style="color:#6e7681;max-width:300px;font-size:11px;">{description[:80]}{'…' if len(description)>80 else ''}</td>
  <td><span class="nb-status-pill {status}">{status}</span></td>
</tr>"""

    return rows_html

