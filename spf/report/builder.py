"""Stage D - unified report.

Rule findings (certain) and anomaly findings (scored) are kept in separate
sections. Related findings are grouped under the process tree, with memory
offsets and open connections.

build_report() returns a plain JSON-serialisable dict (what the CLI writes to
report.json). render_html() turns that dict into a standalone HTML page using
only the standard library, so no extra dependency is added to the project.
"""

from __future__ import annotations

import html
from pathlib import Path

from spf.models import AnomalyFinding, MemoryEvidence, RuleFinding
from spf.rules.checks import skipped_checks


def _socket_summary(proc, limit: int = 8) -> list[str]:
    """Compact 'proto laddr:lport -> raddr:rport state' lines for a process's
    network sockets. Only INET/INET6 sockets are shown (unix-domain and netlink
    sockets are local IPC noise), capped, with a listening socket preferred."""
    net = []
    for s in getattr(proc, "sockets", []) or []:
        low = {str(k).lower(): v for k, v in s.items()}
        def g(*names):
            for n in names:
                if n in low and low[n] not in (None, "", "-"):
                    return low[n]
            return None
        family = str(g("family") or "")
        if "INET" not in family.upper():   # keep only IPv4/IPv6 network sockets
            continue
        proto = g("proto", "protocol") or ""
        la, lp = g("source addr", "local addr"), g("source port", "local port")
        ra, rp = g("destination addr", "remote addr"), g("destination port", "remote port")
        state = str(g("state") or "")
        net.append((state, f"{proto} {la}:{lp} -> {ra}:{rp} {state}".strip()))
    # listening/bound sockets first (most forensically relevant), then cap
    net.sort(key=lambda t: (t[0] != "LISTEN",))
    return [line for _state, line in net[:limit]]


def _flagged_process_tree(ev: MemoryEvidence, rule_findings, anomaly_findings) -> list[dict]:
    """Group every finding under the process it concerns, with that process's
    memory offset, open connections and its chain of parents. Fulfils the
    proposal's 'findings grouped under process tree hierarchies, with memory
    offsets and open connections' (section III.D)."""
    procs = {p.pid: p for p in ev.tasks_list}
    findings_by_pid: dict[int, dict] = {}

    def slot(pid):
        return findings_by_pid.setdefault(pid, {"rules": [], "anomaly": None})

    for f in rule_findings:
        if f.pid is not None and f.pid != -1:
            slot(f.pid)["rules"].append({"rule": f.rule, "description": f.description, "evidence": f.evidence})
        else:
            # module / syscall findings have no owning process; attach to a synthetic kernel node
            slot(-1)["rules"].append({"rule": f.rule, "description": f.description, "evidence": f.evidence})
    for a in anomaly_findings:
        slot(a.pid)["anomaly"] = {
            "score": round(a.score, 4), "threshold": round(a.threshold, 4),
            "reason": a.reason, "novel_features": a.novel_features, "explanation": a.explanation,
        }

    def ancestry(pid):
        chain, seen = [], set()
        cur = procs.get(pid)
        while cur and cur.ppid in procs and cur.ppid not in seen:
            seen.add(cur.ppid)
            parent = procs[cur.ppid]
            chain.append({"pid": parent.pid, "comm": parent.comm})
            cur = parent
        return chain

    nodes = []
    for pid, data in findings_by_pid.items():
        if pid == -1:
            nodes.append({"pid": None, "comm": "<kernel>", "ppid": None,
                          "rule_findings": data["rules"], "anomaly": data["anomaly"]})
            continue
        p = procs.get(pid)
        nodes.append({
            "pid": pid,
            "comm": p.comm if p else None,
            "ppid": p.ppid if p else None,
            "parent_comm": procs[p.ppid].comm if p and p.ppid in procs else None,
            "task_offset": hex(p.task_offset) if p and p.task_offset else None,
            "exe_path": p.exe_path if p else None,
            "cmdline": p.cmdline if p else None,
            "connections": _socket_summary(p) if p else [],
            "ancestry": ancestry(pid),
            "rule_findings": data["rules"],
            "anomaly": data["anomaly"],
        })
    # rule findings first (certain), then by anomaly score; kernel node last
    nodes.sort(key=lambda n: (n["pid"] is None,
                              -len(n["rule_findings"]),
                              -((n["anomaly"] or {}).get("score") or 0)))
    return nodes


def build_report(
    ev: MemoryEvidence,
    rule_findings: list[RuleFinding],
    anomaly_findings: list[AnomalyFinding],
) -> dict:
    procs = {p.pid: p for p in ev.tasks_list}
    anomalies = sorted(anomaly_findings, key=lambda a: a.score, reverse=True)

    def proc_label(pid: int | None) -> str | None:
        p = procs.get(pid)
        return p.comm if p else None

    skipped = skipped_checks(ev)
    report = {
        "image": ev.image_path,
        "summary": {
            "processes_analysed": len(ev.tasks_list),
            "rule_findings": len(rule_findings),
            "anomalies": len(anomalies),
            "checks_skipped": len(skipped),
        },
        "checks_skipped": skipped,
        "flagged_processes": _flagged_process_tree(ev, rule_findings, anomaly_findings),
        "rule_findings": [
            {
                "rule": f.rule,
                "description": f.description,
                "pid": f.pid,
                "comm": proc_label(f.pid),
                "evidence": f.evidence,
            }
            for f in rule_findings
        ],
        "anomalies": [
            {
                "pid": a.pid,
                "comm": proc_label(a.pid),
                "ppid": procs[a.pid].ppid if a.pid in procs else None,
                "score": round(a.score, 4),
                "threshold": round(a.threshold, 4),
                "reason": a.reason,
                "novel_features": a.novel_features,
                "explanation": a.explanation,
                "features": a.features,
                "contributions": a.contributions,
            }
            for a in anomalies
        ],
    }
    return report


def render_html(report: dict, out_path: str | Path) -> Path:
    e = html.escape
    s = report["summary"]
    rows_rules = "".join(
        f'<div class="f certain"><span class="pill red">certain</span>'
        f'<span class="t">{e(f["rule"])}</span>'
        f'<div class="m">{e(f["description"])}</div>'
        f'<div class="m">Target: <code>'
        f'{("PID " + str(f["pid"]) + " ") if f.get("pid") not in (None, -1) else ""}'
        f'{e(str(f.get("comm") or ""))}</code></div></div>'
        for f in report["rule_findings"]
    ) or '<p class="empty">No definitive indicators found.</p>'

    rows_anom = "".join(
        f'<div class="f"><span class="pill">score {a["score"]:.3f}</span>'
        f'<span class="pill">cutoff {a["threshold"]:.3f}</span>'
        f'{"<span class=\"pill amber\">unseen on baseline</span>" if a.get("novel_features") else ""}'
        f'<span class="t">PID {a["pid"]} &middot; {e(str(a.get("comm") or ""))}</span>'
        f'<div class="m">{e(a.get("explanation") or "")}</div></div>'
        for a in report["anomalies"]
    ) or '<p class="empty">No processes exceeded the anomaly cutoff or showed behaviour unseen on the clean baseline.</p>'

    def render_node(n):
        chain = " &rarr; ".join(
            f'{e(str(a["comm"]))}({a["pid"]})' for a in reversed(n.get("ancestry") or [])
        )
        head = (f'PID {n["pid"]} &middot; ' if n["pid"] is not None else "") + e(str(n.get("comm") or ""))
        meta = []
        if n.get("task_offset"):
            meta.append(f'offset <code>{e(n["task_offset"])}</code>')
        if n.get("exe_path"):
            meta.append(f'exe <code>{e(str(n["exe_path"]))}</code>')
        if chain:
            meta.append(f'ancestry {chain}')
        conns = "".join(f'<div class="m">conn: <code>{e(c)}</code></div>' for c in (n.get("connections") or []))
        certain = " certain" if n.get("rule_findings") else ""
        finds = "".join(
            f'<div class="m"><span class="pill red">certain</span> <b>{e(rf["rule"])}</b> &mdash; {e(rf["description"])}</div>'
            for rf in n.get("rule_findings") or []
        )
        a = n.get("anomaly")
        if a:
            novel = '<span class="pill amber">unseen on baseline</span>' if a.get("novel_features") else ""
            finds += (f'<div class="m"><span class="pill">score {a["score"]:.3f}</span>'
                      f'<span class="pill">cutoff {a["threshold"]:.3f}</span>{novel} '
                      f'{e(a.get("explanation") or "")}</div>')
        meta_html = f'<div class="m">{" &middot; ".join(meta)}</div>' if meta else ""
        return (f'<div class="f{certain}"><span class="t">{head}</span>'
                f'{meta_html}{conns}{finds}</div>')

    rows_tree = "".join(render_node(n) for n in report.get("flagged_processes", [])) \
        or '<p class="empty">No process raised a finding.</p>'

    skipped = report.get("checks_skipped") or []
    warn_box = (
        '<div class="warn"><strong>Some checks did not run fully on this image.</strong> '
        'A clean result for these checks is not verified:<ul>'
        + "".join(f"<li>{e(n)}</li>" for n in skipped)
        + "</ul></div>"
    ) if skipped else ""

    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SPF Report - {e(report["image"])}</title><style>
 :root{{--navy:#12395c;--blue:#1f6fb2;--red:#b02a2a;--grey:#555;--line:#dde3ea;}}
 *{{box-sizing:border-box}} body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;color:#1a1a1a;background:#f6f8fa}}
 .wrap{{max-width:960px;margin:0 auto;padding:24px 16px}}
 h1{{color:var(--navy);margin:0 0 4px}} .sub{{color:var(--grey);margin:0 0 20px;font-size:14px}}
 .cards{{display:flex;gap:12px;margin:0 0 20px;flex-wrap:wrap}}
 .card{{flex:1;min-width:140px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px}}
 .card .n{{font-size:28px;font-weight:700}} .card.red .n{{color:var(--red)}} .card.blue .n{{color:var(--blue)}}
 h2{{color:var(--navy);border-bottom:2px solid var(--blue);padding-bottom:4px;margin-top:28px}}
 .f{{background:#fff;border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:8px;padding:12px 14px;margin:10px 0}}
 .f.certain{{border-left-color:var(--red)}}
 .f .t{{font-weight:700;color:var(--navy);margin-left:4px}} .f .m{{font-size:14px;color:#333;margin:4px 0}}
 .pill{{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;background:#eef2f6;color:var(--navy);margin-right:6px}}
 .pill.red{{background:#fde8e8;color:var(--red)}} .pill.amber{{background:#fff1d6;color:#8a5a00}} code{{background:#f0f3f6;padding:1px 4px;border-radius:4px}}
 .empty{{color:var(--grey);font-style:italic}}
 .warn{{background:#fff7e0;border:1px solid #e8c25a;border-radius:8px;padding:12px 14px;margin:0 0 20px;font-size:14px}}
 .warn ul{{margin:6px 0 0 18px;padding:0}}
</style></head><body><div class="wrap">
 <h1>SPF - Suspicious Process Finder</h1>
 <p class="sub">Image: <code>{e(report["image"])}</code> &nbsp;|&nbsp; {s["processes_analysed"]} processes analysed</p>
 <div class="cards">
  <div class="card red"><div class="n">{s["rule_findings"]}</div><div>Definitive (rule) findings</div></div>
  <div class="card blue"><div class="n">{s["anomalies"]}</div><div>Behavioural anomalies</div></div>
 </div>
 {warn_box}
 <h2>Flagged processes (grouped)</h2>
 <p class="sub">Every finding under the process it concerns, with memory offset, open connections and parent chain.</p>
 {rows_tree}
 <h2>Definitive indicators (rule stage)</h2>{rows_rules}
 <h2>Behavioural anomalies (Isolation Forest)</h2>{rows_anom}
</div></body></html>"""
    out_path = Path(out_path)
    out_path.write_text(page)
    return out_path
