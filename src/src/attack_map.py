"""
attack_map.py - turns detections into two pictures:

  kill_chain()       which MITRE ATT&CK tactics the attackers reached (the "kill chain strip")
  attack_graph_dot() who attacked which host, what they got, and where they went next,
                     as a Graphviz DOT string (Streamlit draws it with st.graphviz_chart)

Both only read existing detections; nothing new is detected here.
"""
import ipaddress
import re
from pathlib import PurePosixPath

from src import database, parsers

# The tactics shown in the strip, in ATT&CK order (id, name, one-line meaning).
TACTICS = [
    ("TA0043", "Reconnaissance", "Looking for a way in"),
    ("TA0001", "Initial Access", "Getting in"),
    ("TA0002", "Execution", "Running commands"),
    ("TA0003", "Persistence", "Staying in"),
    ("TA0004", "Privilege Escalation", "Becoming admin"),
    ("TA0006", "Credential Access", "Stealing passwords"),
    ("TA0008", "Lateral Movement", "Moving to other hosts"),
    ("TA0009", "Collection", "Gathering data"),
]

# Which tactic(s) each technique label used by detect.py belongs to.
TECHNIQUE_TACTICS = {
    "T1595": ["Reconnaissance"],
    "T1078": ["Initial Access"],
    "T1190": ["Initial Access"],
    "T1505.003": ["Persistence", "Execution"],      # a web shell keeps access AND runs commands
    "T1136.001": ["Persistence"],
    "T1098.004": ["Persistence"],
    "T1053.003": ["Persistence"],
    "T1548": ["Privilege Escalation"],
    "T1548.001": ["Privilege Escalation"],
    "T1110": ["Credential Access"],
    "T1003.008": ["Credential Access"],
    "T1021.004": ["Lateral Movement"],
    "T1005": ["Collection"],
}

SEVERITY_RANK = database.SEVERITY_RANK

# Short edge labels for the risky-command techniques (keeps the graph compact).
SHORT_LABELS = {"T1003.008": "read /etc/shadow", "T1136.001": "add user", "T1098.004": "add SSH key",
                "T1053.003": "edit cron", "T1548.001": "set SUID", "T1005": "dump DB"}


def kill_chain(detections: list) -> list[dict]:
    """One entry per tactic: how many detections, which techniques, worst severity, first time."""
    chain = []
    for tactic_id, name, meaning in TACTICS:
        hits = [d for d in detections if name in TECHNIQUE_TACTICS.get(d["mitre"], [])]
        chain.append({
            "id": tactic_id, "name": name, "meaning": meaning, "count": len(hits),
            "techniques": sorted({d["mitre"] for d in hits}),
            "titles": sorted({d["title"] for d in hits}),
            "severity": max((d["severity"] for d in hits), key=SEVERITY_RANK.get, default=None),
            "first_seen": min((d["first_seen"] for d in hits), default=None),
        })
    return chain


# ---------------------------------------------------------------------------
# Attack graph
# ---------------------------------------------------------------------------
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_internal(ip: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip) in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def _host(event: dict, details: dict) -> str:
    """Host name from the syslog header, or a short name for a web server log."""
    if details.get("host"):
        return details["host"]
    path = PurePosixPath(event["source_file"])
    name = path.parent.name if path.stem in ("access", "auth") else path.stem.replace("_access", "")
    return f"web server\n{name}"


def _q(text: str) -> str:
    """Quote a value for DOT."""
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


class _Graph:
    def __init__(self):
        self.nodes, self.edges = {}, {}

    def node(self, key, label, kind):
        self.nodes.setdefault(key, (label, kind))
        return key

    def edge(self, a, b, label, severity):
        labels, sev = self.edges.get((a, b), (set(), "INFO"))
        labels.add(label)
        self.edges[(a, b)] = (labels, max(sev, severity, key=SEVERITY_RANK.get))


def attack_graph_data(conn, detections: list) -> dict:
    """The attack graph as plain nodes and edges (used by the web showcase)."""
    g = _build(conn, detections)
    return {"nodes": [{"id": k, "label": label, "kind": kind} for k, (label, kind) in g.nodes.items()],
            "edges": [{"from": a, "to": b, "label": sorted(labels), "severity": sev}
                      for (a, b), (labels, sev) in g.edges.items()]}


def attack_graph_dot(conn, detections: list, palette: dict) -> str:
    """The attack graph as Graphviz DOT. palette: colours for the current light/dark theme."""
    g = _build(conn, detections)
    return _to_dot(g, palette)


def _build(conn, detections: list) -> "_Graph":
    """
    Build the graph from detections:
      attacker IP -> host           (brute force, scan, SQL injection, login)
      host -> web shell             (web shell on that server)
      web shell -> internal IP      (pivot)  -> next host  (lateral movement)
      host -> account -> root       (logged in as, then sudo)
    """
    g = _Graph()
    for d in detections:
        events = database.get_events_by_ids(conn, d["event_ids"])
        for e in events:
            e["details"] = parsers.details_from_raw(e["log_format"], e["raw_log"])
        sev, rule = d["severity"], d["rule"]

        def ip_node(ip):
            kind = "internal" if _is_internal(ip) else "attacker"
            return g.node(f"ip:{ip}", ip, kind)

        def host_node(e):
            h = _host(e, e["details"])
            return g.node(f"host:{h}", h, "host")

        def account_node(e, user=None):
            h = _host(e, e["details"])
            user = user or e["username"]
            kind = "privileged" if user in ("root", "postgres", "Administrator") else "account"
            return g.node(f"acct:{h}:{user}", user, kind)

        first = events[0] if events else None
        if not first:
            continue
        if rule == "R1-brute-force":
            g.edge(ip_node(d["source_ip"]), host_node(first), f"brute force x{len(events)}", sev)
        elif rule == "R2-successful-brute-force":
            g.edge(ip_node(d["source_ip"]), host_node(first), "SSH login", sev)
            g.edge(host_node(first), account_node(first), "valid account", sev)
        elif rule == "R3-web-scan":
            g.edge(ip_node(d["source_ip"]), host_node(first), f"scan {len(events)}x404", sev)
        elif rule in ("R5-sqli", "R5-lfi"):
            g.edge(ip_node(d["source_ip"]), host_node(first),
                   "SQL injection" if rule == "R5-sqli" else "path traversal", sev)
        elif rule == "R5-webshell":
            path = first["details"].get("path", "").split("?")[0]
            shell = g.node(f"shell:{_host(first, first['details'])}:{path}", f"web shell\n{path}", "shell")
            g.edge(ip_node(d["source_ip"]), host_node(first), "uploads shell", sev)
            g.edge(host_node(first), shell, f"{len(events)} commands", sev)
        elif rule == "R6-lateral-movement" and len(events) >= 2:
            shell_evt, login = events[0], events[-1]
            path = shell_evt["details"].get("path", "").split("?")[0]
            shell = g.node(f"shell:{_host(shell_evt, shell_evt['details'])}:{path}",
                           f"web shell\n{path}", "shell")
            pivot = ip_node(login["source_ip"])
            g.edge(shell, pivot, "pivot", sev)
            g.edge(pivot, host_node(login), f"SSH as {login['username']}", sev)
            g.edge(host_node(login), account_node(login), "valid account", sev)
        elif rule == "R7-privilege-escalation" or rule.startswith("R8-"):
            for e in events:
                if e["details"].get("kind") != "sudo":
                    continue
                target = re.search(r" as (\S+?):", e["event_summary"])
                if target:
                    label = "sudo" if rule.startswith("R7") else SHORT_LABELS.get(d["mitre"], d["title"])
                    g.edge(account_node(e), account_node(e, target.group(1)), label, sev)
    return g


def _to_dot(g: "_Graph", palette: dict) -> str:
    styles = {
        "attacker": f'shape=box, style="rounded,filled", fillcolor="{palette["attacker"]}", fontcolor="#FFFFFF"',
        "internal": f'shape=box, style="rounded,filled", fillcolor="{palette["internal"]}", fontcolor="#FFFFFF"',
        "host": f'shape=box3d, style="filled", fillcolor="{palette["host"]}", fontcolor="#FFFFFF"',
        "shell": f'shape=note, style="filled", fillcolor="{palette["shell"]}", fontcolor="#FFFFFF"',
        "account": f'shape=ellipse, style="filled", fillcolor="{palette["account"]}", fontcolor="#FFFFFF"',
        "privileged": f'shape=doubleoctagon, style="filled", fillcolor="{palette["privileged"]}", fontcolor="#FFFFFF"',
    }
    lines = ["digraph attack {",
             f'  graph [rankdir=TB, bgcolor="transparent", pad="0.2", nodesep="0.5", ranksep="0.32", '
             f'fontname="Segoe UI"];',
             f'  node [fontname="Segoe UI", fontsize=13, margin="0.14,0.05", color="{palette["border"]}"];',
             f'  edge [fontname="Segoe UI", fontsize=11, fontcolor="{palette["text"]}", arrowsize=0.7];']
    for key, (label, kind) in g.nodes.items():
        lines.append(f"  {_q(key)} [label={_q(label)}, {styles[kind]}];")
    for (a, b), (labels, sev) in g.edges.items():
        colour = palette["sev"][sev]
        width = {"CRITICAL": 2.6, "HIGH": 1.8}.get(sev, 1.2)
        lines.append(f"  {_q(a)} -> {_q(b)} [label={_q(chr(10).join(sorted(labels)))}, "
                     f'color="{colour}", penwidth={width}];')
    lines.append("}")
    return "\n".join(lines) if g.nodes else ""
