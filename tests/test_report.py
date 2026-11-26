"""The report groups findings under the process they concern (proposal III.D):
a process tree with memory offsets and open connections, kernel-level findings
under a synthetic <kernel> node."""

from spf.models import (
    AnomalyFinding, KernelModule, MemoryEvidence, Process, RuleFinding, SyscallEntry,
)
from spf.report.builder import build_report, render_html


def _evidence():
    parent = Process(pid=1000, ppid=1, uid=0, comm="systemd", task_offset=0x1000)
    agent = Process(pid=1337, ppid=1000, uid=0, comm="agent", task_offset=0xDEAD,
                    exe_path="/dev/shm/agent", sockets=[{"Family": "AF_INET", "Proto": "TCP",
                    "Source Addr": "0.0.0.0", "Source Port": "44444", "Destination Addr": "0.0.0.0",
                    "Destination Port": "0", "State": "LISTEN"}])
    return MemoryEvidence(
        image_path="t.lime", tasks_list=[parent, agent], pid_hash_pids={1000, 1337},
        registered_modules=[], memory_modules=[], syscall_table=[], kernel_text=(0x1, 0x2),
    )


def test_tree_groups_findings_under_their_process():
    ev = _evidence()
    rules = [RuleFinding(rule="HIDDEN_KERNEL_MODULE", description="x", evidence={"name": "rk"})]
    anoms = [AnomalyFinding(pid=1337, score=0.9, threshold=0.7, features={},
                            explanation="runs from /dev/shm", novel_features=["runs_from_tmp_or_shm"])]
    report = build_report(ev, rules, anoms)
    tree = {n["pid"]: n for n in report["flagged_processes"]}

    # the agent node carries its anomaly, memory offset, connection and parent chain
    agent = tree[1337]
    assert agent["anomaly"]["explanation"] == "runs from /dev/shm"
    assert agent["task_offset"] == hex(0xDEAD)
    assert agent["exe_path"] == "/dev/shm/agent"
    assert any("44444" in c for c in agent["connections"])
    assert [a["comm"] for a in agent["ancestry"]] == ["systemd"]

    # module finding (no owning PID) sits under the synthetic kernel node
    kernel = tree[None]
    assert kernel["comm"] == "<kernel>"
    assert kernel["rule_findings"][0]["rule"] == "HIDDEN_KERNEL_MODULE"


def test_html_renders_tree(tmp_path):
    ev = _evidence()
    anoms = [AnomalyFinding(pid=1337, score=0.9, threshold=0.7, features={}, explanation="why")]
    report = build_report(ev, [], anoms)
    out = render_html(report, tmp_path / "r.html")
    page = out.read_text()
    assert "Flagged processes (grouped)" in page
    assert "44444" in page and "0xdead" in page
