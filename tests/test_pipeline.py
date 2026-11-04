"""End-to-end test of the rule + ML + explain + report pipeline on synthetic
evidence (no memory image needed). Proves stages B, C and D fit together."""

from examples.demo_report import main as run_demo


def test_pipeline_end_to_end(tmp_path):
    report = run_demo(out_dir=str(tmp_path))

    # the three planted rule findings fire
    rules = {f["rule"] for f in report["rule_findings"]}
    assert "DKOM_HIDDEN_PROCESS" in rules
    assert "HIDDEN_KERNEL_MODULE" in rules
    assert "HOOKED_SYSCALL" in rules

    # the injected process is flagged by the ML stage with a real explanation
    assert report["summary"]["anomalies"] >= 1
    flagged = {a["pid"] for a in report["anomalies"]}
    assert 1337 in flagged
    inj = next(a for a in report["anomalies"] if a["pid"] == 1337)
    assert inj["score"] >= inj["threshold"]
    assert inj["explanation"]

    # report files were written
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()
