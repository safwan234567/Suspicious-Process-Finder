from spf.ml import FEATURE_NAMES, build_features
from spf.models import VMA, Process


def test_feature_vector_has_all_features():
    proc = Process(pid=10, ppid=1, uid=0, comm="bash", task_offset=0)
    assert set(build_features(proc, parent_uid=0)) == set(FEATURE_NAMES)


def test_suspicious_process_features():
    proc = Process(
        pid=66,
        ppid=1,
        uid=1000,
        comm="x",
        task_offset=0,
        exe_path="/dev/shm/x",
        envars={"LD_PRELOAD": "/tmp/evil.so"},
        vmas=[
            VMA(0x1000, 0x2000, "r-x", "/dev/shm/x"),
            VMA(0x3000, 0x5000, "rwx", None),
            VMA(0x6000, 0x7000, "rwx", None),
        ],
    )
    f = build_features(proc, parent_uid=0)
    assert f["unbacked_exec_count"] == 2
    assert f["unbacked_exec_bytes"] == 0x3000
    assert f["anon_to_file_ratio"] == 3.0
    assert f["uid_differs_from_parent"] == 1.0
    assert f["runs_from_tmp_or_shm"] == 1.0
    assert f["has_ld_preload"] == 1.0


def test_runs_from_shm_detected_despite_spoofed_argv():
    """argv[0] is attacker-controlled; the real binary mapped from /dev/shm as an
    executable VMA must still trip the feature."""
    proc = Process(
        pid=7, ppid=1, uid=0, comm="x", task_offset=0,
        exe_path="sshd: worker",  # masked argv[0]
        vmas=[VMA(0x1000, 0x2000, "r-x", "/dev/shm/evil")],
    )
    assert build_features(proc, parent_uid=0)["runs_from_tmp_or_shm"] == 1.0


def test_normal_process_not_flagged_as_tmp_shm():
    proc = Process(pid=8, ppid=1, uid=0, comm="nginx", task_offset=0,
                   exe_path="/usr/sbin/nginx",
                   vmas=[VMA(0x1000, 0x2000, "r-x", "/usr/sbin/nginx")])
    assert build_features(proc, parent_uid=0)["runs_from_tmp_or_shm"] == 0.0
