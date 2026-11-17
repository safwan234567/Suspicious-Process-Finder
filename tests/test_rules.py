from spf.models import KernelModule, MemoryEvidence, Process, SyscallEntry
from spf.rules import run_rules
from spf.rules.checks import check_dkom_hidden_processes, check_hidden_modules, check_syscall_hooks

KERNEL = (0xFFFF0000, 0xFFFF9000)
GOOD_MOD = KernelModule("ext4", 0xA000, 0x1000)


def evidence(**overrides) -> MemoryEvidence:
    base = dict(
        image_path="test.lime",
        tasks_list=[Process(pid=1, ppid=0, uid=0, comm="systemd", task_offset=0x1000)],
        pid_hash_pids={1},
        registered_modules=[GOOD_MOD],
        memory_modules=[GOOD_MOD],
        syscall_table=[SyscallEntry(0, 0xFFFF0100, "sys_read")],
        kernel_text=KERNEL,
    )
    base.update(overrides)
    return MemoryEvidence(**base)


def test_unknown_kernel_range_skips_syscall_rule():
    table = [SyscallEntry(0, 0xFFFF0100, "sys_read"), SyscallEntry(62, 0xDEAD0000, None)]
    assert check_syscall_hooks(evidence(kernel_text=None, syscall_table=table)) == []


def test_invalid_kernel_range_skips_syscall_rule():
    table = [SyscallEntry(0, 0xFFFF0100, "sys_read")]
    assert check_syscall_hooks(evidence(kernel_text=(0, 0), syscall_table=table)) == []


def test_clean_image_has_no_findings():
    assert run_rules(evidence()) == []


def test_dkom_hidden_process():
    findings = check_dkom_hidden_processes(evidence(pid_hash_pids={1, 1337}))
    assert [f.pid for f in findings] == [1337]


def test_hidden_module():
    rootkit = KernelModule("diamorphine", 0xB000, 0x2000)
    findings = check_hidden_modules(evidence(memory_modules=[GOOD_MOD, rootkit]))
    assert len(findings) == 1 and findings[0].evidence["name"] == "diamorphine"


def test_hooked_syscall():
    table = [SyscallEntry(0, 0xFFFF0100, "sys_read"), SyscallEntry(62, 0xDEAD0000, None)]
    findings = check_syscall_hooks(evidence(syscall_table=table))
    assert len(findings) == 1 and findings[0].evidence["index"] == 62


def test_syscall_into_registered_module_is_not_flagged():
    table = [SyscallEntry(5, 0xA500, "ext4_fn")]
    assert check_syscall_hooks(evidence(syscall_table=table)) == []
