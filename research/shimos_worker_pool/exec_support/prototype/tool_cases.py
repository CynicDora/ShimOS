"""Fixed tool catalogue. No arbitrary executable, shell body, or dependency install.

The Controller validates a catalogue key; argv and the small environment below
are copied into a request. /workloads is immutable in each target domain.
No case is a correctness claim: results must come from the private-VM driver.
"""
from copy import deepcopy


def _case(argv, *, level, expected_exit=0, timeout_s=3.0, post_exit_s=0.2, **kw):
    return {"argv": argv, "level": level, "expected_exit": expected_exit,
            "timeout_s": timeout_s, "post_exit_s": post_exit_s,
            "env": {}, "expected_signal": None, "expect_timeout": False,
            "expected_stdout": [], "expected_stderr": [], **kw}


STATIC = "/workloads/bin/probe-static"
DYNAMIC = "/workloads/bin/probe-dynamic"
SHELL = ["/bin/sh", "/workloads/fixed_shell.sh"]
COMPILE = ["/bin/sh", "/workloads/fixed_compile.sh"]
UNITTEST = ["/usr/bin/python3", "-I", "-B", "/workloads/fixed_unittest.py"]

CASES = {
    "elf_static": _case([STATIC, "normal"], level=1, expected_stdout=["ELF_OK"]),
    "elf_dynamic": _case([DYNAMIC, "normal"], level=1, expected_stdout=["ELF_OK"]),
    "elf_nonzero": _case([DYNAMIC, "nonzero"], level=1, expected_exit=7, expected_stderr=["ELF_EXPECTED_FAILURE"]),
    "elf_environment": _case([DYNAMIC, "env"], level=1, env={"SHIMOS_TOOL_TOKEN": "fixed-env-value"},
                             expected_stdout=["TOOL_ENV=fixed-env-value"], expected_stderr=["TOOL_STDERR_OK"]),
    "elf_loader_failure": _case(["/workloads/bin/linked-missing"], level=1, expected_exit=127,
                                expected_stderr=["libexec_missing_fixture.so"]),
    "elf_negative": _case([DYNAMIC, "negative"], level=1, expected_stdout=['"event":"TOOL_NEGATIVE_RESULT"']),
    "shell_pipeline": _case(SHELL + ["pipeline"], level=2, expected_stdout=["ALPHA\nBETA\nGAMMA", "SHELL_PIPELINE_OK"]),
    "shell_children": _case(SHELL + ["children"], level=2, expected_stdout=["SHELL_CHILDREN_OK", "TOOL_GRANDCHILD"]),
    "shell_failure": _case(SHELL + ["failure"], level=2, expected_exit=7, expected_stderr=["SHELL_PROPAGATED_EXIT=7"]),
    "shell_background": _case(SHELL + ["background"], level=2, expected_stdout=["SHELL_BACKGROUND_PID="],
                              expect_descendants_after_main=True),
    "shell_cancel": _case(SHELL + ["cancel"], level=2, timeout_s=2.0, expected_exit=None,
                          action="cancel", action_after_s=0.15, expected_signal=9, expected_stdout=["SHELL_CANCEL_TREE_READY"]),
    "shell_timeout": _case(SHELL + ["cancel"], level=2, timeout_s=0.35, expected_exit=None,
                           expected_signal=9, expect_timeout=True),
    "gcc_success": _case(COMPILE + ["success"], level=3, timeout_s=6.0,
                         expected_stdout=["COMPILER_LINK_OK", "COMPILED_RESULT=42"]),
    "gcc_failure": _case(COMPILE + ["failure"], level=3, timeout_s=6.0, expected_exit=1,
                         expected_stderr=["error:"]),
    "unittest_pass": _case(UNITTEST + ["pass"], level=4, expected_stderr=["Ran 2 tests", "OK"]),
    "unittest_fail": _case(UNITTEST + ["fail"], level=4, expected_exit=1,
                           expected_stderr=["intentional assertion failure", "FAILED (failures=1)"]),
    "unittest_timeout": _case(UNITTEST + ["timeout"], level=4, timeout_s=0.35,
                              expected_exit=None, expected_signal=9, expect_timeout=True),
    "unittest_partial": _case(UNITTEST + ["partial"], level=4, timeout_s=0.35,
                              expected_exit=None, expected_signal=9, expect_timeout=True,
                              expected_stdout=["UNITTEST_PARTIAL_WITHOUT_NEWLINE"], expect_partial_output=True),
    "unittest_descendants": _case(UNITTEST + ["descendants"], level=4,
                                  expected_stdout=["TOOL_GRANDCHILD"], expected_stderr=["OK"]),
    "unittest_orphan": _case(UNITTEST + ["orphan"], level=4, expect_descendants_after_main=True,
                             expected_stdout=["UNITTEST_DESCENDANT_STILL_HOLDS_OUTPUT"], expected_stderr=["OK"]),
    "tree_child": _case([DYNAMIC, "child"], level=1, expected_stdout=["TOOL_CHILD", "TOOL_PARENT_WAIT"]),
    "tree_grandchild": _case([DYNAMIC, "grandchild"], level=1, expected_stdout=["TOOL_GRANDCHILD_DONE"]),
    "tree_orphan": _case([DYNAMIC, "orphan"], level=1, expect_descendants_after_main=True),
    "tree_holdio": _case([DYNAMIC, "holdio"], level=1, expect_descendants_after_main=True),
    "tree_zombie": _case([DYNAMIC, "zombie"], level=1, expected_stdout=["TOOL_ZOMBIE_NOT_WAITED"]),
    "tool_sigkill": _case([DYNAMIC, "sigkill"], level=1, expected_exit=None, expected_signal=9),
    "tool_timeout": _case([DYNAMIC, "hang"], level=1, timeout_s=0.25, expected_exit=None,
                          expected_signal=9, expect_timeout=True),
    "tool_cancel": _case([DYNAMIC, "hang"], level=1, expected_exit=None, expected_signal=9,
                         action="cancel", action_after_s=0.15),
    "tool_partial": _case([DYNAMIC, "partial"], level=1, timeout_s=0.25, expected_exit=None,
                          expected_signal=9, expect_timeout=True, expect_partial_output=True,
                          expected_stdout=["PARTIAL_WITHOUT_NEWLINE"]),
    "tool_controller_death": _case(SHELL + ["cancel"], level=2, expected_exit=None,
                                   action="controller_death", action_after_s=0.15, expected_business="UNKNOWN"),
    "tool_result_loss": _case([DYNAMIC, "result"], level=1, expected_exit=0,
                              action="result_loss_side_effect", expected_business="UNKNOWN",
                              side_effect_path="/work/tool-side-effect", expected_stdout=["TOOL_SIDE_EFFECT_CREATED"]),
    "tool_output_spoof": _case([DYNAMIC, "spoof"], level=1,
                               expected_stdout=["attacker-chosen-nonce"], expected_stderr=["TOOL_OUTPUT_IS_UNTRUSTED_DATA"],
                               stdout_is_opaque=True),
    "tool_before_gate_cancel": _case([DYNAMIC, "normal"], level=1, expected_exit=None,
                                     action="cancel_before_business", expected_business="NOT_EXECUTED",
                                     expected_not_executed=True),
    "tool_pids_budget": _case([DYNAMIC, "pids"], level=1, timeout_s=4.0,
                              limits={"pids.max": "16"}, expected_stdout=["TOOL_PIDS_LIMIT"]),
    "tool_cpu_budget": _case([DYNAMIC, "cpu"], level=1, timeout_s=4.0,
                             limits={"cpu.max": "10000 100000"}, expected_stdout=["TOOL_CPU_DONE"],
                             resource_outcome="throttling; CPU quota is not a creation denial"),
    "tool_memory_budget": _case([DYNAMIC, "memory"], level=1, timeout_s=4.0, expected_exit=None,
                                expected_signal=9, limits={"memory.max": "33554432", "memory.swap.max": "0"},
                                resource_outcome="OOM kill requires memory.events evidence"),
    "tool_output_limit": _case([DYNAMIC,"output_flood"],level=1,expected_exit=None,
                                expected_outcome="OUTPUT_LIMIT"),
    "tool_unsafe_result": _case([DYNAMIC,"unsafe_result"],level=1,
                                expected_stdout=["TOOL_UNSAFE_RESULT_CREATED"]),
}

SUITES = {
    "level1": ["elf_static", "elf_dynamic", "elf_nonzero", "elf_environment", "elf_loader_failure", "elf_negative"],
    "level2": ["shell_pipeline", "shell_children", "shell_failure", "shell_background", "shell_cancel", "shell_timeout"],
    "level3": ["gcc_success", "gcc_failure"],
    "level4": ["unittest_pass", "unittest_fail", "unittest_timeout", "unittest_partial", "unittest_descendants", "unittest_orphan"],
    "lifecycle": ["tree_child", "tree_grandchild", "tree_orphan", "tree_holdio", "tree_zombie", "tool_sigkill",
                  "tool_timeout", "tool_cancel", "tool_partial", "tool_result_loss",
                  "tool_output_spoof", "tool_before_gate_cancel"],
    "budgets": ["tool_pids_budget", "tool_cpu_budget", "tool_memory_budget"],
    "cost": ["elf_static", "elf_dynamic", "shell_pipeline", "gcc_success", "unittest_pass", "elf_nonzero", "tool_cancel"],
}
SUITES["controller_death"] = ["tool_controller_death"]
SUITES["output_boundary"] = ["tool_output_limit","tool_unsafe_result","tool_output_spoof"]
SUITES["all"] = [name for suite in ("level1", "level2", "level3", "level4", "lifecycle", "budgets") for name in SUITES[suite]]

BLOCKED = {
    "g++": "Frozen initramfs has no g++, cc1plus, libstdc++, or C++ headers; no installation attempted.",
    "pytest": "Frozen initramfs has no pytest/pluggy distribution; unittest is a separately named stdlib substitute.",
}


def get_case(name):
    if name not in CASES:
        raise ValueError("unknown fixed tool case: " + repr(name))
    return {"name": name, **deepcopy(CASES[name])}
