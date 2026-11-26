"""Pure, bounded decoder for the trusted bootstrap/launcher's private pipe.

Never call this decoder on tool stdout/stderr. A pipe's request binding and FD
ownership are established by S, not by these bytes. No EOF, wait status, target
output, or pre-exec record proves that the target image started successfully.
This module performs no I/O and deliberately has no success-promotion API.
"""
import struct

MAGIC = b"SXRC"
VERSION = 1
FRAME = struct.Struct("<4sBBHiIQ")
FRAME_SIZE = FRAME.size  # 24; C implementation encodes fields explicitly.
MAX_RECORDS = 8
MAX_BYTES = FRAME_SIZE * MAX_RECORDS

STAGES = {
    "LAUNCHER_EXEC_ATTEMPT": 1,
    "LAUNCHER_EXEC_FAILED": 2,
    "LAUNCHER_READY": 3,
    "TARGET_EXEC_ATTEMPT": 4,
    "EXEC_FAILED": 5,
    "LAUNCHER_SETUP_FAILED": 6,
}
STAGE_NAMES = {value: name for name, value in STAGES.items()}
DETAIL_NAMES = {
    1: "arguments", 2: "arguments_size", 3: "receipt_cloexec",
    4: "receipt_pipe", 5: "receipt_flags", 6: "capabilities",
    7: "no_new_privs", 8: "seccomp_filter", 9: "close_range",
    10: "signals", 11: "clock", 12: "diagnostic_output",
}
_FAILURES = {2, 5, 6}
_NEXT = {0: {1}, 1: {2, 3, 6}, 3: {4, 6}, 4: {5}, 2: set(), 5: set(), 6: set()}


def _fields_valid(stage, error, detail, monotonic_ns):
    if stage not in STAGE_NAMES:
        return "unknown_stage"
    if any(type(value) is not int for value in (error, detail, monotonic_ns)):
        return "non_integer_field"
    if not 0 <= monotonic_ns < (1 << 64):
        return "invalid_timestamp"
    if stage in _FAILURES:
        if not 1 <= error <= 4095:
            return "invalid_errno"
    elif error != 0:
        return "unexpected_errno"
    if stage == 6:
        if detail not in DETAIL_NAMES:
            return "unknown_setup_detail"
    elif detail != 0:
        return "unexpected_detail"
    return None


def encode_record(stage, error=0, detail=0, monotonic_ns=0):
    """Encode one trusted bootstrap record; the caller owns atomic pipe write.

    stage accepts a STAGES name or numeric ID. The bootstrap normally emits
    only LAUNCHER_EXEC_ATTEMPT and, if os.execv returns, LAUNCHER_EXEC_FAILED.
    Timestamp 0 means unavailable; it conveys no timing guarantee.
    """
    number = STAGES.get(stage) if isinstance(stage, str) else stage
    if type(number) is not int:
        raise ValueError("unknown_stage")
    reason = _fields_valid(number, error, detail, monotonic_ns)
    if reason:
        raise ValueError(reason)
    return FRAME.pack(MAGIC, VERSION, number, 0, error, detail, monotonic_ns)


def decode_receipts(data, eof=False):
    """Decode the complete bounded prefix collected from one private pipe.

    A partial final frame is permitted while eof=False, but is invalid at EOF.
    Invalid framing/order erases any derived conclusion (records remain only
    diagnostic). EXEC_FAILED means a trusted exec syscall returned an errno;
    LAUNCHER_SETUP_FAILED is a distinct pre-target setup failure. All other
    target exec conclusions remain UNKNOWN, including ATTEMPT followed by EOF.
    """
    result = {
        "protocol": "SXRC/1", "valid": True, "protocol_valid": True, "error": None,
        "eof": bool(eof), "bytes": len(data) if isinstance(data, (bytes, bytearray)) else 0,
        "pending_bytes": 0, "status": "EXEC_STATUS_UNKNOWN",
        "stages": [], "records": [], "launcher_state": "NOT_OBSERVED",
        "target_state": "NOT_OBSERVED", "exec_result": "UNKNOWN",
        "failure_stage": None, "errno": None, "success_observed": False,
        "evidence": "PRIVATE_EXEC_RECEIPT",
    }

    def invalid(reason):
        result.update(valid=False, protocol_valid=False, error=reason, launcher_state="UNKNOWN",
                      target_state="UNKNOWN", exec_result="UNKNOWN",
                      status="EXEC_STATUS_UNKNOWN", failure_stage=None, errno=None,
                      success_observed=False)
        return result

    if not isinstance(data, (bytes, bytearray)):
        return invalid("not_bytes")
    if len(data) > MAX_BYTES:
        return invalid("receipt_limit")
    result["pending_bytes"] = len(data) % FRAME_SIZE
    previous = 0
    last_time = 0
    for offset in range(0, len(data) - result["pending_bytes"], FRAME_SIZE):
        magic, version, stage, reserved, error, detail, when = FRAME.unpack_from(data, offset)
        if magic != MAGIC or version != VERSION or reserved != 0:
            return invalid("frame_header")
        reason = _fields_valid(stage, error, detail, when)
        if reason:
            return invalid(reason)
        if stage not in _NEXT[previous]:
            return invalid("stage_order")
        if when and last_time and when < last_time:
            return invalid("timestamp_order")
        if when:
            last_time = when
        record = {"event": STAGE_NAMES[stage], "errno": error,
                  "detail": detail, "monotonic_ns": when}
        if detail:
            record["detail_name"] = DETAIL_NAMES[detail]
        result["records"].append(record)
        result["stages"].append(STAGE_NAMES[stage])
        previous = stage
        if stage == 1:
            result["launcher_state"] = "LAUNCHER_EXEC_ATTEMPTED"
        elif stage == 2:
            result.update(launcher_state="LAUNCHER_EXEC_FAILED", exec_result="EXEC_FAILED",
                          status="LAUNCHER_FAILED", failure_stage="launcher_exec", errno=error)
        elif stage == 3:
            result["launcher_state"] = "LAUNCHER_READY_OBSERVED"
        elif stage == 4:
            result["target_state"] = "TARGET_EXEC_ATTEMPTED"
        elif stage == 5:
            result.update(target_state="EXEC_FAILED", exec_result="EXEC_FAILED",
                          status="TARGET_EXEC_FAILED", failure_stage="target_exec", errno=error)
        elif stage == 6:
            result.update(launcher_state="LAUNCHER_SETUP_FAILED",
                          status="LAUNCHER_FAILED", failure_stage="launcher_setup", errno=error)
    if result["pending_bytes"] and eof:
        return invalid("truncated_frame_at_eof")
    return result
