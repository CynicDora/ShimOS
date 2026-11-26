#ifndef SHIMOS_BRIDGE_TIMING_H
#define SHIMOS_BRIDGE_TIMING_H

/* Optional correctness-preserving diagnostic instrumentation. No FD, file I/O,
 * allocation, policy change or runtime replacement. CLOCK_MONOTONIC is the
 * guest clock, shared with Python monotonic_ns in the same time namespace.
 * Durations are wall spans, NOT kernel CPU or exclusive libc execution time.
 * Fixed-buffer writes and clock reads perturb execution and require calibration.
 */
#include <time.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>

#define SHIMOS_TIMING_CAPACITY 128
struct shimos_timing_record {
    const char *stage;
    const char *branch;
    uint64_t start_ns, end_ns;
    int result, error;
};
static int shimos_timing_on;
static unsigned int shimos_timing_used, shimos_timing_dropped, shimos_timing_clock_errors;
static struct shimos_timing_record shimos_timing_buffer[SHIMOS_TIMING_CAPACITY];

int timing_reset(void) {
    shimos_timing_used = shimos_timing_dropped = shimos_timing_clock_errors = 0;
    return 0;
}
int timing_enable(int enabled) {
    shimos_timing_on = enabled != 0;
    return timing_reset();
}
static uint64_t timing_now_ns(void) {
    if (!shimos_timing_on) return 0; /* Disabled path does not read any clock. */
    int saved = errno;
    struct timespec ts;
    int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (rc) shimos_timing_clock_errors++;
    errno = saved;
    return rc ? 0 : (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}
static void timing_add(const char *stage, const char *branch,
                       uint64_t start_ns, uint64_t end_ns, int result, int error) {
    if (!shimos_timing_on) return;
    if (shimos_timing_used == SHIMOS_TIMING_CAPACITY) {
        shimos_timing_dropped++;
        return;
    }
    struct shimos_timing_record *r = &shimos_timing_buffer[shimos_timing_used++];
    r->stage = stage; r->branch = branch; r->start_ns = start_ns; r->end_ns = end_ns;
    r->result = result; r->error = error;
}
static void timing_finish(const char *stage, uint64_t start_ns, int result, int error) {
    timing_add(stage, "local", start_ns, timing_now_ns(), result, error);
}
static int timing_append(char *out, size_t size, size_t *offset, const char *fmt, ...) {
    if (*offset >= size) return -ENOSPC;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(out + *offset, size - *offset, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - *offset) return -ENOSPC;
    *offset += (size_t)n;
    return 0;
}

/* Call outside the measured region. Returns JSON byte count (excluding NUL),
 * or a negative errno value. No record is consumed on error. Caller provides
 * attempt/role identity; local PIDs and namespace inodes are not unique IDs.
 * A 65536-byte output buffer covers the maximum fixed record count.
 */
int timing_drain(char *out, size_t size) {
    int saved = errno, result = 0;
    size_t offset = 0;
    if (!out || !size) { result = -EINVAL; goto end; }
    result = timing_append(out, size, &offset,
        "{\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\",\"enabled\":%s,"
        "\"capacity\":%u,\"dropped\":%u,\"overflow\":%s,\"clock_errors\":%u,\"records\":[",
        shimos_timing_on ? "true" : "false", SHIMOS_TIMING_CAPACITY,
        shimos_timing_dropped, shimos_timing_dropped ? "true" : "false", shimos_timing_clock_errors);
    for (unsigned int i = 0; result == 0 && i < shimos_timing_used; i++) {
        struct shimos_timing_record *r = &shimos_timing_buffer[i];
        result = timing_append(out, size, &offset,
            "%s{\"stage\":\"%s\",\"branch\":\"%s\",\"start_ns\":%" PRIu64 ","
            "\"end_ns\":%" PRIu64 ",\"ret\":%d,\"error\":%d,\"clock_valid\":%s}",
            i ? "," : "", r->stage, r->branch, r->start_ns, r->end_ns, r->result, r->error,
            r->start_ns && r->end_ns >= r->start_ns ? "true" : "false");
    }
    if (result == 0) result = timing_append(out, size, &offset, "]}");
    if (result == 0) { result = (int)offset; timing_reset(); }
end:
    errno = saved;
    return result;
}
#endif
