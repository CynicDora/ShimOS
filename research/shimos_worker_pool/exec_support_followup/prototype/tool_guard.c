#define _GNU_SOURCE
#include <linux/capability.h>
#include <unistd.h>
#include "tool_policy.h"

/* ABI: return 0 on success, -1 with errno on rejection. The caller must exit
 * without granting/running business on failure; no less-restrictive fallback.
 * ctypes.CDLL(..., use_errno=True) is sufficient: no Python fork takes place.
 * Caller is the already single-threaded, final-drop Tool W only. */
int install_tool_policy(void)
{
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data) < 0) return -1;
    for (unsigned i = 0; i < 2; i++) {
        if (data[i].effective || data[i].permitted || data[i].inheritable) {
            errno = EPERM;
            return -1;
        }
    }
    for (int capability = 0; capability < 64; capability++) {
        int bounded = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (bounded < 0 && errno == EINVAL) break;
        if (bounded < 0) return -1;
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
        if (ambient < 0) return -1;
        if (bounded || ambient) {
            errno = EPERM;
            return -1;
        }
    }
    return shimos_apply_tool_policy();
}
