#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/sysctl.h>

#include <ps5/kernel.h>

#if !defined(dstr)
#define dstr(s) #s
#endif
#if !defined(xstr)
#define xstr(s) dstr(s)
#endif

#if !defined(_countof)
#define _countof(a) (sizeof(a) / sizeof(*a))
#endif

#if !defined(_countof_1)
#define _countof_1(a) (_countof(a) - 1)
#endif

#if !defined(sizeof_1)
#define sizeof_1(s) (sizeof(s) - 1)
#endif

#if !defined(FILE_FUNC_LINE)
#define FILE_FUNC_LINE \
    __FILE__           \
    ":"__FUNCSIG__     \
    ":" xstr(__LINE__)
#endif

#define debug_print_always(a, ...) printf(FILE_FUNC_LINE ": " a, ##__VA_ARGS__)
#define debugf debug_print_always
#define perror_on_cond(e, v, c, es)         \
    e;                                      \
    if (c)                                  \
    {                                       \
        perror(#c " because " es);          \
        debugf(es ": %d (0x%08x)\n", v, v); \
    }
#define perror_on_non_zero(e, v) perror_on_cond(e, v, v != 0, #e)

static void notify_(const char* fn, const char* fmt, ...)
{
    struct notify_request
    {
        char useless1[45];
        char message[1024];
        char useless2[2051];
    } buf = {};
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf.message, _countof_1(buf.message), fmt, args);
    va_end(args);
    size_t len = strlen(buf.message);
    // trim newline
    while (len > 0 && buf.message[len - 1] == '\n')
    {
        buf.message[--len] = '\0';
    }
    extern int sceKernelSendNotificationRequest(const size_t, const struct notify_request*, const size_t, const int);
    printf("%s: %s\n", fn, buf.message);
    sceKernelSendNotificationRequest(0, &buf, sizeof(buf), 0);
}

#define notify(...) notify_(FILE_FUNC_LINE, __VA_ARGS__)

#define MAX_KCHUNK 2048

static uintptr_t kernel_scan(const uintptr_t base, const size_t limit, const void* needle, const size_t nlen)
{
    if (!needle || nlen == 0 || nlen > MAX_KCHUNK)
    {
        return 0;
    }

    uint8_t buf[MAX_KCHUNK];
    size_t scanned = 0;

    while (limit == 0 || scanned < limit)
    {
        size_t chunk = sizeof(buf);
        if (limit && scanned + chunk > limit)
        {
            chunk = limit - scanned;
        }

        if (kernel_copyout(base + scanned, buf, chunk) != 0)
        {
            return 0;
        }

        for (size_t j = 0; j + nlen <= chunk; j++)
        {
            if (memcmp(buf + j, needle, nlen) == 0)
            {
                return base + scanned + j;
            }
        }

        scanned += chunk;
    }

    return 0;
}

// https://github.com/sleirsgoevy/ps4-hamachi/blob/d41f328fb587cc17e567845ed314f89a2255976c/app/app/getfw.c#L6
int dynlib_get_obj_member(const uint32_t module_id, const size_t which, void** out);

static int get_firmware_version_from_disk1(uint32_t* out, const bool want_ps4)
{
    void* sce_proc_param = 0;
    int r = 0;
    const uint32_t libkernel_sys = 0x1;
    perror_on_non_zero(r = dynlib_get_obj_member(libkernel_sys, 8, &sce_proc_param), r);
    if (r || !sce_proc_param)
    {
        return -__LINE__;
    }
    const uint32_t* spp = (uint32_t*)sce_proc_param;
// on ps5, 4 is ps4 ver, 5 is ps5 ver
#if defined(__ORBIS__)
    const size_t fw_idx = 4;
#elif defined(__PROSPERO__)
    const size_t fw_idx = want_ps4 ? 4 : 5;
#endif
    *out = spp[fw_idx];
    return 0;
}

static void get_ver_(const char* fn, const bool display, const char* pf, const char* mibn, uint32_t* out)
{
    size_t len = sizeof(*out);
    *out = 0;
    sysctlbyname(mibn, out, &len, NULL, 0);
    if (display)
    {
        notify_(fn, "%s%s: 0x%08x\n", pf, mibn, *out);
    }
}

#define get_ver(d, pf, m, o) get_ver_(FILE_FUNC_LINE, d, pf, m, o)
#define get_ver_hide(pf, m, o) get_ver(false, pf, m, o)
#define get_ver_show(pf, m, o) get_ver(true, pf, m, o)

// assume only 1 ref, should be okay. nyahuhuhu
static uintptr_t kernel_scan_strref(const uintptr_t base, const size_t limit, const void* s, const size_t slen)
{
    uintptr_t str_addr = kernel_scan(base, limit, s, slen);
    if (!str_addr)
    {
        return 0;
    }
    str_addr += 1;
    return kernel_scan(base, limit, &str_addr, sizeof(str_addr));
}

static uintptr_t kernel_scan_near(const uintptr_t addr, const size_t range, const void* needle, const size_t nlen)
{
    const uintptr_t base = addr > range ? addr - range : 0;
    const size_t limit = range * 2;
    return kernel_scan(base, limit, needle, nlen);
}

static const uint32_t fw_max = 0x99999999;

static void write_fw(const uintptr_t psdk)
{
    uint32_t v = kernel_getint(psdk);
    if (v == fw_max)
    {
        printf("0x%lx same\n", psdk);
        return;
    }
    printf("0x%lx 0x%08x ", psdk, v);
    kernel_setint(psdk, fw_max);
    v = kernel_getint(psdk);
    printf("-> 0x%08x\n", v);
}

static void patch_fw(void)
{
#define strsz(s) s, sizeof_1(s)
    uintptr_t sdk_ver = kernel_scan_strref(KERNEL_ADDRESS_DATA_BASE, 0, strsz("\0ps4_sdk_version\0"));
    if (sdk_ver)
    {
        write_fw(sdk_ver - 8);
    }
    uint32_t upd_version = 0;
    get_ver_hide("before: ", "machdep.upd_version", &upd_version);
    sdk_ver = kernel_scan_near(KERNEL_ADDRESS_SECURITY_FLAGS, 4096, &upd_version, sizeof(upd_version));
    if (sdk_ver)
    {
        write_fw(sdk_ver);
    }
    return;
    sdk_ver = kernel_scan_strref(KERNEL_ADDRESS_DATA_BASE, 0, strsz("\0sdk_version\0"));
    if (sdk_ver)
    {
        write_fw(sdk_ver - 8);
    }
}

int main(void)
{
    // all vars must be 0, otherwise you'll undesirable consequences nyahuhu
    struct d
    {
        uint32_t fw_ps4, fw_ps5, temp;
    } d = {};
    get_firmware_version_from_disk1(&d.fw_ps4, true);
    get_firmware_version_from_disk1(&d.fw_ps5, false);
    notify(
        "real ps4 sdk 0x%08x\n"
        "real ps5 sdk 0x%08x\n",
        d.fw_ps4,
        d.fw_ps5);
    get_ver_show("before ", "kern.ps4_sdk_version", &d.temp);
    get_ver_show("before ", "kern.sdk_version", &d.temp);
    get_ver_show("before ", "machdep.upd_version", &d.temp);
    patch_fw();
    get_ver_show("after ", "kern.ps4_sdk_version", &d.temp);
    get_ver_show("after ", "kern.sdk_version", &d.temp);
    get_ver_show("after ", "machdep.upd_version", &d.temp);
    return 0;
}
