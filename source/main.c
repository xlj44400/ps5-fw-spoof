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

static void notify(const char* fmt, ...)
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
    puts(buf.message);
    sceKernelSendNotificationRequest(0, &buf, sizeof(buf), 0);
}

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

const uint32_t fw_max = 0x99999999;

static void patch_fw(const uint32_t fw, const char* fw_n, const bool upd)
{
    printf("fw 0x%08x\n", fw);
    const uint32_t fw_m[] = {fw_max};
    const uint32_t fw_a[] = {fw, 0x10001};
    const uintptr_t fw_addr = kernel_scan(
        KERNEL_ADDRESS_DATA_BASE,
        0,
        fw_a,
        upd ? sizeof(fw_a) : sizeof(uint32_t));

    if (!fw_addr)
    {
        notify("%s firmware version not found in kernel data\n", fw_n);
        return;
    }
    printf("firmware %s 0x%08x found in kernel 0x%lx\n",
           fw_n,
           fw,
           fw_addr - KERNEL_ADDRESS_DATA_BASE);
    kernel_copyin(fw_m, fw_addr, sizeof(fw_m));
    uint32_t fw_p = 0;
    kernel_copyout(fw_addr, &fw_p, sizeof(fw_p));
    printf("%s patched to 0x%08x\n", fw_n, fw_p);
}

static void get_ver(const char* pf, const char* mibn, uint32_t* out)
{
    size_t len = 4;
    *out = 0;
    sysctlbyname(mibn, out, &len, NULL, 0);
    notify("%s%s: 0x%08x\n", pf, mibn, *out);
}

int main(void)
{
    uint32_t fw = 0;
    uint32_t fw2 = 0;
    get_firmware_version_from_disk1(&fw, true);
    get_firmware_version_from_disk1(&fw2, false);
    uint32_t ps4_sdk = 0;
    get_ver("before: ", "kern.ps4_sdk_version", &ps4_sdk);
    if (ps4_sdk != fw_max)
    {
        patch_fw(fw, "PS4 SDK", false);
    }
    uint32_t ps5_sdk = 0;
    get_ver("before: ", "kern.sdk_version", &ps5_sdk);
    if (0 && ps5_sdk != fw_max)
    {
        patch_fw(fw2, "PS5 SDK", false);
        patch_fw(fw2, "PS5 SDK", false);
    }
    uint32_t upd_version = 0;
    get_ver("before: ", "machdep.upd_version", &upd_version);
    if (upd_version != fw_max)
    {
        patch_fw(upd_version, "PS5 Update", true);
    }
    get_ver("after: ", "kern.ps4_sdk_version", &ps4_sdk);
    get_ver("after: ", "kern.sdk_version", &ps5_sdk);
    get_ver("after: ", "machdep.upd_version", &upd_version);
    return 0;
}
