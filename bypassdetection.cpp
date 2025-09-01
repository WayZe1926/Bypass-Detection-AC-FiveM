#include <windows.h>
#include <vector>
#include <string>
#include <random>
#include <thread>
#include <TlHelp32.h>
#include <Psapi.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#pragma comment(lib, "psapi.lib")
#define LOG_BLOCKED_EVENTS     
#define SPOOF_REAL_HARDWARE    
#define MIN_WAIT_TIME_MS    8000 
#define MAX_MODULE_RETRY     10  

const char* LOG_FILE = "C:\\Temp\\blocked_events.log";


#ifdef LOG_BLOCKED_EVENTS
void LogBlockedEvent(const char* event) {
    std::ofstream log(LOG_FILE, std::ios::app);
    if (log.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        log << "[" << std::setfill('0') << std::setw(2) << st.wHour << ":"
            << std::setfill('0') << std::setw(2) << st.wMinute << ":"
            << std::setfill('0') << std::setw(2) << st.wSecond << "] "
            << "BLOCKED: " << event << std::endl;
        log.close();
    }
}
#else
void LogBlockedEvent(const char* event) { }
#endif


struct HardwareInfo {
    std::string gpuVendor;
    std::string gpuRenderer;
    int cores;
    int ramGB;
    std::string timezone;
    std::string language;
};

class HardwareSpoofer {
private:
    static std::random_device rd;
    static std::mt19937 gen;

public:
    static HardwareInfo GetSpoofedInfo() {
        MEMORYSTATUSEX memInfo{ sizeof(memInfo) };
        GlobalMemoryStatusEx(&memInfo);

        TIME_ZONE_INFORMATION tz;
        GetTimeZoneInformation(&tz);
        char tzName[256];
        WideCharToMultiByte(CP_UTF8, 0, tz.StandardName, -1, tzName, 256, nullptr, nullptr);

        HardwareInfo info = {
            .gpuVendor = "NVIDIA Corporation", 
            .gpuRenderer = "NVIDIA GeForce RTX 3060",
            .cores = std::max(4, (int)std::thread::hardware_concurrency() + (gen() % 3) - 1), // ±1
            .ramGB = static_cast<int>(memInfo.ullTotalPhys / (1024ULL * 1024 * 1024)) + (gen() % 3), // +0-2GB
            .timezone = tzName,
            .language = "en-US"
        };

        return info;
    }

    static std::string GenerateID(int len) {
        const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::string id;
        for (int i = 0; i < len; ++i)
            id += chars[gen() % 62];
        return id;
    }
};

std::random_device HardwareSpoofer::rd;
std::mt19937 HardwareSpoofer::gen(rd());


struct Tokens {
    std::string t1, t2, t3, t4;
};

Tokens GenerateTokens() {
    auto info = HardwareSpoofer::GetSpoofedInfo();

    std::string t1 = info.gpuVendor + info.gpuRenderer +
                     std::to_string(info.cores) +
                     std::to_string(info.ramGB) +
                     info.language +
                     info.timezone;

    std::string t2 = "Realtek High Definition Audio|"
                     "Headphones (USB Audio Device)|"
                     "Default Audio Endpoint";

    static std::string m_id = HardwareSpoofer::GenerateID(32);
    std::string t3 = m_id;

    std::string t4 = "t4_" + HardwareSpoofer::GenerateID(16);

    return { t1, t2, t3, t4 };
}


uintptr_t FindPattern(const char* moduleName, const char* pattern) {
    HMODULE hMod = nullptr;
    for (int i = 0; i < MAX_MODULE_RETRY; ++i) {
        hMod = GetModuleHandleA(moduleName);
        if (hMod) break;
        Sleep(200);
    }
    if (!hMod) return 0;

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo)))
        return 0;

    uintptr_t start = (uintptr_t)hMod;
    uintptr_t end = start + modInfo.SizeOfImage;

    std::vector<int> bytes;
    char* saved = nullptr;
    char patternCopy[256];
    strncpy_s(patternCopy, pattern, sizeof(patternCopy) - 1);

    for (char* tok = strtok_s(patternCopy, " ", &saved); tok; tok = strtok_s(nullptr, " ", &saved)) {
        bytes.push_back(tok[0] == '?' || tok[0] == '??' ? -1 : (int)strtol(tok, nullptr, 16));
    }

    for (uintptr_t i = start; i <= end - bytes.size(); ++i) {
        bool found = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (bytes[j] != -1 && *(BYTE*)(i + j) != (BYTE)bytes[j]) {
                found = false;
                break;
            }
        }
        if (found) return i - start;
    }
    return 0;
}


bool PatchMemory(const char* module, DWORD offset, const std::vector<BYTE>& patch) {
    HMODULE hMod = GetModuleHandleA(module);
    if (!hMod) return false;

    void* addr = (void*)((uintptr_t)hMod + offset);
    DWORD oldProtect;

    if (!VirtualProtect(addr, patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(addr, patch.data(), patch.size());

    VirtualProtect(addr, patch.size(), oldProtect, &oldProtect);
    return true;
}


LONG CALLBACK DummyVEH(EXCEPTION_POINTERS*) {
    return EXCEPTION_CONTINUE_EXECUTION;
}

void BypassVEH() {
    uintptr_t sig = FindPattern("ntdll.dll", "48 8D 3D ? ? ? ? 8A C8");
    if (!sig) return;

    int offset = *(int*)(sig + 3);
    struct { SRWLOCK Lock; LIST_ENTRY ListHead; }* pVEHList =
        (decltype(pVEHList))(sig + 7 + offset);

    if (TryAcquireSRWLockExclusive((PSRWLOCK)&pVEHList->Lock)) {
        for (LIST_ENTRY* entry = pVEHList->ListHead.Flink;
             entry != &pVEHList->ListHead;
             entry = entry->Flink) {

            struct { LIST_ENTRY Entry; PVOID Handler; }* vehEntry =
                CONTAINING_RECORD(entry, decltype(*vehEntry), Entry);

            vehEntry->Handler = EncodePointer((PVOID)DummyVEH);
        }
        ReleaseSRWLockExclusive((PSRWLOCK)&pVEHList->Lock);
    }
}

using PostEventType = void(*)(const char*, void*, void*);
PostEventType originalPostEvent = nullptr;

void HookedPostEvent(const char* event, void* data, void* callback) {
    if (!event) return;

    // Respond to heartbeats
    if (callback && (
        strstr(event, "heartbeat") ||
        strstr(event, "ping") ||
        strstr(event, "keep-alive") ||
        strstr(event, "health") ||
        strstr(event, "alive") ||
        strstr(event, "fini:hb"))) {
        ((void(*)())callback)();
        return;
    }

    if (
        strstr(event, "player_t_res") ||
        strstr(event, "fg:tokens") ||
        strstr(event, "fg_proof_check") ||
        strstr(event, "electronac:collect") ||
        strstr(event, "ws:proof") ||
        strstr(event, "reaper:scan") ||
        strstr(event, "fireac:validate") ||
        strstr(event, "proof:of:life")) {

        LogBlockedEvent(event);
        return;
    }

    if (originalPostEvent) {
        originalPostEvent(event, data, callback);
    }
}

bool InstallPostEventHook() {
    DWORD offset = (DWORD)FindPattern("citizen-resources-core.dll",
        "48 8B C4 55 41 54 41 55 41 56 41 57 48 8D 6C 24");
    if (!offset) return false;

    BYTE* target = (BYTE*)GetModuleHandleA("citizen-resources-core.dll") + offset;
    originalPostEvent = (PostEventType)target;

    DWORD old;
    if (!VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &old))
        return false;

    // mov rax, HookedPostEvent; jmp rax
    target[0] = 0x48; target[1] = 0xB8;
    *(UINT64*)&target[2] = (UINT64)HookedPostEvent;
    target[10] = 0xFF; target[11] = 0xE0;

    VirtualProtect(target, 12, old, &old);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Ensure log directory exists
#ifdef LOG_BLOCKED_EVENTS
        CreateDirectoryA("C:\\Temp", nullptr);
#endif

        // Wait for game to load
        Sleep(MIN_WAIT_TIME_MS);

        // Patch scripting engines
        if (DWORD off = (DWORD)FindPattern("citizen-scripting-lua.dll",
            "48 8B C4 48 89 48 08 55 53")) {
            PatchMemory("citizen-scripting-lua.dll", off, { 0x48, 0x31, 0xC0, 0xC3 });
        }

        if (DWORD off = (DWORD)FindPattern("citizen-resources-core.dll",
            "48 89 5C 24 ? 57 48 83 EC ?")) {
            PatchMemory("citizen-resources-core.dll", off, { 0x48, 0x31, 0xC0, 0xC3 });
        }

        BypassVEH();

        InstallPostEventHook();
    }
    return TRUE;
}