/*
 * ce_mcp_tcp.dll - Native TCP Bridge for Cheat Engine MCP
 *
 * Two operating modes:
 *   1. Native Lua API mode: resolves lua_pushstring etc. and registers global
 *      functions (mcp_tcp_start/stop/poll/respond/status).
 *   2. File IPC mode (fallback): when Lua API cannot be resolved, the DLL
 *      starts TCP itself and exchanges commands/responses via temp files.
 *      Lua polls %TEMP%\ce_mcp\cmd.txt and writes resp.txt.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

/* ---------- Debug Console ---------- */

static HANDLE g_console = NULL;
static FILE  *g_logfp   = NULL;
static HMODULE g_self_module = NULL;

static void dbg_init(void) {
    if (g_console) return;
    AllocConsole();
    /* v3.3.4: the conhost window steals foreground focus on creation, which
     * blocks interaction with CE's own windows. Default is now HIDDEN --
     * WriteConsoleA still buffers into a hidden console, so no log text is
     * lost. Set CE_MCP_DEBUG_CONSOLE=1 to see it; SW_SHOWNOACTIVATE means
     * even that path never takes focus away from CE. */
    {
        char dbgEnv[8] = {0};
        BOOL show = GetEnvironmentVariableA("CE_MCP_DEBUG_CONSOLE", dbgEnv,
                                            sizeof(dbgEnv)) > 0
                    && dbgEnv[0] == '1';
        HWND cw = GetConsoleWindow();
        if (cw) ShowWindow(cw, show ? SW_SHOWNOACTIVATE : SW_HIDE);
    }
    SetConsoleTitleA("[MCP] ce_mcp_tcp.dll - Debug Console");
    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    freopen_s(&g_logfp, "CONOUT$", "w", stdout);
}

static void dbg_log(const char *fmt, ...) {
    if (!g_console) dbg_init();
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf[n] = '\n';
        buf[n + 1] = '\0';
        DWORD written;
        WriteConsoleA(g_console, buf, n + 1, &written, NULL);
    }
}

/* ---------- Lua API runtime binding ---------- */

typedef struct lua_State lua_State;
typedef int (*lua_CFunction)(lua_State *L);
typedef long long lua_Integer;

static const char* (*pL_pushstring)(lua_State*, const char*);
static void        (*pL_pushinteger)(lua_State*, lua_Integer);
static void        (*pL_pushnil)(lua_State*);
static void        (*pL_pushboolean)(lua_State*, int);
static const char* (*pL_tolstring)(lua_State*, int, size_t*);
static lua_Integer (*pL_tointegerx)(lua_State*, int, int*);
static int         (*pL_gettop)(lua_State*);
static void        (*pL_settop)(lua_State*, int);
static void        (*pL_setglobal)(lua_State*, const char*);
static void        (*pL_pushcclosure)(lua_State*, lua_CFunction, int);
static int         (*pL_isstring)(lua_State*, int);
static int         (*pL_isnumber)(lua_State*, int);
static void        (*pL_createtable)(lua_State*, int, int);
static void        (*pL_setfield)(lua_State*, int, const char*);
static int         (*pL_getglobal)(lua_State*, const char*);
static int         (*pL_pcallk)(lua_State*, int, int, int, long long, void*);
static int         (*pL_error)(lua_State*);

static int lua_api_ready = 0;


typedef struct {
    const char *name;
    void       **ptr;
} LuaApiEntry;

static int try_resolve_from_module(HMODULE mod, const char *modName, LuaApiEntry *entries, int count) {
    int found = 0;
    for (int i = 0; i < count; i++) {
        void *addr = (void*)GetProcAddress(mod, entries[i].name);
        if (addr) {
            *(entries[i].ptr) = addr;
            found++;
        }
    }
    if (found > 0)
        dbg_log("[MCP-DLL]   %s => %d/%d functions", modName, found, count);
    return found;
}

static int resolve_lua_api(void) {
    LuaApiEntry entries[] = {
        { "lua_pushstring",  (void**)&pL_pushstring   },
        { "lua_pushinteger", (void**)&pL_pushinteger  },
        { "lua_pushnil",     (void**)&pL_pushnil      },
        { "lua_pushboolean", (void**)&pL_pushboolean  },
        { "lua_tolstring",   (void**)&pL_tolstring    },
        { "lua_tointegerx",  (void**)&pL_tointegerx   },
        { "lua_gettop",      (void**)&pL_gettop       },
        { "lua_settop",      (void**)&pL_settop       },
        { "lua_setglobal",   (void**)&pL_setglobal    },
        { "lua_pushcclosure",(void**)&pL_pushcclosure },
        { "lua_isstring",    (void**)&pL_isstring     },
        { "lua_isnumber",    (void**)&pL_isnumber     },
        { "lua_createtable", (void**)&pL_createtable  },
        { "lua_setfield",    (void**)&pL_setfield     },
        { "lua_getglobal",   (void**)&pL_getglobal    },
        { "lua_pcallk",      (void**)&pL_pcallk       },
        { "lua_error",       (void**)&pL_error        },
    };
    int total = sizeof(entries) / sizeof(entries[0]);
    int best_count = 0;
    char best_name[260] = {0};

    dbg_log("[MCP-DLL] Resolving Lua API (%d functions)...", total);

    const char* known[] = {
        "lua54.dll", "lua53.dll", "lua5.4.dll", "lua5.3.dll",
        "lua54-64.dll", "lua53-64.dll", "lua5.4-64.dll", "lua5.3-64.dll",
        "lua53-32.dll", "lua54-32.dll",
        NULL
    };

    /* Phase 1: well-known Lua DLL names */
    char selfDir[MAX_PATH] = {0};
    if (g_self_module) {
        GetModuleFileNameA(g_self_module, selfDir, MAX_PATH);
        char *sep = strrchr(selfDir, '\\');
        if (sep) *(sep + 1) = '\0'; else selfDir[0] = '\0';
    }

    for (int i = 0; known[i]; i++) {
        HMODULE mod = GetModuleHandleA(known[i]);
        if (!mod) {
            /* Try full path from DLL's directory first */
            if (selfDir[0]) {
                char fullp[MAX_PATH];
                _snprintf(fullp, MAX_PATH, "%s%s", selfDir, known[i]);
                mod = LoadLibraryA(fullp);
            }
        }
        if (!mod) mod = LoadLibraryA(known[i]);
        if (!mod) continue;
        dbg_log("[MCP-DLL] Found module: %s", known[i]);
        int n = try_resolve_from_module(mod, known[i], entries, total);
        if (n == total) { lua_api_ready = 1; return 1; }
        if (n > best_count) { best_count = n; snprintf(best_name, sizeof(best_name), "%s", known[i]); }
    }

    /* Phase 2: main executable */
    {
        HMODULE mainExe = GetModuleHandleA(NULL);
        if (mainExe) {
            int n = try_resolve_from_module(mainExe, "(main exe)", entries, total);
            if (n == total) { lua_api_ready = 1; return 1; }
            if (n > best_count) { best_count = n; snprintf(best_name, sizeof(best_name), "%s", "(main exe)"); }
        }
    }

    /* Phase 3: enumerate every loaded module */
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me;
            me.dwSize = sizeof(me);
            int moduleCount = 0;
            if (Module32First(snap, &me)) {
                do {
                    moduleCount++;
                    HMODULE mod = me.hModule;
                    if (!mod) continue;
                    if (!GetProcAddress(mod, "lua_pushstring")) continue;
                    int n = try_resolve_from_module(mod, me.szModule, entries, total);
                    if (n == total) { CloseHandle(snap); lua_api_ready = 1; return 1; }
                    if (n > best_count) { best_count = n; snprintf(best_name, sizeof(best_name), "%s", me.szModule); }
                } while (Module32Next(snap, &me));
            }
            dbg_log("[MCP-DLL] Enumerated %d modules, best: %d/%d", moduleCount, best_count, total);
            CloseHandle(snap);
        }
    }

    /* Phase 4: scan OUR DLL's directory for lua*.dll (DLL is placed in CE dir) */
    {
        char dllPath[MAX_PATH] = {0};
        GetModuleFileNameA(g_self_module, dllPath, MAX_PATH);
        char *lastSep = strrchr(dllPath, '\\');
        if (!lastSep) lastSep = strrchr(dllPath, '/');
        if (lastSep) {
            char exeDir[MAX_PATH];
            int dirLen = (int)(lastSep - dllPath);
            strncpy(exeDir, dllPath, dirLen);
            exeDir[dirLen] = '\0';
            dbg_log("[MCP-DLL] DLL dir (CE dir): %s", exeDir);

            char searchPattern[MAX_PATH];
            _snprintf(searchPattern, MAX_PATH, "%s\\lua*.dll", exeDir);

            WIN32_FIND_DATAA fd;
            HANDLE hFind = FindFirstFileA(searchPattern, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    char fullPath[MAX_PATH];
                    _snprintf(fullPath, MAX_PATH, "%s\\%s", exeDir, fd.cFileName);
                    dbg_log("[MCP-DLL] Found lua DLL: %s", fd.cFileName);

                    HMODULE mod = GetModuleHandleA(fd.cFileName);
                    if (!mod) mod = LoadLibraryA(fullPath);
                    if (mod) {
                        int n = try_resolve_from_module(mod, fd.cFileName, entries, total);
                        if (n == total) {
                            dbg_log("[MCP-DLL] All Lua API resolved from: %s", fd.cFileName);
                            FindClose(hFind);
                            lua_api_ready = 1;
                            return 1;
                        }
                        if (n > best_count) { best_count = n; snprintf(best_name, sizeof(best_name), "%s", fd.cFileName); }
                    } else {
                        dbg_log("[MCP-DLL]   LoadLibrary failed for %s (err=%lu)", fd.cFileName, GetLastError());
                    }
                } while (FindNextFileA(hFind, &fd));
                FindClose(hFind);
            } else {
                dbg_log("[MCP-DLL] No lua*.dll found in CE dir");
            }

            /* Also try the main exe by full path (some Delphi apps export from exe) */
            {
                HMODULE mainMod = GetModuleHandleA(NULL);
                if (mainMod) {
                    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)mainMod;
                    if (dos->e_magic == 0x5A4D) {
                        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((char*)mainMod + dos->e_lfanew);
                        DWORD expRVA = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
                        if (expRVA) {
                            IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)((char*)mainMod + expRVA);
                            DWORD *names_arr = (DWORD*)((char*)mainMod + exp->AddressOfNames);
                            int luaCount = 0;
                            for (DWORD i = 0; i < exp->NumberOfNames && i < 10000; i++) {
                                const char *nm = (const char*)mainMod + names_arr[i];
                                if (nm[0]=='l' && nm[1]=='u' && nm[2]=='a' && nm[3]=='_') {
                                    luaCount++;
                                    if (luaCount <= 5) dbg_log("[MCP-DLL]   exe export: %s", nm);
                                }
                            }
                            dbg_log("[MCP-DLL] Main exe: %d lua_* exports (%lu total)", luaCount, exp->NumberOfNames);
                        } else {
                            dbg_log("[MCP-DLL] Main exe: no export directory");
                        }
                    }
                }
            }
        }
    }

    /* Partial match with critical functions is acceptable */
    if (pL_pushstring && pL_pushinteger && pL_pushnil &&
        pL_pushboolean && pL_tolstring && pL_tointegerx &&
        pL_gettop && pL_settop && pL_setglobal &&
        pL_pushcclosure && pL_createtable && pL_setfield) {
        dbg_log("[MCP-DLL] Core Lua API resolved (some optional missing)");
        lua_api_ready = 1;
        return 1;
    }

    dbg_log("[MCP-DLL] Lua API resolution FAILED (%d/%d from %s)",
            best_count, total, best_count > 0 ? best_name : "none");
    return 0;
}

/* Convenience wrappers */
static void lua_pushstr(lua_State *L, const char *s) { pL_pushstring(L, s); }
static void lua_pushint(lua_State *L, lua_Integer v) { pL_pushinteger(L, v); }
static void lua_pushbool(lua_State *L, int b) { pL_pushboolean(L, b); }
static void lua_pushnothing(lua_State *L) { pL_pushnil(L); }
static const char* lua_getstr(lua_State *L, int idx) { return pL_tolstring(L, idx, NULL); }
static lua_Integer lua_getint(lua_State *L, int idx) { return pL_tointegerx(L, idx, NULL); }
static int lua_nargs(lua_State *L) { return pL_gettop(L); }

static void lua_newtable(lua_State *L) { pL_createtable(L, 0, 4); }
static void lua_setstrfield(lua_State *L, int idx, const char *k, const char *v) {
    lua_pushstr(L, v);
    pL_setfield(L, idx < 0 ? idx - 1 : idx, k);
}
static void lua_setintfield(lua_State *L, int idx, const char *k, lua_Integer v) {
    lua_pushint(L, v);
    pL_setfield(L, idx < 0 ? idx - 1 : idx, k);
}
static void lua_setboolfield(lua_State *L, int idx, const char *k, int v) {
    lua_pushbool(L, v);
    pL_setfield(L, idx < 0 ? idx - 1 : idx, k);
}
static void lua_register_func(lua_State *L, const char *name, lua_CFunction f) {
    pL_pushcclosure(L, f, 0);
    pL_setglobal(L, name);
}

/* ---------- JSON method extractor ---------- */

static const char* extract_json_method(const char *json, char *out, int outLen) {
    const char *key = "\"method\"";
    const char *p = strstr(json, key);
    if (!p) { out[0] = '\0'; return out; }
    p += strlen(key);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') { out[0] = '\0'; return out; }
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outLen - 1) out[i++] = *p++;
    out[i] = '\0';
    return out;
}

/* ---------- v3.3.0: DLL fast path (dll_* methods, server-thread handled) ----
 *
 * CE executes all Lua on its main thread. While a modal dialog (messageDialog,
 * inputQuery, ...) blocks that thread, the Lua timer cannot fire, the queue is
 * never drained, and every queued command times out from the outside. The DLL's
 * server thread, however, is independent. Methods with the "dll_" prefix are
 * answered HERE -- parsed, executed and replied inline, never queued for Lua:
 *
 *   dll_ping            always-available health probe
 *   dll_status          counters + poll_age_ms -> detects "Lua frozen" precisely
 *   dll_enum_dialogs    EnumWindows of this process (modal detection)
 *   dll_dismiss_dialog  PostMessageW(WM_CLOSE) a dialog, guarded by class name
 *
 * poll_age_ms: l_mcp_tcp_poll is called every 1 ms by the Lua timer. A large
 * age means the main thread stopped servicing the bridge -- blocked by a modal
 * dialog OR running a long command; dll_enum_dialogs disambiguates the two.
 */

#define DLL_VERSION   "3.3.4"
#define LUA_RESPONSIVE_THRESHOLD_MS 5000
#define MAX_DIALOGS   64

static volatile LONG g_last_lua_poll_tick = 0;   /* GetTickCount of last Lua poll */
static volatile LONG g_frames_rx = 0, g_frames_tx = 0;
static volatile LONG g_bytes_rx  = 0, g_bytes_tx  = 0;
static DWORD g_dll_start_tick = 0;
static char g_last_method[128] = {0};            /* guarded by g_lm_lock */
static SRWLOCK g_lm_lock = SRWLOCK_INIT;         /* statically initialized */

static void counters_add(volatile LONG *dst, LONG delta) {
    InterlockedExchangeAdd(dst, delta);
}

/* --- minimal JSON parsing (mirrors the client's actual payload shape) --- */

static const char* json_skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

/* Find "key" and copy its string value. Returns 1 on success. */
static int json_extract_string(const char *json, const char *key, char *out, int outLen) {
    char pat[64];
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p = json_skip_ws(p + strlen(pat));
    if (*p != ':') return 0;
    p = json_skip_ws(p + 1);
    if (*p != '"') return 0;
    p++;
    int i = 0;
    while (*p && *p != '"' && i < outLen - 1) {
        /* unescape the two escapes the client actually sends */
        if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) { out[i++] = *++p; p++; }
        else out[i++] = *p++;
    }
    out[i] = '\0';
    return 1;
}

/* Find "key" and parse an integer value. Returns 1 on success. */
static int json_extract_int(const char *json, const char *key, int *out) {
    char pat[64];
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p = json_skip_ws(p + strlen(pat));
    if (*p != ':') return 0;
    p = json_skip_ws(p + 1);
    if (*p != '-' && (*p < '0' || *p > '9')) return 0;
    /* strtol with clamping: atoi on out-of-range input is UB. */
    *out = (int)strtol(p, NULL, 10);
    return 1;
}

/* Find "key" and parse a 64-bit integer value. HWNDs are sign-extended
 * 32-bit values, so their unsigned decimal form does not always fit in a
 * 32-bit int; atoi on such input overflows (undefined behaviour). */
static int json_extract_i64(const char *json, const char *key, long long *out) {
    char pat[64];
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p = json_skip_ws(p + strlen(pat));
    if (*p != ':') return 0;
    p = json_skip_ws(p + 1);
    if (*p != '-' && (*p < '0' || *p > '9')) return 0;
    /* _strtoi64 clamps to LLONG_MIN/LLONG_MAX on overflow (sets ERANGE),
     * unlike _atoi64 which is UB on out-of-range input. */
    *out = _strtoi64(p, NULL, 10);
    return 1;
}

/* Find "key" and parse a boolean. Returns 1 on success. */
static int json_extract_bool(const char *json, const char *key, int *out) {
    char pat[64];
    _snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    p = json_skip_ws(p + strlen(pat));
    if (*p != ':') return 0;
    p = json_skip_ws(p + 1);
    if (strncmp(p, "true", 4) == 0)  { *out = 1; return 1; }
    if (strncmp(p, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
}

/* Extract the request id verbatim (number, string, or null) for the envelope. */
static void json_extract_id(const char *json, char *out, int outLen) {
    const char *p = strstr(json, "\"id\"");
    if (!p) { _snprintf(out, outLen, "null"); return; }
    p = json_skip_ws(p + 4);
    if (*p != ':') { _snprintf(out, outLen, "null"); return; }
    p = json_skip_ws(p + 1);
    int i = 0;
    if (*p == '"') {
        out[i++] = '"';
        p++;
        while (*p && *p != '"' && i < outLen - 2) {
            if (*p == '\\' && p[1]) { out[i++] = *p++; out[i++] = *p++; }
            else out[i++] = *p++;
        }
        out[i++] = '"';
        out[i] = '\0';
    } else {
        while (*p && *p != ',' && *p != '}' && i < outLen - 1) out[i++] = *p++;
        out[i] = '\0';
        if (i == 0) _snprintf(out, outLen, "null");
    }
}

/* Escape a UTF-8 string for embedding in JSON (quotes, backslash, controls). */
static void json_escape(const char *in, char *out, int outLen) {
    int i = 0;
    while (*in && i < outLen - 2) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[i++] = '\\'; out[i++] = (char)c; in++;
        } else if (c < 0x20) {
            i += _snprintf(out + i, outLen - i, "\\u%04x", c);
            in++;
        } else {
            out[i++] = (char)c; in++;
        }
    }
    out[i] = '\0';
}

/* UTF-16 -> UTF-8 (titles come from Win32 W APIs). */
static void utf16_to_utf8(const wchar_t *w, char *out, int outLen) {
    out[0] = '\0';
    if (!w) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outLen, NULL, NULL);
    out[outLen - 1] = '\0';
}

/* --- window enumeration (this process only, top-level, visible) --- */

typedef struct {
    char   buf[16384];       /* pre-rendered JSON array body */
    int    count;
    HWND   hwnds[MAX_DIALOGS];
} DialogList;

static BOOL CALLBACK enum_dialog_proc(HWND hwnd, LPARAM lp) {
    DialogList *dl = (DialogList*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    if (!IsWindowVisible(hwnd)) return TRUE;

    wchar_t wcls[64], wtitle[192];
    GetClassNameW(hwnd, wcls, 64);
    GetWindowTextW(hwnd, wtitle, 192);

    char cls[128], title[512], escCls[192], escTitle[768];
    utf16_to_utf8(wcls, cls, sizeof(cls));
    utf16_to_utf8(wtitle, title, sizeof(title));

    /* our own debug console is noise for the agent */
    if (strcmp(cls, "ConsoleWindowClass") == 0) return TRUE;

    json_escape(cls, escCls, sizeof(escCls));
    json_escape(title, escTitle, sizeof(escTitle));

    int n = _snprintf(dl->buf + strlen(dl->buf),
                      sizeof(dl->buf) - strlen(dl->buf) - 1,
                      "%s{\"index\":%d,\"hwnd\":%lu,\"class\":\"%s\",\"title\":\"%s\",\"enabled\":%s}",
                      dl->count ? "," : "",
                      dl->count, (unsigned long)(uintptr_t)hwnd, escCls, escTitle,
                      IsWindowEnabled(hwnd) ? "true" : "false");
    if (n < 0) return FALSE; /* buffer full */
    dl->hwnds[dl->count] = hwnd;
    dl->count++;
    return dl->count < MAX_DIALOGS ? TRUE : FALSE;
}

static void enumerate_dialogs(DialogList *dl) {
    memset(dl, 0, sizeof(*dl));
    dl->buf[0] = '[';
    EnumWindows(enum_dialog_proc, (LPARAM)dl);
    size_t len = strlen(dl->buf);
    _snprintf(dl->buf + len, sizeof(dl->buf) - len, "]");
}

/* Refuse to close windows that would kill or lobotomize CE itself. */
static int is_protected_class(const char *cls) {
    return strcmp(cls, "TApplication") == 0 ||
           strcmp(cls, "TMainForm") == 0;
}

/* --- fast-path envelope --- */

static char* fastpath_envelope(const char *idToken, const char *resultJson) {
    size_t cap = strlen(resultJson) + strlen(idToken) + 64;
    char *out = (char*)malloc(cap);
    if (!out) return NULL;
    _snprintf(out, cap, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":%s}",
              idToken, resultJson);
    return out;
}

static char* fp_dll_ping(const char *id) {
    char result[192];
    _snprintf(result, sizeof(result),
              "{\"success\":true,\"component\":\"dll\",\"version\":\"" DLL_VERSION "\","
              "\"uptime_ms\":%lu}",
              (unsigned long)(GetTickCount() - g_dll_start_tick));
    return fastpath_envelope(id, result);
}

static char* fp_dll_status(const char *id) {
    char result[640], escMethod[192];
    DWORD now = GetTickCount();
    DWORD last = (DWORD)g_last_lua_poll_tick;
    long age = (last == 0) ? -1 : (long)(now - last);
    int responsive = (last != 0) && (now - last) < LUA_RESPONSIVE_THRESHOLD_MS;

    AcquireSRWLockShared(&g_lm_lock);
    json_escape(g_last_method, escMethod, sizeof(escMethod));
    ReleaseSRWLockShared(&g_lm_lock);

    _snprintf(result, sizeof(result),
              "{\"success\":true,\"component\":\"dll\",\"version\":\"" DLL_VERSION "\","
              "\"uptime_ms\":%lu,\"frames_rx\":%ld,\"frames_tx\":%ld,"
              "\"bytes_rx\":%ld,\"bytes_tx\":%ld,"
              "\"last_method\":\"%s\",\"poll_age_ms\":%ld,"
              "\"lua_responsive\":%s,"
              "\"note\":\"poll_age_ms is time since the CE main thread last "
              "called mcp_tcp_poll; a large value means the main thread is "
              "blocked or busy - call dll_enum_dialogs to check for a modal\"}",
              (unsigned long)(now - g_dll_start_tick),
              g_frames_rx, g_frames_tx, g_bytes_rx, g_bytes_tx,
              escMethod, age,
              responsive ? "true" : "false");
    return fastpath_envelope(id, result);
}

static char* fp_dll_enum_dialogs(const char *id) {
    DialogList dl;
    enumerate_dialogs(&dl);
    char result[17100];
    _snprintf(result, sizeof(result),
              "{\"success\":true,\"count\":%d,\"dialogs\":%s,"
              "\"hint\":\"enabled:false windows are disabled owners; a modal "
              "is usually an enabled dialog whose parent is disabled. Close "
              "with dll_dismiss_dialog (index/hwnd/title). TMainForm and "
              "TApplication are protected.\"}",
              dl.count, dl.buf);
    return fastpath_envelope(id, result);
}

static char* fp_dll_dismiss(const char *cmd, const char *id) {
    int idx = -1, haveIdx = json_extract_int(cmd, "index", &idx);
    long long hwndLL = 0; int haveHwnd = json_extract_i64(cmd, "hwnd", &hwndLL);
    char title[256]; int haveTitle = json_extract_string(cmd, "title", title, sizeof(title));
    int force = 0; json_extract_bool(cmd, "force", &force);

    if (!haveIdx && !haveHwnd && !haveTitle) {
        char *r = fastpath_envelope(id, "{\"success\":false,"
            "\"error\":\"need one of: index, hwnd, title\",\"error_code\":\"INVALID_PARAMS\"}");
        return r;
    }

    DialogList dl;
    enumerate_dialogs(&dl);

    HWND target = NULL;
    if (haveHwnd) {
        /* USER handles are sign-extended 32-bit values: truncate to 32 bits
         * and sign-extend back so the round trip through the client's decimal
         * form is lossless regardless of how the handle was printed. */
        target = (HWND)(LONG_PTR)(LONG)(unsigned int)(unsigned long long)hwndLL;
        DWORD pid = 0;
        GetWindowThreadProcessId(target, &pid);
        if (pid != GetCurrentProcessId() || !IsWindow(target)) {
            return fastpath_envelope(id, "{\"success\":false,"
                   "\"error\":\"hwnd is not a window of this process\","
                   "\"error_code\":\"INVALID_TARGET\"}");
        }
    } else if (haveTitle) {
        /* case-insensitive substring match on window title (fold the needle
         * once, outside the loop) */
        char needle[512];
        _snprintf(needle, sizeof(needle), "%s", title);
        for (char *c = needle; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
        for (int i = 0; i < dl.count && !target; i++) {
            char t[512];
            wchar_t wt[192];
            GetWindowTextW(dl.hwnds[i], wt, 192);
            utf16_to_utf8(wt, t, sizeof(t));
            for (char *c = t; *c; c++) if (*c >= 'A' && *c <= 'Z') *c += 32;
            if (strstr(t, needle)) target = dl.hwnds[i];
        }
        if (!target) {
            return fastpath_envelope(id, "{\"success\":false,"
                   "\"error\":\"no window title matches\",\"error_code\":\"NOT_FOUND\"}");
        }
    } else if (haveIdx) {
        if (idx < 0 || idx >= dl.count) {
            return fastpath_envelope(id, "{\"success\":false,"
                   "\"error\":\"index out of range\",\"error_code\":\"INVALID_TARGET\"}");
        }
        target = dl.hwnds[idx];
    }

    wchar_t wcls[64];
    char cls[128];
    GetClassNameW(target, wcls, 64);
    utf16_to_utf8(wcls, cls, sizeof(cls));
    if (is_protected_class(cls) && !force) {
        char *r = (char*)malloc(512);
        if (r) _snprintf(r, 512, "{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":"
                 "{\"success\":false,\"error\":\"refusing to close protected "
                 "window class '%s' (pass force=true to override)\","
                 "\"error_code\":\"PROTECTED_WINDOW\"}}", id, cls);
        return r;
    }

    BOOL posted = PostMessageW(target, WM_CLOSE, 0, 0);
    char result[512];
    _snprintf(result, sizeof(result),
              "{\"success\":true,\"posted\":%s,\"hwnd\":%lu,\"class\":\"%s\"}",
              posted ? "true" : "false", (unsigned long)(uintptr_t)target, cls);
    return fastpath_envelope(id, result);
}

/* Dispatch a dll_* frame on the server thread. Returns a malloc'd response or
 * NULL on OOM (caller sends a generic error). Never touches the Lua queue. */
static char* handle_dll_fastpath(const char *cmd, const char *method) {
    char idTok[48];
    json_extract_id(cmd, idTok, sizeof(idTok));

    if      (strcmp(method, "dll_ping")           == 0) return fp_dll_ping(idTok);
    else if (strcmp(method, "dll_status")         == 0) return fp_dll_status(idTok);
    else if (strcmp(method, "dll_enum_dialogs")   == 0) return fp_dll_enum_dialogs(idTok);
    else if (strcmp(method, "dll_dismiss_dialog") == 0) return fp_dll_dismiss(cmd, idTok);

    char result[256];
    _snprintf(result, sizeof(result),
              "{\"success\":false,\"error\":\"unknown dll_ method '%s'\","
              "\"error_code\":\"UNKNOWN_METHOD\"}", method);
    return fastpath_envelope(idTok, result);
}

/* ---------- TCP Server ---------- */

#define MAX_CMD_SIZE   (4 * 1024 * 1024)
#define MAX_RESP_SIZE  (4 * 1024 * 1024)
#define MAX_PORT_RANGE 10
#define SELECT_TIMEOUT_SEC 1

typedef struct {
    volatile int running;
    volatile int listening;
    volatile int connected;
    int listen_port;

    SOCKET listen_sock;
    SOCKET client_sock;

    HANDLE thread;
    DWORD  thread_id;

    CRITICAL_SECTION cs;
    char  *cmd_buf;
    int    cmd_len;
    volatile int cmd_ready;

    char  *resp_buf;
    int    resp_len;
    volatile int resp_ready;
    HANDLE resp_event;

    char bind_addr[64];
    int  base_port;
    int  max_port;
} TcpBridge;

static TcpBridge g_bridge = {0};
static int g_wsa_init = 0;
static volatile int g_bridge_initialized = 0;

static int wsa_startup(void) {
    if (g_wsa_init) return 1;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
    g_wsa_init = 1;
    return 1;
}

static int tcp_send_frame(SOCKET s, const char *data, int len) {
    unsigned char hdr[4];
    hdr[0] = (unsigned char)(len & 0xFF);
    hdr[1] = (unsigned char)((len >> 8) & 0xFF);
    hdr[2] = (unsigned char)((len >> 16) & 0xFF);
    hdr[3] = (unsigned char)((len >> 24) & 0xFF);

    int sent = 0;
    while (sent < 4) {
        int n = send(s, (char*)hdr + sent, 4 - sent, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, len - sent, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    return 1;
}

static int tcp_recv_exact(SOCKET s, char *buf, int len, int timeout_ms) {
    int total = 0;
    DWORD start = GetTickCount();
    while (total < len) {
        fd_set rd;
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        FD_ZERO(&rd);
        FD_SET(s, &rd);
        int sel = select(0, &rd, NULL, NULL, &tv);
        if (sel < 0) return -1;
        if (sel == 0) {
            if (!g_bridge.running) return -1;
            if (timeout_ms > 0 && (int)(GetTickCount() - start) > timeout_ms)
                return -1;
            continue;
        }
        int n = recv(s, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static char* tcp_recv_frame(SOCKET s, int *out_len) {
    unsigned char hdr[4];
    if (tcp_recv_exact(s, (char*)hdr, 4, 600000) != 4) return NULL;
    int len = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16) | (hdr[3] << 24);
    if (len <= 0 || len > MAX_CMD_SIZE) return NULL;
    char *buf = (char*)malloc(len + 1);
    if (!buf) return NULL;
    if (tcp_recv_exact(s, buf, len, 600000) != len) { free(buf); return NULL; }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

static DWORD WINAPI tcp_server_thread(LPVOID param) {
    TcpBridge *br = (TcpBridge*)param;
    dbg_log("[MCP-DLL] TCP server thread started");

    br->listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (br->listen_sock == INVALID_SOCKET) {
        dbg_log("[MCP-DLL] ERROR: socket() failed, err %d", WSAGetLastError());
        br->running = 0;
        return 1;
    }

    int optval = 1;
    setsockopt(br->listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(br->bind_addr);

    int bound = 0;
    for (int p = br->base_port; p <= br->max_port; p++) {
        addr.sin_port = htons((u_short)p);
        if (bind(br->listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            br->listen_port = p;
            bound = 1;
            break;
        }
    }
    if (!bound) {
        dbg_log("[MCP-DLL] ERROR: bind failed on ports %d-%d", br->base_port, br->max_port);
        closesocket(br->listen_sock);
        br->listen_sock = INVALID_SOCKET;
        br->running = 0;
        return 2;
    }

    if (listen(br->listen_sock, 1) != 0) {
        dbg_log("[MCP-DLL] ERROR: listen() failed");
        closesocket(br->listen_sock);
        br->listen_sock = INVALID_SOCKET;
        br->running = 0;
        return 3;
    }

    dbg_log("[MCP-DLL] Listening on %s:%d (THREADED mode)",
            br->bind_addr, br->listen_port);
    br->listening = 1;

    while (br->running) {
        fd_set rd;
        struct timeval tv;
        tv.tv_sec = SELECT_TIMEOUT_SEC;
        tv.tv_usec = 0;
        FD_ZERO(&rd);
        FD_SET(br->listen_sock, &rd);

        int sel = select(0, &rd, NULL, NULL, &tv);
        if (sel <= 0) continue;

        SOCKET cs = accept(br->listen_sock, NULL, NULL);
        if (cs == INVALID_SOCKET) continue;

        int one = 1;
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));
        setsockopt(cs, SOL_SOCKET, SO_KEEPALIVE, (char*)&one, sizeof(one));

        br->client_sock = cs;
        br->connected = 1;
        dbg_log("[MCP-DLL] Client connected");

        while (br->running && br->connected) {
            int cmd_len = 0;
            char *cmd = tcp_recv_frame(cs, &cmd_len);
            if (!cmd) { br->connected = 0; break; }

            {
                char method[128];
                extract_json_method(cmd, method, sizeof(method));

                counters_add(&g_frames_rx, 1);
                counters_add(&g_bytes_rx, cmd_len);
                AcquireSRWLockExclusive(&g_lm_lock);
                _snprintf(g_last_method, sizeof(g_last_method), "%s",
                          method[0] ? method : "(unknown)");
                ReleaseSRWLockExclusive(&g_lm_lock);

                /* Fast path: dll_* methods are answered on this thread and
                 * never queued for Lua -- they must work exactly when CE's
                 * main thread (and therefore Lua) is blocked or busy. */
                if (strncmp(method, "dll_", 4) == 0) {
                    dbg_log("[MCP-DLL] CMD: %s (fastpath)", method);
                    char *resp = handle_dll_fastpath(cmd, method);
                    if (resp) {
                        int respLen = (int)strlen(resp);
                        tcp_send_frame(cs, resp, respLen);
                        counters_add(&g_frames_tx, 1);
                        counters_add(&g_bytes_tx, respLen);
                        free(resp);
                    } else {
                        const char *oom = "{\"jsonrpc\":\"2.0\",\"id\":null,"
                                          "\"result\":{\"success\":false,\"error\":\"dll fastpath oom\"}}";
                        tcp_send_frame(cs, oom, (int)strlen(oom));
                    }
                    continue;
                }

                dbg_log("[MCP-DLL] CMD: %s", method[0] ? method : "(unknown)");

                ResetEvent(br->resp_event);
                EnterCriticalSection(&br->cs);
                if (br->cmd_buf) free(br->cmd_buf);
                br->cmd_buf = cmd;
                br->cmd_len = cmd_len;
                br->resp_ready = 0;
                br->cmd_ready = 1;
                LeaveCriticalSection(&br->cs);

                DWORD wait = WaitForSingleObject(br->resp_event, 120000);
                if (wait != WAIT_OBJECT_0 || !br->resp_ready) {
                    dbg_log("[MCP-DLL] RSP: %s -> TIMEOUT (dropping client)",
                            method[0] ? method : "(unknown)");
                    const char *err = "{\"error\":\"timeout waiting for command handler\"}";
                    tcp_send_frame(cs, err, (int)strlen(err));
                    /* A late Lua response would otherwise be paired with the NEXT
                     * command (stale-response crossover). Industry standard for
                     * protocol desync is teardown: drop the connection. The client
                     * reconnects cleanly on its next call. */
                    br->connected = 0;
                    break;
                }

                EnterCriticalSection(&br->cs);
                if (br->resp_buf && br->resp_len > 0) {
                    dbg_log("[MCP-DLL] RSP: %s -> OK (%d bytes)", method[0] ? method : "(unknown)", br->resp_len);
                    tcp_send_frame(cs, br->resp_buf, br->resp_len);
                    counters_add(&g_frames_tx, 1);
                    counters_add(&g_bytes_tx, br->resp_len);
                    free(br->resp_buf);
                    br->resp_buf = NULL;
                    br->resp_len = 0;
                }
                br->resp_ready = 0;
                LeaveCriticalSection(&br->cs);
            }
        }

        dbg_log("[MCP-DLL] Client disconnected");
        /* l_mcp_tcp_stop may already have closed this socket from the Lua
         * thread (it closes client_sock to wake us out of select/recv).
         * Closing the same handle twice is undefined behaviour -- the value
         * can even have been reused for a fresh socket in between -- so only
         * close it when the slot still holds exactly this handle. */
        if (br->client_sock == cs)
            closesocket(cs);
        br->client_sock = INVALID_SOCKET;
        br->connected = 0;
    }

    if (br->listen_sock != INVALID_SOCKET) {
        closesocket(br->listen_sock);
        br->listen_sock = INVALID_SOCKET;
    }
    br->listening = 0;
    br->running = 0;
    return 0;
}

/* Start TCP server (shared by both modes) */
static int start_tcp_server(int base_port, const char *bind_addr) {
    if (!wsa_startup()) {
        dbg_log("[MCP-DLL] ERROR: WSAStartup failed");
        return 0;
    }

    memset(&g_bridge, 0, sizeof(g_bridge));
    InitializeCriticalSection(&g_bridge.cs);
    g_bridge.resp_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_bridge.listen_sock = INVALID_SOCKET;
    g_bridge.client_sock = INVALID_SOCKET;
    g_bridge_initialized = 1;
    g_bridge.base_port = base_port;
    g_bridge.max_port = base_port + MAX_PORT_RANGE - 1;
    _snprintf(g_bridge.bind_addr, sizeof(g_bridge.bind_addr), "%s", bind_addr);
    g_bridge.running = 1;
    g_dll_start_tick = GetTickCount();

    g_bridge.thread = CreateThread(NULL, 0, tcp_server_thread, &g_bridge, 0, &g_bridge.thread_id);
    if (!g_bridge.thread) {
        g_bridge.running = 0;
        DeleteCriticalSection(&g_bridge.cs);
        CloseHandle(g_bridge.resp_event);
        return 0;
    }

    for (int i = 0; i < 50 && g_bridge.running && !g_bridge.listening; i++)
        Sleep(100);

    return g_bridge.listening;
}

/* ---------- Lua-callable functions (native mode only) ---------- */

static int l_mcp_tcp_start(lua_State *L) {
    dbg_log("[MCP-DLL] mcp_tcp_start called");
    if (g_bridge.running) {
        lua_newtable(L);
        lua_setboolfield(L, -1, "ok", 0);
        lua_setstrfield(L, -1, "err", "server already running");
        return 1;
    }

    /* Security default: loopback only. Remote debugging is opt-in via the
     * CE_MCP_BIND environment variable (set before CE starts) or by passing
     * an explicit bind address as Lua argument 2. */
    int port = 17171;
    char bindBuf[64] = "127.0.0.1";
    const char *bind = bindBuf;
    if (lua_nargs(L) >= 1 && pL_isnumber && pL_isnumber(L, 1))
        port = (int)lua_getint(L, 1);
    if (lua_nargs(L) >= 2 && pL_isstring && pL_isstring(L, 2))
        bind = lua_getstr(L, 2);
    {
        char envBind[64];
        DWORD n = GetEnvironmentVariableA("CE_MCP_BIND", envBind, sizeof(envBind));
        if (n > 0 && n < sizeof(envBind)) {
            memcpy(bindBuf, envBind, n + 1);
            dbg_log("[MCP-DLL] CE_MCP_BIND override: %s", envBind);
        }
    }

    int ok = start_tcp_server(port, bind);

    lua_newtable(L);
    lua_setboolfield(L, -1, "ok", ok ? 1 : 0);
    lua_setintfield(L, -1, "port", g_bridge.listen_port);
    if (!ok)
        lua_setstrfield(L, -1, "err", "failed to bind port");
    return 1;
}

static int l_mcp_tcp_stop(lua_State *L) {
    if (!g_bridge_initialized) {
        lua_newtable(L);
        lua_setboolfield(L, -1, "ok", 1);
        return 1;
    }

    dbg_log("[MCP-DLL] Stopping server...");
    g_bridge.running = 0;

    if (g_bridge.client_sock != INVALID_SOCKET) {
        shutdown(g_bridge.client_sock, SD_BOTH);
        closesocket(g_bridge.client_sock);
        g_bridge.client_sock = INVALID_SOCKET;
    }
    if (g_bridge.listen_sock != INVALID_SOCKET) {
        closesocket(g_bridge.listen_sock);
        g_bridge.listen_sock = INVALID_SOCKET;
    }
    if (g_bridge.resp_event) SetEvent(g_bridge.resp_event);
    if (g_bridge.thread) {
        DWORD w = WaitForSingleObject(g_bridge.thread, 10000);
        if (w != WAIT_OBJECT_0) {
            /* The thread may still be inside the critical section. Deleting
             * the CS or the event here would be undefined behavior. Leak them
             * (once) and report failure; running=0 already stops all loops. */
            dbg_log("[MCP-DLL] ERROR: server thread did not stop in 10s");
            lua_newtable(L);
            lua_setboolfield(L, -1, "ok", 0);
            lua_setstrfield(L, -1, "err", "server thread did not stop");
            return 1;
        }
        CloseHandle(g_bridge.thread);
        g_bridge.thread = NULL;
    }

    EnterCriticalSection(&g_bridge.cs);
    if (g_bridge.cmd_buf) { free(g_bridge.cmd_buf); g_bridge.cmd_buf = NULL; }
    if (g_bridge.resp_buf) { free(g_bridge.resp_buf); g_bridge.resp_buf = NULL; }
    g_bridge.cmd_ready = 0;
    g_bridge.resp_ready = 0;
    LeaveCriticalSection(&g_bridge.cs);
    DeleteCriticalSection(&g_bridge.cs);
    if (g_bridge.resp_event) { CloseHandle(g_bridge.resp_event); g_bridge.resp_event = NULL; }

    g_bridge.listening = 0;
    g_bridge.connected = 0;
    g_bridge_initialized = 0;

    dbg_log("[MCP-DLL] Server stopped");

    lua_newtable(L);
    lua_setboolfield(L, -1, "ok", 1);
    return 1;
}

static int l_mcp_tcp_poll(lua_State *L) {
    /* Heartbeat: the Lua timer calls this every 1 ms while the main thread is
     * servicing the bridge. dll_status derives lua_responsive from its age. */
    InterlockedExchange(&g_last_lua_poll_tick, (LONG)GetTickCount());
    if (!g_bridge.cmd_ready) {
        lua_pushnothing(L);
        return 1;
    }
    EnterCriticalSection(&g_bridge.cs);
    if (g_bridge.cmd_ready && g_bridge.cmd_buf) {
        pL_pushstring(L, g_bridge.cmd_buf);
        free(g_bridge.cmd_buf);
        g_bridge.cmd_buf = NULL;
        g_bridge.cmd_len = 0;
        g_bridge.cmd_ready = 0;
    } else {
        lua_pushnothing(L);
    }
    LeaveCriticalSection(&g_bridge.cs);
    return 1;
}

static int l_mcp_tcp_respond(lua_State *L) {
    if (lua_nargs(L) < 1 || !pL_isstring || !pL_isstring(L, 1)) {
        lua_newtable(L);
        lua_setboolfield(L, -1, "ok", 0);
        lua_setstrfield(L, -1, "err", "expected string argument");
        return 1;
    }
    size_t len = 0;
    const char *data = pL_tolstring(L, 1, &len);
    if (!data || len == 0) {
        lua_newtable(L);
        lua_setboolfield(L, -1, "ok", 0);
        lua_setstrfield(L, -1, "err", "empty response");
        return 1;
    }

    EnterCriticalSection(&g_bridge.cs);
    if (g_bridge.resp_buf) free(g_bridge.resp_buf);
    g_bridge.resp_buf = (char*)malloc(len + 1);
    if (!g_bridge.resp_buf) {
        /* Wake the server thread now so it does not block for 120s on a
         * response that will never arrive. */
        g_bridge.resp_len = 0;
        g_bridge.resp_ready = 0;
        LeaveCriticalSection(&g_bridge.cs);
        SetEvent(g_bridge.resp_event);
        lua_newtable(L);
        lua_setboolfield(L, -1, "ok", 0);
        lua_setstrfield(L, -1, "err", "out of memory");
        return 1;
    }
    memcpy(g_bridge.resp_buf, data, len);
    g_bridge.resp_buf[len] = '\0';
    g_bridge.resp_len = (int)len;
    g_bridge.resp_ready = 1;
    LeaveCriticalSection(&g_bridge.cs);
    SetEvent(g_bridge.resp_event);

    lua_newtable(L);
    lua_setboolfield(L, -1, "ok", 1);
    return 1;
}

static int l_mcp_tcp_status(lua_State *L) {
    DWORD now = GetTickCount();
    DWORD last = (DWORD)g_last_lua_poll_tick;
    lua_newtable(L);
    lua_setboolfield(L, -1, "listening", g_bridge.listening);
    lua_setboolfield(L, -1, "connected", g_bridge.connected);
    lua_setintfield(L, -1, "port", g_bridge.listen_port);
    lua_setboolfield(L, -1, "running", g_bridge.running);
    lua_setintfield(L, -1, "poll_age_ms", (last == 0) ? -1 : (lua_Integer)(now - last));
    lua_setboolfield(L, -1, "lua_responsive",
                     (last != 0) && (now - last) < LUA_RESPONSIVE_THRESHOLD_MS);
    return 1;
}

/* ---------- DLL Entry Point ---------- */

__declspec(dllexport) int luaopen_ce_mcp_tcp(lua_State *L) {
    dbg_log("[MCP-DLL] luaopen_ce_mcp_tcp called");

    if (!lua_api_ready && !resolve_lua_api()) {
        dbg_log("[MCP-DLL] FATAL: cannot resolve Lua API");
        dbg_log("[MCP-DLL] This CE build has Lua statically linked without exports.");
        dbg_log("[MCP-DLL] Check the log above for diagnostic details.");
        return 0;
    }

    /* ---- NATIVE LUA API MODE ---- */
    lua_register_func(L, "mcp_tcp_start",   l_mcp_tcp_start);
    lua_register_func(L, "mcp_tcp_stop",    l_mcp_tcp_stop);
    lua_register_func(L, "mcp_tcp_poll",    l_mcp_tcp_poll);
    lua_register_func(L, "mcp_tcp_respond", l_mcp_tcp_respond);
    lua_register_func(L, "mcp_tcp_status",  l_mcp_tcp_status);

    dbg_log("[MCP-DLL] Native mode: 5 Lua functions registered (dll_* fastpath enabled)");

    lua_newtable(L);
    lua_setstrfield(L, -1, "version", "3.3.4");
    lua_setstrfield(L, -1, "transport", "native_tcp");
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)hModule; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self_module = hModule;
        /* dbg_init() is deliberately NOT called here: DllMain runs under the
         * loader lock, and AllocConsole is exactly the kind of call the
         * Dynamic-Link Library Best Practices document tells you to defer.
         * dbg_log() lazy-initializes the console on first use, which happens
         * inside luaopen_ce_mcp_tcp -- after LoadLibrary has released the
         * loader lock. */
        dbg_log("[MCP-DLL] ce_mcp_tcp.dll loaded (v3.3.4)");
    }
    if (reason == DLL_PROCESS_DETACH) {
        dbg_log("[MCP-DLL] DLL unloading...");
        if (g_bridge.running) {
            g_bridge.running = 0;
            if (g_bridge.client_sock != INVALID_SOCKET) closesocket(g_bridge.client_sock);
            if (g_bridge.listen_sock != INVALID_SOCKET) closesocket(g_bridge.listen_sock);
            if (g_bridge.resp_event) SetEvent(g_bridge.resp_event);
        }
        if (g_logfp) fclose(g_logfp);
        if (g_console) FreeConsole();
    }
    return TRUE;
}
