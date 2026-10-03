-- ============================================================================
-- CHEATENGINE MCP BRIDGE v15.1.0
-- ----------------------------------------------------------------------------
-- Transport : native TCP via ce_mcp_tcp_<arch>.dll (Winsock2, static CRT).
-- Framing   : 4-byte little-endian length prefix + UTF-8 JSON-RPC 2.0.
-- Endpoint  : CE binds 0.0.0.0:17171..17180 and reports the chosen port to Lua.
-- Threading : the DLL owns the socket thread. CE's main thread drains one
--             pending command per tick (mcp_tcp_poll) and answers with
--             mcp_tcp_respond. Every CE Lua API call therefore stays on the
--             main thread -> the GUI never freezes, and no FFI / pipe / Lua
--             socket code remains in this file.
--
-- Removed in v15.1.0: PIPE_NAME, TRANSPORT and TCP_MAX_PORT (the Named Pipe
-- path and the in-Lua TCP server are gone). The Python side's
-- CE_TRANSPORT=pipe option no longer has a counterpart here.
-- ============================================================================

local VERSION = "15.8.2"

-- v15.8.2: valid-name catalogs for scan parameters (used by fail-fast
-- INVALID_PARAMS messages; must live above cmd_scan_all which is defined
-- before the resolver functions).
local VAR_TYPE_NAMES  = "byte, word, dword, qword, float, double, string"
local SCAN_OPTION_NAMES = "exact, unknown, between, bigger, smaller, increased, decreased, changed, unchanged"

local TCP_BASE_PORT = 17171
-- Security default: loopback only. Remote debugging is opt-in via the
-- CE_MCP_BIND environment variable (read at start, see resolveBindAddr).
local TCP_BIND      = "127.0.0.1"

-- CE_MCP_BIND lets a user opt into binding a non-loopback interface (e.g.
-- "0.0.0.0" for remote debugging across a trusted LAN). The DLL applies the
-- same override, so setting it before CE starts is sufficient; this Lua-side
-- read exists so the effective bind address is visible in the start log.
-- Read one environment variable through CE's accessor when available, with
-- os.getenv as fallback. Returns nil when unset/empty. (Single implementation:
-- CE_MCP_BIND and CE_MCP_AUTH_TOKEN both go through here.)
local function readEnvVar(name)
    if type(getEnvironmentVariable) == "function" then
        local ok, v = pcall(getEnvironmentVariable, name)
        if ok and type(v) == "string" and v ~= "" then return v end
    end
    if type(os) == "table" and type(os.getenv) == "function" then
        local ok, v = pcall(os.getenv, name)
        if ok and type(v) == "string" and v ~= "" then return v end
    end
    return nil
end

local function resolveBindAddr()
    return readEnvVar("CE_MCP_BIND")
end

-- Optional shared-token authentication (design borrowed from the
-- tonytranrp/cheat-engine-mcp bridge, implemented here at the Lua dispatch
-- layer so the DLL stays untouched). When CE_MCP_AUTH_TOKEN is set, every
-- request must carry params._auth == token or it is rejected with
-- AUTH_REQUIRED before any handler runs (batch sub-commands included, since
-- the check sits in executeCommand, the single entry point). Unset on both
-- sides = open loopback access (the default).
-- Unset on both
-- sides = open loopback access (the default).
local AUTH_TOKEN = readEnvVar("CE_MCP_AUTH_TOKEN")

-- Length-independent comparison so token probing cannot timing-oracle the
-- secret byte-by-byte. (Lua's `~` is bitwise XOR, CE ships Lua 5.3+.)
local function secureTokenEq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do diff = diff | (a:byte(i) ~ b:byte(i)) end
    return diff == 0
end

-- CE constant fallbacks (some CE builds may not expose all globals)
-- Value types
if vtByte      == nil then vtByte      = 0 end
if vtWord      == nil then vtWord      = 1 end
if vtDword     == nil then vtDword     = 2 end
if vtQword     == nil then vtQword     = 3 end
if vtSingle    == nil then vtSingle    = 4 end
if vtDouble    == nil then vtDouble    = 5 end
if vtString    == nil then vtString    = 6 end
if vtByteArray == nil then vtByteArray = 7 end
if vtPointer   == nil then vtPointer   = 8 end
-- Scan options
if soExactValue     == nil then soExactValue     = 0 end
if soValueBetween   == nil then soValueBetween   = 1 end
if soBiggerThan     == nil then soBiggerThan     = 2 end
if soSmallerThan    == nil then soSmallerThan    = 3 end
if soIncreasedValue == nil then soIncreasedValue = 4 end
if soDecreasedValue == nil then soDecreasedValue = 5 end
if soChanged        == nil then soChanged        = 6 end
if soUnchanged      == nil then soUnchanged      = 7 end
if soUnknownValue   == nil then soUnknownValue   = 8 end
-- Rounding / alignment
if rtRounded     == nil then rtRounded     = 0 end
if fsmNotAligned == nil then fsmNotAligned = 0 end
-- Breakpoint types / methods
if bptExecute      == nil then bptExecute      = 0 end
if bptAccess       == nil then bptAccess       = 1 end
if bptWrite        == nil then bptWrite        = 2 end
if bpmDebugRegister == nil then bpmDebugRegister = 1 end

-- Global State
local serverState = {
    running = false,
    -- scanning / persistent scan sessions
    scan_memscan = nil,
    scan_foundlist = nil,
    persistent_scans = {},
    -- debugging resources torn down by cleanupZombieState()
    breakpoints = {},
    breakpoint_hits = {},
    hw_bp_slots = {},
    active_watches = {},
    -- native transport facts (refreshed on start, surfaced by bridge_status)
    tcpPort = nil,
    nativeInfo = nil,
    startedAt = nil,
    -- lightweight telemetry; see cmd_status()
    stats = { commands = 0, errors = 0, batches = 0, subcommands = 0 },
    lastMethod = nil,
    lastError = nil,
    lastErrorCode = nil,
    -- audit trail of mutating commands (ring buffer, see MAX_AUDIT_ENTRIES)
    auditLog = {},
}

-- MDL handles for active mapMemory() calls, keyed by mapped-address hex string.
-- mapMemory() returns (address, mdl) and unmapMemory() needs that mdl to release
-- the mapping. Declared HERE — above cleanupZombieState() — because a `local`
-- introduced further down the file is invisible to an earlier function: the old
-- placement made cleanupZombieState() read a *global* named mappedMemoryMDL
-- (always nil), so kernel mappings silently leaked on every script reload.
local mappedMemoryMDL = {}

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Canonical address formatter for every handler.
-- Always emits "0x" + uppercase hex with no zero padding, so a 32-bit address
-- and a 64-bit address look the same shape ("0x1000" / "0x140001000").
-- Non-numbers and non-integer floats are coerced instead of raising, because
-- toHex() is called on raw CE return values all over the bridge.
local function toHex(num)
    if num == nil then return "nil" end
    if type(num) ~= "number" then return tostring(num) end
    local v = num
    if math.tointeger then
        v = math.tointeger(v) or math.floor(v)
    else
        v = math.floor(v)
    end
    if v < 0 then v = v & 0xFFFFFFFFFFFFFFFF end
    return string.format("0x%X", v)
end

local function toHexLow32(num)
    if not num then return nil end
    return num & 0xFFFFFFFF
end

-- Universal 32/64-bit architecture helper
-- Returns pointer size, whether target is 64-bit, and current stack/instruction pointers
local function getArchInfo()
    local is64 = targetIs64Bit()
    local ptrSize = is64 and 8 or 4
    local stackPtr = is64 and (RSP or ESP) or ESP
    local instPtr = is64 and (RIP or EIP) or EIP
    return {
        is64bit = is64,
        ptrSize = ptrSize,
        stackPtr = stackPtr,
        instPtr = instPtr
    }
end

-- Universal register capture - works for both 32-bit and 64-bit targets
local function captureRegisters()
    local is64 = targetIs64Bit()
    if is64 then
        return {
            RAX = RAX and toHex(RAX) or nil,
            RBX = RBX and toHex(RBX) or nil,
            RCX = RCX and toHex(RCX) or nil,
            RDX = RDX and toHex(RDX) or nil,
            RSI = RSI and toHex(RSI) or nil,
            RDI = RDI and toHex(RDI) or nil,
            RBP = RBP and toHex(RBP) or nil,
            RSP = RSP and toHex(RSP) or nil,
            RIP = RIP and toHex(RIP) or nil,
            R8 = R8 and toHex(R8) or nil,
            R9 = R9 and toHex(R9) or nil,
            R10 = R10 and toHex(R10) or nil,
            R11 = R11 and toHex(R11) or nil,
            R12 = R12 and toHex(R12) or nil,
            R13 = R13 and toHex(R13) or nil,
            R14 = R14 and toHex(R14) or nil,
            R15 = R15 and toHex(R15) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x64"
        }
    else
        return {
            EAX = EAX and toHex(EAX) or nil,
            EBX = EBX and toHex(EBX) or nil,
            ECX = ECX and toHex(ECX) or nil,
            EDX = EDX and toHex(EDX) or nil,
            ESI = ESI and toHex(ESI) or nil,
            EDI = EDI and toHex(EDI) or nil,
            EBP = EBP and toHex(EBP) or nil,
            ESP = ESP and toHex(ESP) or nil,
            EIP = EIP and toHex(EIP) or nil,
            EFLAGS = EFLAGS and toHex(EFLAGS) or nil,
            arch = "x86"
        }
    end
end

-- Universal stack capture - reads stack with correct pointer size.
-- Emits a dense 1-based array of {offset, value} entries. The old version
-- stored entries at 0..depth-1, and since json.encode() treats any table whose
-- [1] is set as a JSON array, the very first stack slot was silently dropped.
local function captureStack(depth)
    local arch = getArchInfo()
    local stack = {}
    local stackPtr = arch.stackPtr
    if not stackPtr then return stack end

    -- Clamp at the chokepoint: an unclamped stack_depth (e.g. 1e9) would spin
    -- this loop reading memory for hours and freeze CE.
    depth = math.max(0, math.min(tonumber(depth) or 16, 128))

    for i = 0, depth - 1 do
        local off = i * arch.ptrSize
        local val
        if arch.is64bit then
            val = readQword(stackPtr + off)
        else
            val = readInteger(stackPtr + off)
        end
        if val then
            stack[#stack + 1] = { offset = off, value = toHex(val) }
        end
    end
    return stack
end

-- Cap the per-breakpoint hit history so a hot breakpoint in a long session
-- cannot exhaust CE memory. Oldest hits are dropped first, newest are kept.
-- The cap is intentionally invisible to callers beyond "only the last 500
-- hits are available" — cmd_get_breakpoint_hits reads the same list.
local MAX_HITS_PER_BREAKPOINT = 500
-- AutoAssemble scripts above this size are rejected: the assembly pass runs
-- on CE's main thread and large scripts have been observed to freeze it.
local AA_MAX_SCRIPT_SIZE = 64 * 1024
local function recordBPHit(bpId, hitData)
    local list = serverState.breakpoint_hits[bpId]
    if list == nil then
        list = {}
        serverState.breakpoint_hits[bpId] = list
    end
    while #list >= MAX_HITS_PER_BREAKPOINT do
        table.remove(list, 1)
    end
    table.insert(list, hitData)
end

-- Paging parameter clamp: normalise offset/limit from params WITHOUT slicing.
-- Use when the source is a 0-based CE collection (FoundList, addresslist) that
-- must be indexed in its own range instead of a 1-based Lua table.
-- `max` is accepted as a backward-compat alias for `limit`.
-- Non-numeric values fall back to the default instead of erroring mid-handler.
-- Returns: limit, offset
local function clampPaging(params, defaultLimit, maxLimit)
    local limit = math.max(1, math.min(tonumber(params.limit or params.max) or defaultLimit or 100, maxLimit or 10000))
    local offset = math.max(0, tonumber(params.offset) or 0)
    return limit, offset
end

-- Pagination helper: parse offset/limit params and slice a table.
-- Returns: limit, offset, page_table, total
-- Usage: local limit, offset, page, total = paginate(params, allItems, 100)
local function paginate(params, items, defaultLimit, maxLimit)
    local limit, offset = clampPaging(params, defaultLimit, maxLimit)
    local total = #items
    local page = {}
    for i = offset + 1, math.min(offset + limit, total) do
        page[#page + 1] = items[i]
    end
    return limit, offset, page, total
end

-- ============================================================================
-- AUDIT TRAIL (v15.3.0)
-- ----------------------------------------------------------------------------
-- Every mutating command is recorded into a bounded ring buffer. The audit
-- answers "what changed this session, when, and did it succeed" — memory
-- writes, script/AA execution, table operations, symbol registration, process
-- attachment. Read-only probes are deliberately NOT recorded.
-- Entries survive until the script is reloaded; persist them via
-- get_audit_log if the session matters.
-- ============================================================================

local MAX_AUDIT_ENTRIES = 200
local MAX_AUDIT_PARAM_STR = 96

-- Prefix match is intentional: it stays correct for aliases and new commands
-- that follow the naming convention (write_*, set_*, create_*, ...).
-- AUDIT_MUTATING_EXACT catches mutating commands whose names the prefixes
-- miss (run_command, the debug_* family, watch/table_file/evaluate_lua, ...).
-- Read-only dbk_get_cr*/dbk_read_msr/dbvm_read_msr/dbvm_cloak_read DO match
-- the "dbk_"/"dbvm_" prefixes and are audited anyway: over-recording is the
-- safe side, and the distinction is not worth a third list.
local AUDIT_MUTATING_PREFIXES = {
    "write_", "set_", "create_", "delete_", "execute_", "inject_",
    "load_table", "save_table", "register_", "unregister_",
    "append_memory_record", "open_process", "pause_process", "unpause_process",
    "auto_assemble", "compile_", "map_memory", "unmap_memory", "copy_memory",
    "free_memory", "allocate_", "full_access", "key_down", "key_up",
    "do_key_press", "shell_execute", "patch_", "undo_", "remove_",
    "dbk_", "dbvm_",
}

local AUDIT_MUTATING_EXACT = {
    run_command = true,
    evaluate_lua = true,
    auto_guess_structure = true,
    clear_all_breakpoints = true,
    start_dbvm_watch = true,
    stop_dbvm_watch = true,
    find_what_writes_safe = true,
    find_what_accesses_safe = true,
    set_execution_breakpoint = true,
    set_write_breakpoint = true,
    debug_set_context = true,
    debug_set_breakpoint_for_thread = true,
    debug_remove_breakpoint_for_thread = true,
    debug_set_last_branch_recording = true,
    debug_process = true,
    debug_continue = true,
    debug_detach = true,
    debug_break_thread = true,
    map_view_of_section = true,
    read_region_from_file = true,
    table_file_create = true,
    table_file_delete = true,
    table_file_export = true,
}

local function isMutatingMethod(method)
    if type(method) ~= "string" then return false end
    if AUDIT_MUTATING_EXACT[method] then return true end
    for _, p in ipairs(AUDIT_MUTATING_PREFIXES) do
        if method:sub(1, #p) == p then return true end
    end
    return false
end

-- Compact, bounded params summary: key=value for short scalars, type+len for
-- anything else. Never embeds full scripts or byte arrays in the audit.
local function auditParamsSummary(params)
    local parts = {}
    local n = 0
    for k, v in pairs(params) do
        n = n + 1
        if n > 6 then parts[#parts + 1] = "..." break end
        local t = type(v)
        if t == "string" then
            if #v > MAX_AUDIT_PARAM_STR then
                parts[#parts + 1] = k .. "=<" .. #v .. "B>"
            else
                parts[#parts + 1] = k .. "=" .. v
            end
        elseif t == "table" then
            parts[#parts + 1] = k .. "=<" .. t .. ">"
        else
            parts[#parts + 1] = k .. "=" .. tostring(v)
        end
    end
    return table.concat(parts, " ")
end

local function auditLogEntry(method, params, success, errorCode)
    local log = serverState.auditLog
    log[#log + 1] = {
        time = os.time(),
        method = method,
        success = success and true or false,
        error_code = errorCode,
        params = auditParamsSummary(params or {}),
    }
    if #log > MAX_AUDIT_ENTRIES then table.remove(log, 1) end
end

function cmd_get_audit_log(params)
    local limit, offset = clampPaging(params, 100, MAX_AUDIT_ENTRIES)
    local log = serverState.auditLog
    local total = #log
    local page = {}
    -- newest first: the common question is "what just happened"
    for i = 0, limit - 1 do
        local idx = total - offset - i
        if idx < 1 then break end
        page[#page + 1] = log[idx]
    end
    if params.clear then serverState.auditLog = {} end
    return { success = true, total = total, offset = offset, limit = limit,
             returned = #page, entries = page, cleared = params.clear and true or false }
end

-- ============================================================================
-- SHARED HELPERS (Unit 5 refactor — used by multiple cmd_* handlers)
-- ============================================================================
-- >>> BEGIN UNIT-05 Shared helpers <<<

local function parseAddress(input)
    -- Accepts string hex ("0x140001000"), symbol ("game.exe+1000"), or integer.
    -- Returns (address, error) — address nil if invalid.
    if type(input) == "number" then return input, nil end
    if type(input) ~= "string" then return nil, "address must be string or number" end
    local addr = getAddressSafe(input)
    if not addr or addr == 0 then return nil, "Invalid address: " .. tostring(input) end
    return addr, nil
end

local function requireProcess()
    -- Single definition for the whole bridge (do not re-declare it later).
    -- Returns (true, nil) when a process is attached, (false, {error}) otherwise.
    -- Both call idioms work:
    --     local ok, err = requireProcess(); if not ok then return err end
    --     if not requireProcess() then return { success = false, ... } end
    if (getOpenedProcessID() or 0) == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

-- >>> BEGIN UNIT-24 Signature Tooling <<<
-- 1) {token} substitution for AOB signatures / AA scripts, keyed by game FileVersion
-- 2) scan-failure diagnosis (on-disk vs in-memory) + likely mod conflicts
-- 3) bounded address-range AOB scan

local SIG_TOKEN_FILE = nil
local sigTokenCache  = nil

local function sigTokenPath()
    if SIG_TOKEN_FILE then return SIG_TOKEN_FILE end
    local src = (debug.getinfo(1, "S").source or ""):gsub("^@", "")
    local dir = src:match("^(.*)[/\\][^/\\]*$") or "."
    SIG_TOKEN_FILE = dir .. "\\sig_tokens.txt"
    return SIG_TOKEN_FILE
end

-- file format (one rule per line):  <gameFileVersion> <TAB> <token> <TAB> <bytes>
-- '*' as version = fallback for any version.  Lines starting with '#' are comments.
local function loadSigTokens(force)
    if sigTokenCache and not force then return sigTokenCache end
    local t = {}
    local f = io.open(sigTokenPath(), "r")
    if f then
        for rawline in f:lines() do
            local line = rawline:gsub("^%s+", ""):gsub("%s+$", "")
            if line ~= "" and line:sub(1, 1) ~= "#" then
                local ver, tok, bytes = line:match("^([^\t]+)\t([^\t]+)\t(.+)$")
                if ver and tok then
                    t[ver] = t[ver] or {}
                    t[ver][tok] = bytes:gsub("^%s+", ""):gsub("%s+$", "")
                end
            end
        end
        f:close()
    end
    sigTokenCache = t
    return t
end

local function saveSigTokens(t)
    local out = io.open(sigTokenPath(), "w")
    if not out then return false end
    out:write("# <gameFileVersion>\t<token>\t<bytes>   -- use as {token} in patterns/software scripts\n")
    out:write("# version '*' = fallback for every game version\n")
    for ver, toks in pairs(t) do
        for tok, bytes in pairs(toks) do
            out:write(ver, "\t", tok, "\t", bytes, "\n")
        end
    end
    out:close()
    sigTokenCache = t
    return true
end

local function mainModuleExePath()
    local pid = getOpenedProcessID() or 0
    local modules
    pcall(function()
        modules = enumModules(pid)
        if not modules or #modules == 0 then modules = enumModules() end
    end)
    if not modules then return nil, nil end
    local base = getAddressSafe(process)
    local exePath, mainBase
    for _, m in ipairs(modules) do
        local addr = m.Address or m.address
        if addr and base and addr == base then
            exePath  = m.PathToFile or m.path
            mainBase = addr
        end
    end
    if not exePath then exePath, mainBase = (modules[1] and (modules[1].PathToFile or modules[1].path)), (modules[1] and (modules[1].Address or modules[1].address)) end
    return exePath, mainBase
end

local function gameVersionString()
    local exePath = mainModuleExePath()
    if not exePath then return nil end
    -- v15.8.1: getFileVersion returns TWO values; the closure propagates both,
    -- so pcall yields (status, v1, v2) and the table is v2 -- the old two-value
    -- destructure bound v1 (a non-table) and ALWAYS returned nil, silently
    -- degrading signature-token version matching to wildcard-only.
    local ok, _, vt = pcall(function() return getFileVersion(exePath) end)
    if not ok or type(vt) ~= "table" then return nil end
    return string.format("%d.%d.%d.%d", vt.major or 0, vt.minor or 0, vt.release or 0, vt.build or 0)
end

local function tokensForVersion()
    local ver = gameVersionString()
    local all = loadSigTokens()
    local merged = {}
    for k, v in pairs(all["*"] or {}) do merged[k] = v end
    if ver and all[ver] then for k, v in pairs(all[ver]) do merged[k] = v end end
    return ver, merged
end

-- expand {token}; returns text (unchanged if no tokens) or nil + error table
local function expandSigTokens(text)
    if type(text) ~= "string" or not text:find("{", 1, true) then return text end
    local ver, toks = tokensForVersion()
    local missing, used = nil, {}
    local out = text:gsub("{(%w[%w%._%-]*)}", function(name)
        local b = toks[name]
        if not b then missing = missing or name; return "{" .. name .. "}" end
        used[#used + 1] = name
        return b
    end)
    if missing then
        return nil, {
            success    = false,
            error      = "Unknown signature token {" .. missing .. "}"
                      .. (ver and (" for game version " .. ver) or " (game version unknown)")
                      .. ". Add one line to sig_tokens.txt:  <version><TAB>" .. missing .. "<TAB><bytes>",
            error_code = "UNKNOWN_SIG_TOKEN",
            token      = missing,
            version    = ver
        }
    end
    return out
end

local function findModulesViaMZScan(maxCount)
    -- Shared MZ-header AOB scan used by cmd_get_process_info and cmd_enum_modules.
    -- Returns an array of { name, address, size, source } tables.
    maxCount = maxCount or 50
    local moduleList = {}
    local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
    if mzScan and mzScan.Count > 0 then
        for i = 0, math.min(mzScan.Count - 1, maxCount) do
            local addr = tonumber(mzScan.getString(i), 16)
            if addr then
                local peOffset = readInteger(addr + 0x3C)
                local moduleSize = 0
                local realName = nil

                if peOffset and peOffset > 0 and peOffset < 0x1000 then
                    -- Get Size of Image
                    local sizeOfImage = readInteger(addr + peOffset + 0x50)
                    if sizeOfImage then moduleSize = sizeOfImage end

                    -- TRY TO READ INTERNAL NAME FROM EXPORT DIRECTORY
                    -- PE Header + 0x78 is the Data Directory for Exports (32-bit)
                    local exportRVA = readInteger(addr + peOffset + 0x78)
                    if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                        -- Export Directory + 0x0C is the Name RVA
                        local nameRVA = readInteger(addr + exportRVA + 0x0C)
                        if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                            local name = readString(addr + nameRVA, 64)
                            if name and #name > 0 and #name < 60 then
                                realName = name
                            end
                        end
                    end
                end

                -- Determine module name
                local modName
                if realName then
                    modName = realName
                elseif i == 0 then
                    -- First module is likely main exe - use process name or L2.exe
                    modName = (process ~= "" and process) or "L2.exe"
                else
                    modName = "Module_" .. string.format("%X", addr)
                end

                table.insert(moduleList, {
                    name = modName,
                    address = toHex(addr),
                    size = moduleSize,
                    source = realName and "export_directory" or "aob_fallback"
                })
            end
        end
        mzScan.destroy()
    end
    return moduleList
end

local function findFunctionPrologue(addr, maxSearch)
    -- Searches backward from addr for a function prologue (x86: "55 8B EC" / x64: "55 48 89 E5" / "48 83 EC xx").
    -- Returns (prologueAddress, prologueType) or (nil, nil).
    maxSearch = maxSearch or 4096
    local is64 = targetIs64Bit()
    local funcStart = nil
    local prologueType = nil
    for offset = 0, maxSearch do
        local checkAddr = addr - offset
        local b1 = readBytes(checkAddr, 1, false)
        local b2 = readBytes(checkAddr + 1, 1, false)
        local b3 = readBytes(checkAddr + 2, 1, false)
        local b4 = readBytes(checkAddr + 3, 1, false)

        -- 32-bit prologue: push ebp; mov ebp, esp (55 8B EC)
        if b1 == 0x55 and b2 == 0x8B and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x86_standard"
            break
        end

        -- 64-bit prologue: push rbp; mov rbp, rsp (55 48 89 E5)
        if is64 and b1 == 0x55 and b2 == 0x48 and b3 == 0x89 and b4 == 0xE5 then
            funcStart = checkAddr
            prologueType = "x64_standard"
            break
        end

        -- 64-bit alternative: sub rsp, imm8 (48 83 EC xx) - common in leaf functions
        if is64 and b1 == 0x48 and b2 == 0x83 and b3 == 0xEC then
            funcStart = checkAddr
            prologueType = "x64_leaf"
            break
        end
    end
    return funcStart, prologueType
end

-- >>> END UNIT-05 <<<

-- ============================================================================
-- CLEANUP & SAFETY ROUTINES (CRITICAL FOR ROBUSTNESS)
-- ============================================================================
-- Prevents "zombie" breakpoints and DBVM watches when script is reloaded

local function cleanupZombieState()
    local cleaned = { breakpoints = 0, dbvm_watches = 0, scans = 0 }
    
    -- 1. Remove all Hardware Breakpoints managed by us
    if serverState.breakpoints then
        for id, bp in pairs(serverState.breakpoints) do
            if bp.address then
                local ok = pcall(function() debug_removeBreakpoint(bp.address) end)
                if ok then cleaned.breakpoints = cleaned.breakpoints + 1 end
            end
        end
    end
    
    -- 2. Stop all DBVM Watches
    if serverState.active_watches then
        for key, watch in pairs(serverState.active_watches) do
            if watch.id then
                local ok = pcall(function() dbvm_watch_disable(watch.id) end)
                if ok then cleaned.dbvm_watches = cleaned.dbvm_watches + 1 end
            end
        end
    end

    -- 3. Cleanup Scan memory objects
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
        cleaned.scans = cleaned.scans + 1
    end
    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end

    -- 4. Cleanup persistent scans (Unit 15)
    if serverState.persistent_scans then
        for name, entry in pairs(serverState.persistent_scans) do
            if entry then
                if entry.fl then pcall(function() entry.fl.destroy() end) end
                pcall(function() entry.ms.destroy() end)
                cleaned.scans = cleaned.scans + 1
            end
        end
    end

    -- Reset all tracking tables
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    serverState.active_watches = {}

    -- 5. Release any kernel-mapped MDL handles created via map_memory (Unit-21)
    for key, mdl in pairs(mappedMemoryMDL) do
        pcall(function() unmapMemory(getAddressSafe(key) or 0, mdl) end)
        cleaned.mappings = (cleaned.mappings or 0) + 1
    end
    for k in pairs(mappedMemoryMDL) do mappedMemoryMDL[k] = nil end

    serverState.persistent_scans = {}

    -- Extension point (reserved for additive units):
    -- Any new long-lived resource added to serverState must get a teardown entry
    -- above, otherwise reloading the script while it is live leaks it (orphaned
    -- DR slots, DBVM watches and kernel mappings can freeze the target).

    return cleaned
end

-- ============================================================================
-- JSON LIBRARY (Pure Lua - Complete Implementation)
-- ============================================================================
local json = {}
local encode

local escape_char_map = { [ "\\" ] = "\\", [ "\"" ] = "\"", [ "\b" ] = "b", [ "\f" ] = "f", [ "\n" ] = "n", [ "\r" ] = "r", [ "\t" ] = "t" }
local escape_char_map_inv = { [ "/" ] = "/" }
for k, v in pairs(escape_char_map) do escape_char_map_inv[v] = k end

local function escape_char(c) return "\\" .. (escape_char_map[c] or string.format("u%04x", c:byte())) end
local function encode_nil(val) return "null" end

-- Nesting depth is capped far below Lua's C-call limit so a pathological
-- payload fails with a deterministic message instead of "stack overflow"
-- reported at an arbitrary recursion site (observed in the field as an error
-- attributed to the encode_table object loop).
local ENCODE_MAX_DEPTH = 200
local encode_depth = 0

local function encode_table(val, stack)
  local res, stack = {}, stack or {}
  if stack[val] then error("circular reference (table contains itself)") end
  if encode_depth >= ENCODE_MAX_DEPTH then
    error("JSON nesting depth exceeded " .. ENCODE_MAX_DEPTH, 0)
  end
  encode_depth = encode_depth + 1
  stack[val] = true
  if rawget(val, 1) ~= nil or next(val) == nil then
    local n = 0
    for i, v in ipairs(val) do
      n = i
      table.insert(res, encode(v, stack))
    end
    if n == 0 or next(val, n) == nil then
      -- Empty table, or dense sequential array ([1..n], nothing else): [...]
      stack[val] = nil
      encode_depth = encode_depth - 1
      return "[" .. table.concat(res, ",") .. "]"
    end
    -- Mixed table (array prefix plus other keys): fall through to object
    -- encoding so no key is silently dropped; numeric keys become "1", "2"...
    res = {}
  end
  for k, v in pairs(val) do
    local key = type(k) == "string" and k or tostring(k)
    table.insert(res, encode(key, stack) .. ":" .. encode(v, stack))
  end
  stack[val] = nil
  encode_depth = encode_depth - 1
  return "{" .. table.concat(res, ",") .. "}"
end
local function encode_string(val) return '"' .. val:gsub('[%z\1-\31\\"]', escape_char) .. '"' end

-- Numbers must round-trip exactly: "%.14g" silently corrupts any 64-bit value
-- above 2^53 (e.g. read_integer(type="qword"), pointer values, os.time()*1000
-- style ids). Integers are emitted verbatim; only genuine floats use %g.
local function encode_number(val)
  if val ~= val or val <= -math.huge or val >= math.huge then return "null" end
  local mt = math.type and math.type(val) or nil
  if mt == "integer" then return string.format("%d", val) end
  if val == math.floor(val) and math.abs(val) <= 9007199254740992 then
    return string.format("%d", val)
  end
  return string.format("%.14g", val)
end
local type_func_map = { ["nil"] = encode_nil, ["table"] = encode_table, ["string"] = encode_string, ["number"] = encode_number, ["boolean"] = tostring, ["function"] = function() return "null" end, ["userdata"] = function() return "null" end }
encode = function(val, stack) local t = type(val) local f = type_func_map[t] if f then return f(val, stack) end error("unexpected type '" .. t .. "'") end
json.encode = function(val)
  encode_depth = 0          -- fresh entry; recursive calls share the counter
  return encode(val)
end

local function decode_scanwhite(str, pos) return str:find("%S", pos) or #str + 1 end
local decode

-- Minimal UTF-8 encoder. Lua 5.3+ ships utf8.char, but CE builds differ in
-- which stdlibs are exposed, so keep this self-contained.
local function utf8Encode(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 | (cp >> 6), 0x80 | (cp & 0x3F))
  elseif cp < 0x10000 then
    return string.char(0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
  end
  return string.char(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F),
                     0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F))
end

-- Undo JSON string escaping in a single pass.
-- CRITICAL: \uXXXX escapes are decoded to real UTF-8 here. The previous
-- implementation called string.char(codepoint), which raises
-- "value out of range" for any codepoint > 0xFF — i.e. every CJK character.
-- Because Python's json.dumps() defaults to ensure_ascii=True, that turned
-- any non-ASCII payload (write_string, evaluate_lua, file paths, speak_text)
-- into an unrecoverable "Parse error" response.
local function unescapeJsonString(raw)
  local out, i, n = {}, 1, #raw
  while i <= n do
    local c = raw:sub(i, i)
    if c ~= "\\" or i == n then
      out[#out + 1] = c
      i = i + 1
    else
      local e = raw:sub(i + 1, i + 1)
      if e == "u" then
        local hex = raw:sub(i + 2, i + 5)
        if #hex == 4 and hex:match("^%x%x%x%x$") then
          local cp = tonumber(hex, 16)
          local nextI = i + 6
          -- recombine a UTF-16 surrogate pair into one code point
          if cp >= 0xD800 and cp <= 0xDBFF then
            local lo = raw:sub(nextI, nextI + 5):match("^\\u(%x%x%x%x)$")
            lo = lo and tonumber(lo, 16) or nil
            if lo and lo >= 0xDC00 and lo <= 0xDFFF then
              cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
              nextI = nextI + 6
            end
          end
          out[#out + 1] = utf8Encode(cp)
          i = nextI
        else
          out[#out + 1] = "u"          -- malformed escape: keep it literal
          i = i + 2
        end
      else
        out[#out + 1] = escape_char_map_inv[e] or e
        i = i + 2
      end
    end
  end
  return table.concat(out)
end

local function decode_string(str, pos)
  local startpos = pos + 1
  local endpos = pos
  while true do
    endpos = str:find('["\\]', endpos + 1)
    if not endpos then return nil, "expected closing quote" end
    if str:sub(endpos, endpos) == '"' then break end
    endpos = endpos + 1
  end
  return unescapeJsonString(str:sub(startpos, endpos - 1)), endpos + 1
end
local function decode_number(str, pos)
  local numstr = str:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
  local val = numstr and tonumber(numstr) or nil
  if not val then return nil, "invalid number" end
  return val, pos + #numstr
end
local function decode_literal(str, pos)
  local word = str:match("^%a+", pos)
  if word == "true" then return true, pos + 4 end
  if word == "false" then return false, pos + 5 end
  if word == "null" then return nil, pos + 4 end
  return nil, "invalid literal"
end
local function decode_array(str, pos)
  pos = pos + 1
  local arr, n = {}, 0
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "]" then return arr, pos + 1 end
  while true do
        local val
        val, pos = decode(str, pos)
        n = n + 1
        arr[n] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "]" then return arr, pos + 1 end
    if c ~= "," then return nil, "expected ']' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local function decode_object(str, pos)
  pos = pos + 1
  local obj = {}
  pos = decode_scanwhite(str, pos)
  if str:sub(pos, pos) == "}" then return obj, pos + 1 end
  while true do
        local key
        key, pos = decode_string(str, pos)
        if not key then return nil, "expected string key" end
    pos = decode_scanwhite(str, pos)
    if str:sub(pos, pos) ~= ":" then return nil, "expected ':'" end
    pos = decode_scanwhite(str, pos + 1)
        local val
        val, pos = decode(str, pos)
        obj[key] = val
    pos = decode_scanwhite(str, pos)
    local c = str:sub(pos, pos)
    if c == "}" then return obj, pos + 1 end
    if c ~= "," then return nil, "expected '}' or ','" end
    pos = decode_scanwhite(str, pos + 1)
  end
end
local char_func_map = { ['"'] = decode_string, ["{"] = decode_object, ["["] = decode_array }
setmetatable(char_func_map, { __index = function(t, c) if c:match("%d") or c == "-" then return decode_number end return decode_literal end })
-- Depth reset at every fresh entry (pos == nil); nested calls always pass a
-- numeric pos, so one reset per json.decode() is sufficient. Errors unwind
-- without decrementing, but the next fresh entry resets the counter.
local DECODE_MAX_DEPTH = 200
local decode_depth = 0
decode = function(str, pos)
  if pos == nil then decode_depth = 0 end
  pos = pos or 1
  pos = decode_scanwhite(str, pos)
  local c = str:sub(pos, pos)
  if c == "[" or c == "{" then
    if decode_depth >= DECODE_MAX_DEPTH then
      error("JSON nesting depth exceeded " .. DECODE_MAX_DEPTH, 0)
    end
    decode_depth = decode_depth + 1
    local val, npos = char_func_map[c](str, pos)
    decode_depth = decode_depth - 1
    return val, npos
  end
  return char_func_map[c](str, pos)
end
json.decode = decode

-- ============================================================================
-- COMMAND HANDLERS - PROCESS & MODULES
-- ============================================================================

-- Shared helper: scan for MZ PE headers via AOB and read module names from export directories.
-- Returns a list of {name, address, size, is_64bit, path, source} entries (up to maxCount).
-- Names are only taken from real PE export directories; otherwise the entry is named "Module_<HEX>".
local function aobScanPEModules(maxCount)
    maxCount = maxCount or 50
    local found = {}
    local mzScan = AOBScan("4D 5A 90 00 03 00 00 00")
    if not mzScan or mzScan.Count == 0 then return found end
    for i = 0, math.min(mzScan.Count - 1, maxCount - 1) do
        local addr = tonumber(mzScan.getString(i), 16)
        if addr then
            local peOffset = readInteger(addr + 0x3C)
            local moduleSize = 0
            local realName = nil
            if peOffset and peOffset > 0 and peOffset < 0x1000 then
                local sizeOfImage = readInteger(addr + peOffset + 0x50)
                if sizeOfImage then moduleSize = sizeOfImage end
                local exportRVA = readInteger(addr + peOffset + 0x78)
                if exportRVA and exportRVA > 0 and exportRVA < 0x10000000 then
                    local nameRVA = readInteger(addr + exportRVA + 0x0C)
                    if nameRVA and nameRVA > 0 and nameRVA < 0x10000000 then
                        local name = readString(addr + nameRVA, 64)
                        if name and #name > 0 and #name < 60 then
                            realName = name
                        end
                    end
                end
            end
            table.insert(found, {
                name    = realName or ("Module_" .. string.format("%X", addr)),
                address = toHex(addr),
                size    = moduleSize,
                is_64bit = false,
                path    = "",
                source  = realName and "export_directory" or "aob_fallback",
                real_name = realName  -- kept for callers that need to know if it's verified
            })
        end
    end
    mzScan.destroy()
    return found
end

function cmd_get_process_info(params)
    -- reinitializeSymbolhandler is expensive (rescans all modules for
    -- symbols); polling this tool used to force a full reload every call.
    -- Opt in explicitly with refresh_symbols=true when fresh symbols matter.
    if params.refresh_symbols == true then
        pcall(reinitializeSymbolhandler)
    end
    
    local pid = getOpenedProcessID()
    if pid and pid > 0 then
        -- Get modules using the same logic as enum_modules (with AOB fallback)
        local modules = enumModules(pid)
        if not modules or #modules == 0 then
            modules = enumModules()
        end
        
        -- Build module list
        local moduleList = {}
        local mainModuleName = nil
        local usedAobFallback = false
        
        if modules and #modules > 0 then
            for i = 1, math.min(#modules, 50) do
                local m = modules[i]
                if m then
                    table.insert(moduleList, {
                        name = m.Name or "???",
                        address = toHex(m.Address or 0),
                        size = m.Size or 0
                    })
                    if i == 1 then mainModuleName = m.Name end
                end
            end
        end
        
        -- If still no modules, fall back to an MZ-header AOB scan that reads
        -- module names out of each PE export directory.
        -- NOTE: only ONE scanner runs. Running both findModulesViaMZScan and
        -- aobScanPEModules produced the same addresses twice, so the reported
        -- module_count was inflated and every module appeared two or three times.
        if #moduleList == 0 then
            usedAobFallback = true
            local aobModules = aobScanPEModules(50)
            if #aobModules == 0 then aobModules = findModulesViaMZScan(50) end
            for idx, m in ipairs(aobModules) do
                table.insert(moduleList, {
                    name    = m.name,
                    address = m.address,
                    size    = m.size,
                    source  = m.source
                })
                if idx == 1 then
                    mainModuleName = m.real_name or ((process ~= "" and process) or nil)
                end
            end
        end

        -- If neither enumModules nor the AOB fallback produced any modules, report failure honestly
        if #moduleList == 0 then
            return {
                success = false,
                error = "Process attached but cannot enumerate modules (likely anti-cheat interference). Try enum_modules directly, or attach to a different process.",
                error_code = "CE_API_UNAVAILABLE",
                process_id = pid
            }
        end

        -- Use the best available module-derived process name
        local name = mainModuleName or (moduleList[1] and moduleList[1].name) or "UnknownProcess"

        return {
            success = true,
            process_id = pid,
            process_name = name,
            module_count = #moduleList,
            modules = moduleList,
            used_aob_fallback = usedAobFallback
        }
    end
    return { success = false, error = "No process attached" }
end

function cmd_enum_modules(params)
    local pid = getOpenedProcessID()
    local modules = enumModules(pid)  -- Try with PID first
    
    -- If that fails, try without PID
    if not modules or #modules == 0 then
        modules = enumModules()
    end
    
    local result = {}
    if modules and #modules > 0 then
        for i, m in ipairs(modules) do
            if m then
                table.insert(result, {
                    name = m.Name or "???",
                    address = toHex(m.Address or 0),
                    size = m.Size or 0,
                    is_64bit = m.Is64Bit or false,
                    path = m.PathToFile or ""
                })
            end
        end
    end
    
    -- Fallback: If no modules found, run ONE MZ-header scan with
    -- export-directory name resolution (running two scanners duplicated entries).
    if #result == 0 then
        local aobModules = aobScanPEModules(50)
        if #aobModules == 0 then aobModules = findModulesViaMZScan(50) end
        for _, m in ipairs(aobModules) do
            table.insert(result, {
                name     = m.name,
                address  = m.address,
                size     = m.size,
                is_64bit = m.is_64bit or false,
                path     = m.path or "",
                source   = m.source
            })
        end
    end

    -- If both enumModules and the AOB fallback failed to produce any modules, report failure honestly
    if #result == 0 and (pid or 0) > 0 then
        return {
            success = false,
            error = "Process attached but cannot enumerate modules (likely anti-cheat interference). Try enum_modules directly, or attach to a different process.",
            error_code = "CE_API_UNAVAILABLE",
            process_id = pid
        }
    end
    
    local fallback_used = #result > 0 and result[1] and result[1].source ~= nil
    local limit, offset, page, total = paginate(params, result, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, modules = page, fallback_used = fallback_used }
end

function cmd_get_symbol_address(params)
    local symbol = params.symbol or params.name
    if not symbol then return { success = false, error = "No symbol name" } end
    
    local addr = getAddressSafe(symbol)
    if addr then
        return { success = true, symbol = symbol, address = toHex(addr), value = addr }
    end
    return { success = false, error = "Symbol not found: " .. symbol }
end

-- ============================================================================
-- COMMAND HANDLERS - MEMORY READ
-- ============================================================================

function cmd_read_memory(params)
    local addr = params.address
    local size = math.max(1, math.min(params.size or 256, 1048576))  -- 1 MB max
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local bytes = readBytes(addr, size, true)
    if not bytes then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    local hex = {}
    for i, b in ipairs(bytes) do hex[i] = string.format("%02X", b) end

    local result = {
        success = true,
        address = toHex(addr),
        size = #bytes,
        data = table.concat(hex, " ")
    }
    -- "bytes" is the same information as "data" but as a JSON array, i.e. ~4x
    -- the wire size. A 1 MB read used to ship ~3 MB of hex plus ~4 MB of array.
    -- Send it only when the caller explicitly asks for it.
    if params.include_bytes == true then result.bytes = bytes end
    return result
end

function cmd_read_integer(params)
    local addr = params.address
    local itype = params.type or "dword"
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local val
    if itype == "byte" then
        local b = readBytes(addr, 1, true)
        if b and #b > 0 then val = b[1] end
    elseif itype == "word" then val = readSmallInteger(addr)
    elseif itype == "dword" then val = readInteger(addr)
    elseif itype == "qword" then val = readQword(addr)
    elseif itype == "float" then val = readFloat(addr)
    elseif itype == "double" then val = readDouble(addr)
    else return { success = false, error = "Unknown type: " .. tostring(itype) } end
    
    if val == nil then return { success = false, error = "Failed to read at " .. toHex(addr) } end
    
    return { success = true, address = toHex(addr), value = val, type = itype, hex = toHex(val) }
end

function cmd_read_string(params)
    local addr = params.address
    local maxlen = tonumber(params.max_length) or 256
    -- Every byte flows through readString/readBytes plus per-byte escaping on
    -- the CE main thread; an unclamped max_length would freeze CE.
    if maxlen < 1 then maxlen = 1 end
    if maxlen > 1024 * 1024 then maxlen = 1024 * 1024 end
    local wide = params.wide or false
    -- encoding: "ascii" | "utf8" | "utf16le" | "raw" (default "utf8")
    -- Backward compat: wide=true maps to utf16le unless encoding is explicitly set
    local encoding = params.encoding or (wide and "utf16le" or "utf8")

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local parts = {}
    local rawLen = 0

    if encoding == "utf16le" then
        local str = readString(addr, maxlen, true)
        rawLen = str and #str or 0
        if str then
            for i = 1, #str do
                local byte = str:byte(i)
                if byte >= 32 and byte < 127 then
                    parts[#parts + 1] = str:sub(i, i)
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = str:sub(i, i)
                else
                    parts[#parts + 1] = string.format("\\x%02X", byte)
                end
            end
        end
    elseif encoding == "raw" then
        local bytes = readBytes(addr, maxlen, true)
        rawLen = bytes and #bytes or 0
        if bytes then
            for i, b in ipairs(bytes) do parts[i] = string.format("%02X", b) end
        end
        return { success = true, address = toHex(addr), value = table.concat(parts, " "), encoding = encoding, wide = false, length = rawLen, raw_length = rawLen }
    elseif encoding == "ascii" then
        local str = readString(addr, maxlen, false)
        rawLen = str and #str or 0
        if str then
            for i = 1, #str do
                local byte = str:byte(i)
                if byte >= 32 and byte < 127 then
                    parts[#parts + 1] = str:sub(i, i)
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = " "
                else
                    parts[#parts + 1] = string.format("\\x%02X", byte)
                end
            end
        end
    else
        -- utf8 (default): preserve valid UTF-8 multi-byte sequences; strip C0 controls
        local str = readString(addr, maxlen, false)
        rawLen = str and #str or 0
        if str then
            local i = 1
            while i <= #str do
                local byte = str:byte(i)
                if byte >= 0x80 then
                    local seqLen
                    if byte >= 0xF0 then seqLen = 4
                    elseif byte >= 0xE0 then seqLen = 3
                    elseif byte >= 0xC0 then seqLen = 2
                    else seqLen = 1 end  -- 0x80-0xBF: orphan continuation byte
                    if seqLen > 1 and i + seqLen - 1 <= #str then
                        local valid = true
                        for j = i + 1, i + seqLen - 1 do
                            local cb = str:byte(j)
                            if cb < 0x80 or cb > 0xBF then valid = false; break end
                        end
                        if valid then
                            parts[#parts + 1] = str:sub(i, i + seqLen - 1)
                            i = i + seqLen
                        else
                            parts[#parts + 1] = string.format("\\x%02X", byte)
                            i = i + 1
                        end
                    else
                        parts[#parts + 1] = string.format("\\x%02X", byte)
                        i = i + 1
                    end
                elseif byte == 9 or byte == 10 or byte == 13 then
                    parts[#parts + 1] = str:sub(i, i)
                    i = i + 1
                elseif byte >= 0x20 and byte < 0x80 then
                    parts[#parts + 1] = str:sub(i, i)
                    i = i + 1
                else
                    i = i + 1  -- strip C0 control bytes
                end
            end
        end
    end

    local sanitized = table.concat(parts)
    return { success = true, address = toHex(addr), value = sanitized, encoding = encoding, wide = (encoding == "utf16le"), length = rawLen, raw_length = #sanitized }
end

function cmd_read_pointer(params)
    local base = params.base or params.address
    local offsets = params.offsets or {}
    
    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local path = { toHex(base) }
    
    for i, offset in ipairs(offsets) do
        -- Use readPointer for 32/64-bit compatibility (readInteger on 32-bit, readQword on 64-bit)
        local ptr = readPointer(currentAddr)
        if not ptr then
            return { success = false, error = "Failed to read pointer at " .. toHex(currentAddr), path = path }
        end
        currentAddr = ptr + offset
        table.insert(path, toHex(currentAddr))
    end
    
    -- Read final value using readPointer for 32/64-bit compatibility
    local finalValue = readPointer(currentAddr)
    return { 
        success = true, 
        base = toHex(base), 
        final_address = toHex(currentAddr), 
        value = finalValue, 
        path = path 
    }
end

-- ============================================================================
-- COMMAND HANDLERS - PATTERN SCANNING
-- ============================================================================

function cmd_aob_scan(params)
    local pattern = params.pattern
    local _texp, _terr = expandSigTokens(pattern)
    if _texp == nil then return _terr end
    pattern = _texp
    local protection = params.protection or "+X"
    local limit = clampPaging(params, 100)

    if not pattern then return { success = false, error = "No pattern provided" } end
    
    local results = AOBScan(pattern, protection)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addrStr = results.getString(i)
        local addr = tonumber(addrStr, 16)
        table.insert(addresses, { 
            address = "0x" .. addrStr, 
            value = addr 
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, pattern = pattern, addresses = addresses }
end

function cmd_scan_all(params)
    local value = params.value
    if value == nil or value == "" then
        return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" }
    end
    -- v15.8.2: 'type' is the VALUE type here (byte/word/dword/qword/float/
    -- double/string) even though the Python docstring historically called it
    -- the scan type ("exact"). Accept the legacy names explicitly, reject
    -- everything else, and resolve BEFORE createMemScan so typos fail fast.
    local vtype = (params.var_type or params.type or "dword"):lower()
    if vtype == "exact" or vtype == "array" then vtype = "dword" end

    -- Strict value-type mapping inline (this handler sits above the shared
    -- resolveVarType local, which is not yet in scope here).
    local varType
    if     vtype == "byte"   then varType = vtByte
    elseif vtype == "word"   then varType = vtWord
    elseif vtype == "dword"  then varType = vtDword
    elseif vtype == "qword"  then varType = vtQword
    elseif vtype == "float"  then varType = vtSingle
    elseif vtype == "double" then varType = vtDouble
    elseif vtype == "string" then varType = vtString end
    if not varType then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "unknown value type '" .. tostring(params.type) .. "' (valid: " .. VAR_TYPE_NAMES
                         .. "; legacy aliases: exact, array -> dword)" }
    end

    local ms = createMemScan()
    local scanOpt = soExactValue
    
    -- Use specific protection flags if provided (defaults to +W-C from Python)
    -- CRITICAL: Limit scan to User Mode space (0x7FFFFFFFFFFFFFFF) to prevent BSODs in Kernel/Guard regions
    local protect = params.protection or "+W-C"
    ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil, 0, 0x7FFFFFFFFFFFFFFF, protect, fsmNotAligned, "1", false, false, false, false)
    ms.waitTillDone()
    
    local fl = createFoundList(ms)
    fl.initialize()
    local count = fl.getCount()
    
    if serverState.scan_foundlist then
        pcall(function() serverState.scan_foundlist.destroy() end)
        serverState.scan_foundlist = nil
    end
    if serverState.scan_memscan then
        pcall(function() serverState.scan_memscan.destroy() end)
        serverState.scan_memscan = nil
    end

    serverState.scan_memscan = ms
    serverState.scan_foundlist = fl

    return { success = true, count = count }
end

function cmd_get_scan_results(params)
    -- limit (alias: max), offset clamped by the shared paging helper
    local limit, offset = clampPaging(params, 100)

    if not serverState.scan_foundlist then
        return { success = false, error = "No scan results. Run scan_all first." }
    end

    local fl = serverState.scan_foundlist
    local total = fl.getCount()
    local results = {}
    local endIdx = math.min(offset + limit, total) - 1

    for i = offset, endIdx do
        -- IMPORTANT: Ensure address has 0x prefix for consistency with all other commands
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0x") and not addrStr:match("^0X") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value = fl.getValue(i)
        })
    end

    return { success = true, total = total, offset = offset, limit = limit, returned = #results, results = results }
end

-- ============================================================================
-- COMMAND HANDLERS - NEXT SCAN & WRITE MEMORY (Added by MCP Enhancement)
-- ============================================================================

function cmd_next_scan(params)
    local value = params.value
    local scanType = params.scan_type or "exact"
    
    if not serverState.scan_memscan then
        return { success = false, error = "No previous scan. Run scan_all first." }
    end
    
    local ms = serverState.scan_memscan
    local scanOpt = soExactValue
    
    if scanType == "increased" then scanOpt = soIncreasedValue
    elseif scanType == "decreased" then scanOpt = soDecreasedValue
    elseif scanType == "changed" then scanOpt = soChanged
    elseif scanType == "unchanged" then scanOpt = soUnchanged
    elseif scanType == "bigger" then scanOpt = soBiggerThan
    elseif scanType == "smaller" then scanOpt = soSmallerThan
    end
    
    if scanOpt == soExactValue then
        ms.nextScan(scanOpt, rtRounded, tostring(value), nil, false, false, false, false, false)
    else
        ms.nextScan(scanOpt, rtRounded, nil, nil, false, false, false, false, false)
    end
    ms.waitTillDone()
    
    if serverState.scan_foundlist then
        -- destroy() can throw when the previous scan session was torn down
        -- externally; scan_all guards the same call, so does next_scan.
        pcall(function() serverState.scan_foundlist.destroy() end)
    end
    local fl = createFoundList(ms)
    fl.initialize()
    serverState.scan_foundlist = fl
    
    return { success = true, count = fl.getCount() }
end

function cmd_write_integer(params)
    local addr = params.address
    local value = params.value
    local vtype = params.type or "dword"

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    if vtype == "byte" then
        if type(value) ~= "number" or value < 0 or value > 0xFF then
            return { success = false, error = "Value out of range for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "word" or vtype == "2bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFF then
            return { success = false, error = "Value out of range for type", error_code = "INVALID_PARAMS" }
        end
    elseif vtype == "dword" or vtype == "4bytes" then
        if type(value) ~= "number" or value < 0 or value > 0xFFFFFFFF then
            return { success = false, error = "Value out of range for type", error_code = "INVALID_PARAMS" }
        end
    end

    local ok, err
    if vtype == "byte" then
        ok, err = pcall(writeByte, addr, value)
    elseif vtype == "word" or vtype == "2bytes" then
        ok, err = pcall(writeSmallInteger, addr, value)
    elseif vtype == "dword" or vtype == "4bytes" then
        ok, err = pcall(writeInteger, addr, value)
    elseif vtype == "qword" or vtype == "8bytes" then
        ok, err = pcall(writeQword, addr, value)
    elseif vtype == "float" then
        ok, err = pcall(writeFloat, addr, value)
    elseif vtype == "double" then
        ok, err = pcall(writeDouble, addr, value)
    else
        return { success = false, error = "Unknown type: " .. tostring(vtype) }
    end

    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end

    return { success = true, address = toHex(addr), value = value, type = vtype }
end

function cmd_write_memory(params)
    local addr = params.address
    local bytes = params.bytes
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if not bytes or #bytes == 0 then return { success = false, error = "No bytes provided" } end
    
    local ok, err = pcall(writeBytes, addr, bytes)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), bytes_written = #bytes }
end

function cmd_write_string(params)
    local addr = params.address
    local str = params.value or params.string
    local wide = params.wide or false
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    if not str then return { success = false, error = "No string provided" } end
    
    local ok, err = pcall(writeString, addr, str, wide)
    
    if not ok then
        return { success = false, error = "Write failed: " .. tostring(err), address = toHex(addr) }
    end
    
    return { success = true, address = toHex(addr), length = #str, wide = wide }
end


-- ============================================================================
-- COMMAND HANDLERS - DISASSEMBLY & ANALYSIS
-- ============================================================================

function cmd_disassemble(params)
    local addr = params.address
    local count = math.max(1, math.min(params.count or 20, 1000))

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local allInstructions = {}
    local currentAddr = addr

    for i = 1, count do
        local ok, disasm = pcall(disassemble, currentAddr)
        if not ok or not disasm then break end

        local instSize = getInstructionSize(currentAddr) or 1
        local instBytes = readBytes(currentAddr, instSize, true) or {}
        local bytesHex = {}
        for _, b in ipairs(instBytes) do table.insert(bytesHex, string.format("%02X", b)) end

        table.insert(allInstructions, {
            address = toHex(currentAddr),
            offset = currentAddr - addr,
            size = instSize,
            bytes = table.concat(bytesHex, " "),
            instruction = disasm
        })

        currentAddr = currentAddr + instSize
    end

    local limit, offset, page, total = paginate(params, allInstructions, 100)
    -- Returning success=true with zero instructions used to hide the fact that
    -- nothing was disassembled at all (unreadable page, bad address).
    if total == 0 then
        return { success = false, error_code = "INVALID_ADDRESS",
                 error = "Nothing to disassemble at " .. toHex(addr) .. " (unreadable or not code)",
                 start_address = toHex(addr) }
    end
    return { success = true, start_address = toHex(addr), total = total, offset = offset, limit = limit, returned = #page, instructions = page }
end

function cmd_get_instruction_info(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local ok, disasm = pcall(disassemble, addr)
    if not ok or not disasm then
        return { success = false, error = "Failed to disassemble at " .. toHex(addr) }
    end
    local size = getInstructionSize(addr)
    local bytes = readBytes(addr, size or 1, true) or {}
    local bytesHex = {}
    for _, b in ipairs(bytes) do table.insert(bytesHex, string.format("%02X", b)) end
    
    local prevAddr = getPreviousOpcode(addr)
    
    return {
        success = true,
        address = toHex(addr),
        instruction = disasm,
        size = size,
        bytes = table.concat(bytesHex, " "),
        previous_instruction = prevAddr and toHex(prevAddr) or nil
    }
end

function cmd_find_function_boundaries(params)
    local addr = params.address
    local maxSearch = tonumber(params.max_search) or 4096
    -- One readBytes round-trip per offset below; unclamped max_search = freeze.
    if maxSearch < 16 then maxSearch = 16 end
    if maxSearch > 65536 then maxSearch = 65536 end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()

    local funcStart, prologueType = findFunctionPrologue(addr, maxSearch)

    -- Search forwards for return instruction
    local funcEnd = nil
    if funcStart then
        for offset = 0, maxSearch do
            local b = readBytes(funcStart + offset, 1, false)
            if b == 0xC3 or b == 0xC2 then
                funcEnd = funcStart + offset
                break
            end
        end
    end

    local found = funcStart ~= nil

    return {
        success = true,
        found = found,
        query_address = toHex(addr),
        function_start = funcStart and toHex(funcStart) or nil,
        function_end = funcEnd and toHex(funcEnd) or nil,
        function_size = (funcStart and funcEnd) and (funcEnd - funcStart + 1) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        note = not found and "No standard function prologue found within search range" or nil
    }
end

function cmd_analyze_function(params)
    local addr = params.address
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local is64 = targetIs64Bit()

    local funcStart, prologueType = findFunctionPrologue(addr, 4096)

    if not funcStart then 
        return { 
            success = false, 
            error = "Could not find function start",
            arch = is64 and "x64" or "x86",
            query_address = toHex(addr)
        } 
    end
    
    -- Analyze calls within function
    local calls = {}
    local funcEnd = nil
    local currentAddr = funcStart
    
    while currentAddr < funcStart + 0x2000 do
        local instSize = getInstructionSize(currentAddr)
        if not instSize or instSize == 0 then break end
        
        local b1 = readBytes(currentAddr, 1, false)
        if b1 == 0xC3 or b1 == 0xC2 then
            funcEnd = currentAddr
            break
        end
        
        -- Detect CALL instructions
        -- E8 xx xx xx xx = relative CALL (most common)
        if b1 == 0xE8 then
            local relOffset = readInteger(currentAddr + 1)
            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    target = toHex(currentAddr + 5 + relOffset),
                    type = "relative"
                })
            end
        end
        
        -- FF /2 = indirect CALL (CALL r/m32 or CALL r/m64)
        if b1 == 0xFF then
            local b2 = readBytes(currentAddr + 1, 1, false)
            if b2 and (b2 >= 0x10 and b2 <= 0x1F) then  -- ModR/M for /2
                local disasm = disassemble(currentAddr)
                table.insert(calls, {
                    call_site = toHex(currentAddr),
                    instruction = disasm,
                    type = "indirect"
                })
            end
        end
        
        currentAddr = currentAddr + instSize
    end
    
    return {
        success = true,
        function_start = toHex(funcStart),
        function_end = funcEnd and toHex(funcEnd) or nil,
        prologue_type = prologueType,
        arch = is64 and "x64" or "x86",
        call_count = #calls,
        calls = calls
    }
end

-- ============================================================================
-- COMMAND HANDLERS - REFERENCE FINDING
-- ============================================================================

function cmd_find_references(params)
    local targetAddr = params.address

    if type(targetAddr) == "string" then targetAddr = getAddressSafe(targetAddr) end
    if not targetAddr then return { success = false, error = "Invalid address" } end

    local is64 = targetIs64Bit()
    local pattern

    -- Convert address to AOB pattern (little-endian)
    if is64 and targetAddr > 0xFFFFFFFF then
        -- 64-bit address: 8 bytes little-endian
        local bytes = {}
        local tempAddr = targetAddr
        for i = 1, 8 do
            bytes[i] = tempAddr % 256
            tempAddr = math.floor(tempAddr / 256)
        end
        pattern = string.format("%02X %02X %02X %02X %02X %02X %02X %02X",
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8])
    else
        -- 32-bit address: 4 bytes little-endian
        local b1 = targetAddr % 256
        local b2 = math.floor(targetAddr / 256) % 256
        local b3 = math.floor(targetAddr / 65536) % 256
        local b4 = math.floor(targetAddr / 16777216) % 256
        pattern = string.format("%02X %02X %02X %02X", b1, b2, b3, b4)
    end

    local scanResults = AOBScan(pattern, "+X")
    if not scanResults then
        local limit, offset, page, total = paginate(params, {}, 50)
        return { success = true, target = toHex(targetAddr), total = total, offset = offset, limit = limit, returned = 0, references = {}, arch = is64 and "x64" or "x86" }
    end

    local allRefs = {}
    -- Each hit costs a disassemble() on the CE main thread; cap the loop and
    -- report truncation instead of freezing CE on a pointer with many refs.
    local MAX_DISASM_REFS = 4096
    local refTruncated = false
    for i = 0, scanResults.Count - 1 do
        if #allRefs >= MAX_DISASM_REFS then refTruncated = true break end
        local refAddr = tonumber(scanResults.getString(i), 16)
        local disasm = disassemble(refAddr) or "???"
        allRefs[#allRefs + 1] = { address = toHex(refAddr), instruction = disasm }
    end
    scanResults.destroy()

    local limit, offset, page, total = paginate(params, allRefs, 50)
    return { success = true, target = toHex(targetAddr), total = total, offset = offset, limit = limit, returned = #page, references = page, truncated = refTruncated, arch = is64 and "x64" or "x86" }
end

function cmd_find_call_references(params)
    local funcAddr = params.address or params.function_address

    if type(funcAddr) == "string" then funcAddr = getAddressSafe(funcAddr) end
    if not funcAddr then return { success = false, error = "Invalid function address" } end

    -- Collect ALL matching callers to get accurate total for pagination.
    -- readInteger per E8 site adds up fast across a whole address space; cap
    -- the walk and report truncation instead of freezing CE.
    local MAX_CALL_SITES = 100000
    local callTruncated = false
    local allCallers = {}
    local scanResults = AOBScan("E8 ?? ?? ?? ??", "+X")

    if scanResults then
        for i = 0, scanResults.Count - 1 do
            if i >= MAX_CALL_SITES then callTruncated = true break end
            local callAddr = tonumber(scanResults.getString(i), 16)
            local relOffset = readInteger(callAddr + 1)

            if relOffset then
                if relOffset > 0x7FFFFFFF then relOffset = relOffset - 0x100000000 end
                local target = callAddr + 5 + relOffset

                if target == funcAddr then
                    allCallers[#allCallers + 1] = {
                        caller_address = toHex(callAddr),
                        instruction = disassemble(callAddr) or "???"
                    }
                end
            end
        end
        scanResults.destroy()
    end

    local limit, offset, page, total = paginate(params, allCallers, 100)
    return { success = true, function_address = toHex(funcAddr), total = total, offset = offset, limit = limit, returned = #page, callers = page, truncated = callTruncated }
end

-- ============================================================================
-- COMMAND HANDLERS - BREAKPOINTS
-- ============================================================================

-- Clears any hw_bp_slots entry (and its tracking tables) whose address matches
-- addr, so the slot is available for re-use without leaking the old entry.
local function clearGhostBpSlot(addr)
    for i = 1, 4 do
        if serverState.hw_bp_slots[i] and serverState.hw_bp_slots[i].address == addr then
            local oldId = serverState.hw_bp_slots[i].id
            serverState.hw_bp_slots[i] = nil
            if oldId then
                serverState.breakpoints[oldId] = nil
                serverState.breakpoint_hits[oldId] = nil
            end
        end
    end
end

function cmd_set_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local captureRegs = params.capture_registers ~= false
    local captureStackFlag = params.capture_stack or false
    local stackDepth = params.stack_depth or 16
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    clearGhostBpSlot(addr)

    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end

    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end

    -- Remove existing breakpoint at this address
    pcall(function() debug_removeBreakpoint(addr) end)

    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, 1, bptExecute, bpmDebugRegister, function()
        local hitData = {
            id = bpId,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_execute"
        }
        
        if captureRegs then
            hitData.registers = captureRegisters()
        end
        
        if captureStackFlag then
            hitData.stack = captureStack(stackDepth)
        end
        
        recordBPHit(bpId, hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "execute" }
    return { success = true, id = bpId, address = toHex(addr), slot = slot, method = "hardware_debug_register" }
end

function cmd_set_data_breakpoint(params)
    local addr = params.address
    local bpId = params.id
    local accessType = params.access_type or "w"  -- r, w, rw
    local size = params.size or 4
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    bpId = bpId or tostring(addr)
    -- Avoid collision if an existing breakpoint has the same ID
    if serverState.breakpoints[bpId] then
        local suffix = 2
        while serverState.breakpoints[bpId .. "_" .. suffix] do suffix = suffix + 1 end
        bpId = bpId .. "_" .. suffix
    end

    clearGhostBpSlot(addr)

    -- Find free hardware slot (max 4 debug registers)
    local slot = nil
    for i = 1, 4 do
        if not serverState.hw_bp_slots[i] then
            slot = i
            break
        end
    end

    if not slot then
        return { success = false, error = "No free hardware breakpoint slots (max 4 debug registers)" }
    end

    local bpType = bptWrite
    if accessType == "r" then bpType = bptAccess
    elseif accessType == "rw" then bpType = bptAccess end
    
    serverState.breakpoint_hits[bpId] = {}
    
    -- CRITICAL: Use bpmDebugRegister for hardware breakpoints (anti-cheat safe)
    -- Signature: debug_setBreakpoint(address, size, trigger, breakpointmethod, function)
    debug_setBreakpoint(addr, size, bpType, bpmDebugRegister, function()
        local arch = getArchInfo()
        local instPtr = arch.instPtr
        local hitData = {
            id = bpId,
            type = "data_" .. accessType,
            address = toHex(addr),
            timestamp = os.time(),
            breakpoint_type = "hardware_data",
            value = arch.is64bit and readQword(addr) or readInteger(addr),
            registers = captureRegisters(),
            instruction = instPtr and disassemble(instPtr) or "???",
            arch = arch.is64bit and "x64" or "x86"
        }
        
        recordBPHit(bpId, hitData)
        debug_continueFromBreakpoint(co_run)
        return 1
    end)
    
    serverState.hw_bp_slots[slot] = { id = bpId, address = addr }
    serverState.breakpoints[bpId] = { address = addr, slot = slot, type = "data" }
    
    return { success = true, id = bpId, address = toHex(addr), slot = slot, access_type = accessType, method = "hardware_debug_register" }
end

function cmd_remove_breakpoint(params)
    local bpId = params.id
    
    if bpId and serverState.breakpoints[bpId] then
        local bp = serverState.breakpoints[bpId]
        pcall(function() debug_removeBreakpoint(bp.address) end)
        
        if bp.slot then
            serverState.hw_bp_slots[bp.slot] = nil
        end
        
        serverState.breakpoints[bpId] = nil
        return { success = true, id = bpId }
    end
    
    return { success = false, error = "Breakpoint not found: " .. tostring(bpId) }
end

function cmd_get_breakpoint_hits(params)
    local bpId = params.id
    -- Default is "peek, do not consume" — matches the Python tool signature
    -- (clear: bool = False). The old `params.clear ~= false` meant an omitted
    -- flag silently flushed the hit buffer on every read.
    local clear = params.clear == true

    local hits
    if bpId then
        hits = serverState.breakpoint_hits[bpId] or {}
        if clear then serverState.breakpoint_hits[bpId] = {} end
    else
        hits = {}
        for id, hitsForBp in pairs(serverState.breakpoint_hits) do
            for _, hit in ipairs(hitsForBp) do
                hits[#hits + 1] = hit
            end
        end
        if clear then serverState.breakpoint_hits = {} end
    end

    local limit, offset, page, total = paginate(params, hits, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, hits = page }
end

function cmd_list_breakpoints(params)
    local list = {}
    for id, bp in pairs(serverState.breakpoints) do
        table.insert(list, {
            id = id,
            address = toHex(bp.address),
            type = bp.type or "execution",
            slot = bp.slot
        })
    end
    return { success = true, count = #list, breakpoints = list }
end

function cmd_clear_all_breakpoints(params)
    local count = 0
    for id, bp in pairs(serverState.breakpoints) do
        pcall(function() debug_removeBreakpoint(bp.address) end)
        count = count + 1
    end
    serverState.breakpoints = {}
    serverState.breakpoint_hits = {}
    serverState.hw_bp_slots = {}
    return { success = true, removed = count }
end

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

-- Serialize an arbitrary Lua value into a human-readable string. Plain data
-- tables are emitted as JSON (so AI clients can parse them); anything holding
-- userdata/CE objects falls back to a shallow structural dump. Depth 0 keeps
-- plain strings verbatim (a `return "hello"` must not arrive as `"hello"`).
local function serializeLuaValue(v, depth)
    depth = depth or 0
    local tv = type(v)
    if tv == "nil" then return "nil" end
    if tv == "number" or tv == "boolean" then return tostring(v) end
    if tv == "string" then
        if depth == 0 then return v end
        return string.format("%q", v)
    end
    if tv == "table" then
        if depth >= 4 then return "{...}" end
        local ok, encoded = pcall(json.encode, v)
        if ok and type(encoded) == "string" and #encoded <= 16000 then
            return encoded
        end
        local parts, n = {}, 0
        for k, val in pairs(v) do
            n = n + 1
            if n > 32 then
                table.insert(parts, "... (truncated)")
                break
            end
            local key = (type(k) == "string") and k or ("[" .. tostring(k) .. "]")
            table.insert(parts, key .. " = " .. serializeLuaValue(val, depth + 1))
        end
        return "{ " .. table.concat(parts, ", ") .. " }"
    end
    return tostring(v)
end

function cmd_evaluate_lua(params)
    local code = params.code
    if type(code) ~= "string" or code == "" then
        return { success = false, error = "code required", error_code = "INVALID_PARAMS" }
    end

    local fn, err = load(code, "mcp_evaluate_lua", "t")
    if not fn then
        return { success = false, error = "Compile error: " .. tostring(err),
                 error_code = "INVALID_PARAMS" }
    end

    -- Capture print() output so diagnostics do not leak into the CE console
    -- (and to the CE UI) instead of back to the caller. Output is capped:
    -- a runaway print loop must not balloon the response payload.
    local MAX_PRINTED_LINES = 200
    local printed = {}
    local printedTruncated = false
    local realPrint = print
    -- xpcall with a traceback handler: by the time pcall has returned, the
    -- stack is unwound and debug.traceback can no longer see the error site.
    local ok, result = xpcall(function()
        print = function(...)
            if #printed >= MAX_PRINTED_LINES then printedTruncated = true return end
            local n = select("#", ...)
            local parts = {}
            for i = 1, n do parts[#parts + 1] = tostring(select(i, ...)) end
            printed[#printed + 1] = table.concat(parts, "\t")
        end
        return fn()
    end, function(m)
        return debug.traceback(tostring(m), 2)
    end)
    print = realPrint

    if not ok then
        -- result is "<message>\nstack traceback:\n\t..." — split so the
        -- message stays greppable and the stack is a separate field.
        local msg = tostring(result)
        local firstLine = msg:match("^([^\n]*)")
        return { success = false, error = "Runtime error: " .. firstLine,
                 traceback = msg, printed = printed,
                 printed_truncated = printedTruncated or nil,
                 error_code = "INTERNAL_ERROR" }
    end

    local resp = { success = true, result = serializeLuaValue(result) }
    if #printed > 0 then resp.printed = printed end
    if printedTruncated then
        resp.printed_truncated = true
        resp.note = "print output capped at " .. MAX_PRINTED_LINES .. " lines"
    end
    return resp
end

-- >>> BEGIN UNIT-22 Threading Sync <<<
-- ============================================================================
-- COMMAND HANDLERS - THREADING & SYNCHRONIZATION
-- These operate on CE's Lua scripting host, NOT the target process.
-- No process guard is needed or appropriate here.
-- ============================================================================

local _unit22_thread_counter = 0

function cmd_create_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process.
    -- It carries the same risk as evaluate_lua. Only use with trusted code.
    -- THREADING NOTE: the code runs on a CE worker thread. CE GUI/API objects
    -- (forms, memory records, debugger...) must be touched via synchronize()
    -- from inside the thread; raw memory reads are usually safe off-thread.
    local code = params.code
    local arg  = params.arg or ""
    if not code then return { success = false, error = "No code provided" } end

    local ok, err = pcall(function()
        createThread(function(thread, a)
            local f, ferr = load(code, "mcp_thread", "t")
            if not f then error("Compile error: " .. tostring(ferr)) end
            return f(thread, a)
        end, arg)
    end)

    if not ok then
        return { success = false, error = "createThread failed: " .. tostring(err) }
    end
    _unit22_thread_counter = _unit22_thread_counter + 1
    return { success = true, thread_id = _unit22_thread_counter }
end

function cmd_get_global_variable(params)
    local name = params.name
    if not name then return { success = false, error = "No variable name provided" } end

    local ok, value = pcall(getGlobalVariable, name)
    if not ok then
        return { success = false, error = "getGlobalVariable failed: " .. tostring(value) }
    end
    return { success = true, value = tostring(value) }
end

function cmd_set_global_variable(params)
    local name  = params.name
    local value = params.value
    if not name  then return { success = false, error = "No variable name provided"  } end
    if value == nil then return { success = false, error = "No value provided" } end

    local ok, err = pcall(setGlobalVariable, name, value)
    if not ok then
        return { success = false, error = "setGlobalVariable failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_queue_to_main_thread(params)
    -- SECURITY WARNING: This tool executes arbitrary Lua code inside CE's process
    -- on the main thread. It carries the same risk as evaluate_lua.
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end

    local ok, err = pcall(function()
        queue(function()
            local f, ferr = loadstring(code)
            if not f then error("Compile error: " .. tostring(ferr)) end
            f()
        end)
    end)

    if not ok then
        return { success = false, error = "queue failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_check_synchronize(params)
    local ok, err = pcall(checkSynchronize)
    if not ok then
        return { success = false, error = "checkSynchronize failed: " .. tostring(err) }
    end
    return { success = true }
end

function cmd_in_main_thread(params)
    local ok, result = pcall(inMainThread)
    if not ok then
        return { success = false, error = "inMainThread failed: " .. tostring(result) }
    end
    return { success = true, is_main_thread = result == true }
end

-- >>> END UNIT-22 <<<

-- ============================================================================
-- COMMAND HANDLERS - MEMORY REGIONS
-- ============================================================================

function cmd_get_memory_regions(params)
    local ok, allRegs = pcall(enumMemoryRegions)
    if not ok or not allRegs then
        return { success = false, error = "enumMemoryRegions failed: " .. tostring(allRegs), error_code = "INTERNAL_ERROR" }
    end

    local regions = {}
    for _, r in ipairs(allRegs) do
        local state = r.State or 0
        if state == 0x1000 then
            local prot = r.Protect or 0
            local rd = (prot == 0x02 or prot == 0x04 or prot == 0x20 or prot == 0x40)
            local wr = (prot == 0x04 or prot == 0x08 or prot == 0x40 or prot == 0x80)
            local ex = (prot == 0x10 or prot == 0x20 or prot == 0x40 or prot == 0x80)
            local protStr = ""
            if rd then protStr = protStr .. "R" end
            if wr then protStr = protStr .. "W" end
            if ex then protStr = protStr .. "X" end

            regions[#regions + 1] = {
                base       = toHex(r.BaseAddress or 0),
                size       = r.RegionSize or 0,
                protection = protStr,
                readable   = rd,
                writable   = wr,
                executable = ex
            }
        end
    end

    local limit, offset, page, total = paginate(params, regions, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, count = #page, regions = page }
end

-- ============================================================================
-- COMMAND HANDLERS - UTILITY
-- ============================================================================

function cmd_ping(params)
    return {
        success = true,
        version = VERSION,
        timestamp = os.time(),
        process_id = getOpenedProcessID() or 0,
        message = "CE MCP Bridge v" .. VERSION .. " alive"
    }
end

function cmd_search_string(params)
    local searchStr = params.string or params.pattern
    local wide = params.wide or false
    local limit = clampPaging(params, 100)

    if not searchStr then return { success = false, error = "No search string" } end
    
    -- Convert string to AOB pattern
    local pattern = ""
    for i = 1, #searchStr do
        if i > 1 then pattern = pattern .. " " end
        pattern = pattern .. string.format("%02X", searchStr:byte(i))
        if wide then pattern = pattern .. " 00" end
    end
    
    local results = AOBScan(pattern)
    if not results then return { success = true, count = 0, addresses = {} } end
    
    local addresses = {}
    for i = 0, math.min(results.Count - 1, limit - 1) do
        local addr = tonumber(results.getString(i), 16)
        local preview = readString(addr, 50, wide) or ""
        table.insert(addresses, {
            address = "0x" .. results.getString(i),
            preview = preview
        })
    end
    results.destroy()
    
    return { success = true, count = #addresses, addresses = addresses }
end

-- ============================================================================
-- COMMAND HANDLERS - HIGH-LEVEL ANALYSIS TOOLS
-- ============================================================================

-- Dissect Structure: Uses CE's Structure.autoGuess to map memory into typed fields
function cmd_dissect_structure(params)
    local address = params.address
    local size = math.max(1, math.min(params.size or 256, 65536))
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    -- Create a temporary structure and use autoGuess
    local ok, struct = pcall(createStructure, "MCP_TempStruct")
    if not ok or not struct then
        return { success = false, error = "Failed to create structure" }
    end
    
    -- Use the Structure class autoGuess method
    pcall(function() struct:autoGuess(address, 0, size) end)
    
    local elements = {}
    local count = struct.Count or 0
    
    for i = 0, count - 1 do
        local elem = struct.Element[i]
        if elem then
            local val = nil
            -- Try to get current value
            pcall(function() val = elem:getValue(address) end)
            
            table.insert(elements, {
                offset = elem.Offset,
                hex_offset = string.format("+0x%X", elem.Offset),
                name = elem.Name or "",
                vartype = elem.Vartype,
                bytesize = elem.Bytesize,
                current_value = val
            })
        end
    end
    
    -- Cleanup - don't add to global list
    pcall(function() struct:removeFromGlobalStructureList() end)
    
    return {
        success = true,
        base_address = toHex(address),
        size_analyzed = size,
        element_count = #elements,
        elements = elements
    }
end

-- Get Thread List: Returns all threads in the attached process
function cmd_get_thread_list(params)
    local list = createStringlist()
    getThreadlist(list)

    local allThreads = {}
    for i = 0, list.Count - 1 do
        local idHex = list[i]
        allThreads[#allThreads + 1] = { id_hex = idHex, id_int = tonumber(idHex, 16) }
    end
    list.destroy()

    local limit, offset, page, total = paginate(params, allThreads, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, threads = page }
end

-- AutoAssemble: Execute an AutoAssembler script
function cmd_auto_assemble(params)
    local script = params.script or params.code
    local _sexp, _serr = expandSigTokens(script)
    if _sexp == nil then return _serr end
    script = _sexp
    local disable = params.disable or false

    if not script then return { success = false, error = "No script provided" } end

    -- Same size gate as auto_assemble_check: execution on oversized scripts
    -- blocks the main thread for the whole assembly pass.
    if #script > AA_MAX_SCRIPT_SIZE then
        return { success = false,
                 error = string.format("Script too large: %d bytes (max %d). "
                     .. "Split it into sections and execute them separately.",
                     #script, AA_MAX_SCRIPT_SIZE),
                 error_code = "SCRIPT_TOO_LARGE" }
    end

    local success, disableInfo = autoAssemble(script)
    
    if success then
        local result = {
            success = true,
            executed = true
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo)
        }
    end
end

-- Enum Memory Regions Full: Uses CE's native enumMemoryRegions for accurate data
function cmd_enum_memory_regions_full(params)
    local ok, regions = pcall(enumMemoryRegions)
    if not ok or not regions then
        return { success = false, error = "enumMemoryRegions failed" }
    end

    local allRegions = {}
    for i, r in ipairs(regions) do
        local prot = r.Protect or 0
        local state = r.State or 0
        local protStr
        if     prot == 0x10 then protStr = "X"
        elseif prot == 0x20 then protStr = "RX"
        elseif prot == 0x40 then protStr = "RWX"
        elseif prot == 0x80 then protStr = "WX"
        elseif prot == 0x02 then protStr = "R"
        elseif prot == 0x04 then protStr = "RW"
        elseif prot == 0x08 then protStr = "W"
        else                     protStr = string.format("0x%X", prot)
        end

        allRegions[#allRegions + 1] = {
            base             = toHex(r.BaseAddress or 0),
            allocation_base  = toHex(r.AllocationBase or 0),
            size             = r.RegionSize or 0,
            state            = state,
            protect          = prot,
            protect_string   = protStr,
            type             = r.Type or 0,
            is_committed     = state == 0x1000,
            is_reserved      = state == 0x2000,
            is_free          = state == 0x10000
        }
    end

    local limit, offset, page, total = paginate(params, allRegions, 100)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, regions = page }
end

-- Read Pointer Chain: Follow a chain of pointers to resolve dynamic addresses
function cmd_read_pointer_chain(params)
    local base = params.base
    local offsets = params.offsets or {}
    
    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then return { success = false, error = "Invalid base address" } end
    
    local currentAddr = base
    local chain = { { step = 0, address = toHex(currentAddr), description = "base" } }
    
    for i, offset in ipairs(offsets) do
        -- Read pointer at current address
        local ptr = readPointer(currentAddr)
        if not ptr then
            return {
                success = false,
                error = "Failed to read pointer at step " .. i,
                partial_chain = chain,
                failed_at_address = toHex(currentAddr)
            }
        end
        
        -- Apply offset
        currentAddr = ptr + offset
        table.insert(chain, {
            step = i,
            address = toHex(currentAddr),
            offset = offset,
            hex_offset = string.format("+0x%X", offset),
            pointer_value = toHex(ptr)
        })
    end
    
    -- Try to read a value at the final address (using readPointer for 32/64-bit compatibility)
    local finalValue = nil
    pcall(function()
        finalValue = readPointer(currentAddr)
    end)
    
    return {
        success = true,
        base = toHex(base),
        offsets = offsets,
        final_address = toHex(currentAddr),
        final_value = finalValue,
        chain = chain
    }
end

-- Get RTTI Class Name: Uses C++ RTTI to identify object types
function cmd_get_rtti_classname(params)
    local address = params.address
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local className = getRTTIClassName(address)
    
    if className then
        return {
            success = true,
            address = toHex(address),
            class_name = className,
            found = true
        }
    else
        return {
            success = true,
            address = toHex(address),
            class_name = nil,
            found = false,
            note = "No RTTI information found at this address"
        }
    end
end

-- Get Address Info: Converts raw address to symbolic name (module+offset)
function cmd_get_address_info(params)
    local address = params.address
    local includeModules = params.include_modules ~= false  -- default true
    local includeSymbols = params.include_symbols ~= false  -- default true
    local includeSections = params.include_sections or false  -- default false
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local symbolicName = getNameFromAddress(address, includeModules, includeSymbols, includeSections)
    
    -- inModule() may fail or return nil in anti-cheat environments, so we check symbolicName too
    local isInModule = false
    local okInMod, inModResult = pcall(inModule, address)
    if okInMod and inModResult then
        isInModule = true
    elseif symbolicName and symbolicName:match("%+") then
        -- symbolicName contains "+" like "L2.exe+1000" which means it's in a module
        isInModule = true
    end
    
    -- Ensure symbolic_name has 0x prefix if it's just a hex address
    if symbolicName and symbolicName:match("^%x+$") then
        symbolicName = "0x" .. symbolicName
    end
    
    return {
        success = true,
        address = toHex(address),
        symbolic_name = symbolicName or toHex(address),
        is_in_module = isInModule,
        options_used = {
            include_modules = includeModules,
            include_symbols = includeSymbols,
            include_sections = includeSections
        }
    }
end

-- Checksum Memory: Calculate MD5 hash of a memory region
function cmd_checksum_memory(params)
    local address = params.address
    local size = math.max(1, math.min(params.size or 256, 16777216))
    
    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address" } end
    
    local ok, hash = pcall(md5memory, address, size)
    
    if ok and hash then
        return {
            success = true,
            address = toHex(address),
            size = size,
            md5_hash = hash
        }
    else
        return {
            success = false,
            address = toHex(address),
            size = size,
            error = "Failed to calculate MD5: " .. tostring(hash)
        }
    end
end

-- Generate Signature: Creates a unique AOB pattern for an address (for re-acquisition)
function cmd_generate_signature(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- getUniqueAOB(address) returns: AOBString, Offset
    -- It scans for a unique byte pattern that identifies this location
    local ok, signature, offset = pcall(getUniqueAOB, addr)
    
    if not ok then
        return {
            success = false,
            address = toHex(addr),
            error = "getUniqueAOB failed: " .. tostring(signature)
        }
    end
    
    if not signature or signature == ""
       or signature:find("错误") or signature:find("Error")
       or signature:find("error") or signature:find("unable")
       or signature:find("无法") then
        return {
            success = false,
            address = toHex(addr),
            error = "Could not generate unique signature: " .. tostring(signature or "pattern not unique enough")
        }
    end
    
    -- Calculate signature length (count bytes, wildcards count as 1)
    local byteCount = 0
    for _ in signature:gmatch("%S+") do
        byteCount = byteCount + 1
    end
    
    return {
        success = true,
        address = toHex(addr),
        signature = signature,
        offset_from_start = offset or 0,
        byte_count = byteCount,
        usage_hint = string.format("aob_scan('%s') then add offset %d to reach target", signature, offset or 0)
    }
end

-- ============================================================================
-- DBVM HYPERVISOR TOOLS (Safe Dynamic Tracing - Ring -1)
-- ============================================================================
-- These tools use DBVM (Debuggable Virtual Machine) for hypervisor-level tracing.
-- They are 100% invisible to anti-cheat: no game memory modification, no debug registers.
-- DBVM works at the hypervisor level, beneath the OS, making it undetectable.
-- ============================================================================

-- Get Physical Address: Converts virtual address to physical RAM address
-- Required for DBVM operations which work on physical memory
function cmd_get_physical_address(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- Check if DBK (kernel driver) is available
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    
    if not ok then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "DBK driver not loaded. Run dbk_initialize() first or load it via CE settings."
        }
    end
    
    if not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page may not be present in RAM."
        }
    end
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        physical_int = phys
    }
end

-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
-- Start DBVM Watch: Hypervisor-level memory access monitoring
-- This is the "Find what writes/reads" equivalent but at Ring -1 (invisible to games)
function cmd_start_dbvm_watch(params)
    local addr = params.address
    local mode = params.mode or "w"  -- "w" = write, "r" = read, "rw" = both, "x" = execute
    local maxEntries = params.max_entries or 1000  -- Internal buffer size
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    -- 0. Safety Checks
    if not dbk_initialized() then
        return { success = false, error = "DBK driver not loaded. Go to Settings -> Debugger -> Kernelmode" }
    end
    
    if not dbvm_initialized() then
        -- Try to initialize if possible
        pcall(dbvm_initialize)
        if not dbvm_initialized() then
            return { success = false, error = "DBVM not running. Go to Settings -> Debugger -> Use DBVM" }
        end
    end

    -- 1. Get Physical Address (DBVM works on physical RAM)
    local ok, phys = pcall(dbk_getPhysicalAddress, addr)
    if not ok or not phys or phys == 0 then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Could not resolve physical address. Page might be paged out or invalid."
        }
    end
    
    -- 2. Check if already watching this address
    local watchKey = toHex(addr)
    if serverState.active_watches[watchKey] then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "Already watching this address. Call stop_dbvm_watch first."
        }
    end
    
    -- 3. Configure watch options
    -- Bit 0: Log multiple times (1 = yes)
    -- Bit 1: Ignore size / log whole page (2)
    -- Bit 2: Log FPU registers (4)
    -- Bit 3: Log Stack (8)
    local options = 1 + 2 + 8  -- Multiple logging + whole page + stack context
    
    -- 4. Start the appropriate watch based on mode
    local watch_id
    local okWatch, result

    if mode == "x" then
        if not dbvm_watch_executes then
            return { success = false, error = "dbvm_watch_executes function missing from CE Lua engine" }
        end
        okWatch, result = pcall(dbvm_watch_executes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    elseif mode == "r" or mode == "rw" then
        okWatch, result = pcall(dbvm_watch_reads, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    else  -- default: write
        okWatch, result = pcall(dbvm_watch_writes, phys, 1, options, maxEntries)
        watch_id = okWatch and result or nil
    end
    
    if not okWatch then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch CRASHED/FAILED: " .. tostring(result)
        }
    end
    
    if not watch_id then
        return {
            success = false,
            virtual_address = toHex(addr),
            physical_address = toHex(phys),
            error = "DBVM watch returned nil (check CE console for details)"
        }
    end
    
    -- 5. Store watch for later retrieval
    serverState.active_watches[watchKey] = {
        id = watch_id,
        physical = phys,
        mode = mode,
        start_time = os.time()
    }
    
    return {
        success = true,
        status = "monitoring",
        virtual_address = toHex(addr),
        physical_address = toHex(phys),
        watch_id = watch_id,
        mode = mode,
        note = "Call poll_dbvm_watch to get logs without stopping, or stop_dbvm_watch to end"
    }
end

-- Poll DBVM Watch: Retrieve logged accesses WITHOUT stopping the watch
-- This is CRITICAL for continuous packet monitoring - logs can be polled repeatedly
function cmd_poll_dbvm_watch(params)
    local addr = params.address
    local clear = (params.clear ~= false)  -- nil→true, false→false, true→true
    local max_results = math.min(params.max_results or 1000, 100000)
    
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address. Call start_dbvm_watch first."
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}
    
    -- Retrieve log entries (DBVM accumulates these automatically)
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)
    
    if okLog and log then
        local count = math.min(#log, max_results)
        for i = 1, count do
            local entry = log[i]
            -- For packet capture, we need the stack pointer to read [ESP+4]
            -- ESP/RSP contains the stack pointer at time of execution
            local hitData = {
                hit_number = i,
                -- 32-bit game uses ESP, 64-bit uses RSP
                ESP = entry.RSP and toHexLow32(entry.RSP) or nil,
                RSP = entry.RSP and toHex(entry.RSP) or nil,
                EIP = entry.RIP and toHexLow32(entry.RIP) or nil,
                RIP = entry.RIP and toHex(entry.RIP) or nil,
                -- Include key registers that might hold packet buffer
                EAX = entry.RAX and toHexLow32(entry.RAX) or nil,
                ECX = entry.RCX and toHexLow32(entry.RCX) or nil,
                EDX = entry.RDX and toHexLow32(entry.RDX) or nil,
                EBX = entry.RBX and toHexLow32(entry.RBX) or nil,
                ESI = entry.RSI and toHexLow32(entry.RSI) or nil,
                EDI = entry.RDI and toHexLow32(entry.RDI) or nil,
            }
            table.insert(results, hitData)
        end
    end

    if clear then
        pcall(dbvm_watch_clearlog, watch_id)
    end

    local uptime = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        status = "active",
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        uptime_seconds = uptime,
        hit_count = #results,
        hits = results,
        note = "Watch still active. Call again to get more logs, or stop_dbvm_watch to end."
    }
end

-- Stop DBVM Watch: Retrieve logged accesses and disable monitoring
-- Returns all instructions that touched the monitored memory
function cmd_stop_dbvm_watch(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end
    
    local watchKey = toHex(addr)
    local watchInfo = serverState.active_watches[watchKey]
    
    if not watchInfo then
        return {
            success = false,
            virtual_address = toHex(addr),
            error = "No active watch found for this address"
        }
    end
    
    local watch_id = watchInfo.id
    local results = {}

    -- 1. Retrieve the log of all memory accesses
    local okLog, log = pcall(dbvm_watch_retrievelog, watch_id)

    if okLog and log then
        -- Each entry costs a disassemble() on the CE main thread; cap like the
        -- other DBVM log paths and report truncation.
        local MAX_STOP_HITS = 10000
        for i, entry in ipairs(log) do
            if i > MAX_STOP_HITS then break end
            local instruction = "???"
            if entry.RIP then
                local okDis, dis = pcall(disassemble, entry.RIP)
                if okDis and dis then instruction = dis end
            end
            local hitData = {
                hit_number = i,
                instruction_address = entry.RIP and toHex(entry.RIP) or nil,
                instruction = instruction,
                -- CPU registers at time of access
                registers = {
                    RAX = entry.RAX and toHex(entry.RAX) or nil,
                    RBX = entry.RBX and toHex(entry.RBX) or nil,
                    RCX = entry.RCX and toHex(entry.RCX) or nil,
                    RDX = entry.RDX and toHex(entry.RDX) or nil,
                    RSI = entry.RSI and toHex(entry.RSI) or nil,
                    RDI = entry.RDI and toHex(entry.RDI) or nil,
                    RBP = entry.RBP and toHex(entry.RBP) or nil,
                    RSP = entry.RSP and toHex(entry.RSP) or nil,
                    RIP = entry.RIP and toHex(entry.RIP) or nil
                }
            }
            table.insert(results, hitData)
        end
    end
    
    -- 2. Disable the watch
    pcall(dbvm_watch_disable, watch_id)
    
    -- 3. Clean up
    serverState.active_watches[watchKey] = nil
    
    local duration = os.time() - (watchInfo.start_time or os.time())
    
    return {
        success = true,
        virtual_address = toHex(addr),
        physical_address = toHex(watchInfo.physical),
        mode = watchInfo.mode,
        hit_count = #results,
        duration_seconds = duration,
        hits = results,
        truncated = okLog and log ~= nil and #log > #results or false,
        note = #results > 0 and "Found instructions that accessed the memory" or "No accesses detected during monitoring"
    }
end

-- >>> BEGIN UNIT-23 Debug Multimedia <<<

local progressStateMap = {
    none          = tbpsNone,
    normal        = tbpsNormal,
    paused        = tbpsPaused,
    error         = tbpsError,
    indeterminate = tbpsIndeterminate,
}

function cmd_output_debug_string(params)
    local message = params.message
    if type(message) ~= "string" then
        return { success = false, error = "message must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(outputDebugString, message)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_speak_text(params)
    local text = params.text
    if type(text) ~= "string" then
        return { success = false, error = "text must be a string", error_code = "INVALID_PARAMS" }
    end
    local ok, err
    if params.english_only then
        ok, err = pcall(speakEnglish, text)
    else
        ok, err = pcall(speak, text)
    end
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_play_sound(params)
    if type(params.filename) ~= "string" or params.filename:find("%.%.") then
        return { success = false, error = "Invalid filename", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(playSound, params.filename)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_beep(params)
    local ok, err = pcall(beep)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_set_progress_state(params)
    local tbState = progressStateMap[params.state]
    if not tbState then
        return { success = false, error = "state must be one of: none, normal, paused, error, indeterminate", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressState, tbState)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_set_progress_value(params)
    local current = params.current
    local max = params.max
    if type(current) ~= "number" or type(max) ~= "number" then
        return { success = false, error = "current and max must be numbers", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(setProgressValue, current, max)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

-- >>> END UNIT-23 <<<

-- >>> BEGIN UNIT-21 Kernel DBVM <<<
-- ============================================================================
-- COMMAND HANDLERS - KERNEL MODE / DBVM EXTENSIONS (Unit 21)
-- Requires DBK kernel driver and/or DBVM hypervisor to be loaded.
-- ============================================================================

-- MDL bookkeeping table (mappedMemoryMDL) is declared near the top of the file
-- so that cleanupZombieState() can see the same local. Do NOT re-declare it here.

local function dbkNotLoadedError()
    return {
        success = false,
        error = "Kernel driver (DBK) or hypervisor (DBVM) not loaded",
        error_code = "DBK_NOT_LOADED"
    }
end

function cmd_dbk_get_cr0(params)
    local ok, result = pcall(dbk_getCR0)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr0 = toHex(result) }
end

function cmd_dbk_get_cr3(params)
    local ok, result = pcall(dbk_getCR3)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr3 = toHex(result) }
end

function cmd_dbk_get_cr4(params)
    local ok, result = pcall(dbk_getCR4)
    if not ok then return dbkNotLoadedError() end
    return { success = true, cr4 = toHex(result) }
end

function cmd_read_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local size     = tonumber(params.size)

    if not cr3_str or not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters cr3, address and size are required" }
    end
    -- Kernel-path reads are capped: response is a full byte array (≈5x JSON
    -- inflation), so anything past 4 MiB would blow the 32 MiB response guard.
    if size > 4194304 then
        return { success = false, error = "size too large (max 4 MiB per call)", error_code = "INVALID_PARAMS" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value" }
    end

    local ok, byteTable = pcall(readProcessMemoryCR3, cr3, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not byteTable then
        return { success = false, error = "Read failed — page may be paged out or invalid" }
    end

    return { success = true, bytes = byteTable, size = #byteTable }
end

function cmd_write_process_memory_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str  = params.cr3
    local addr_str = params.address
    local bytes    = params.bytes

    if not cr3_str or not addr_str or not bytes or type(bytes) ~= "table" then
        return { success = false, error = "Parameters cr3, address and bytes (list) are required" }
    end

    local cr3  = type(cr3_str)  == "string" and getAddressSafe(cr3_str)  or cr3_str
    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not cr3 or not addr then
        return { success = false, error = "Invalid cr3 or address value" }
    end

    local ok = pcall(writeProcessMemoryCR3, cr3, addr, bytes)
    if not ok then return dbkNotLoadedError() end

    return { success = true, bytes_written = #bytes }
end

function cmd_map_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local addr_str = params.address
    local size     = tonumber(params.size)

    if not addr_str or not size or size <= 0 then
        return { success = false, error = "Parameters address and size are required" }
    end
    -- Each mapping is retained until unmap_memory; an unbounded size would let
    -- one call pin unbounded kernel memory. 16 MiB is ample for code pages.
    if size > 16777216 then
        return { success = false, error = "size too large (max 16 MiB per mapping)", error_code = "INVALID_PARAMS" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid address value" }
    end

    local ok, mappedAddr, mdl = pcall(mapMemory, addr, size)
    if not ok then return dbkNotLoadedError() end
    if not mappedAddr then
        return { success = false, error = "mapMemory failed — address may be invalid or DBK not loaded" }
    end

    local key = toHex(mappedAddr)
    mappedMemoryMDL[key] = mdl  -- retain MDL so unmap_memory can release it

    return { success = true, mapped_address = key }
end

function cmd_unmap_memory(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local addr_str = params.mapped_address
    if not addr_str then
        return { success = false, error = "Parameter mapped_address is required" }
    end

    local addr = type(addr_str) == "string" and getAddressSafe(addr_str) or addr_str
    if not addr then
        return { success = false, error = "Invalid mapped_address value" }
    end

    local key = toHex(addr)
    local mdl = mappedMemoryMDL[key]
    if mdl == nil then
        return { success = false, error_code = "NOT_FOUND",
                 error = "No tracked mapping for " .. key .. " (already unmapped, or created outside this bridge session)" }
    end

    local ok = pcall(unmapMemory, addr, mdl)
    if not ok then return dbkNotLoadedError() end

    mappedMemoryMDL[key] = nil

    return { success = true, mapped_address = key }
end

function cmd_dbk_writes_ignore_write_protection(params)
    local enable = params.enable
    if type(enable) ~= "boolean" then
        return { success = false, error = "Parameter enable (boolean) is required" }
    end

    local ok = pcall(dbk_writesIgnoreWriteProtection, enable)
    if not ok then return dbkNotLoadedError() end

    return { success = true }
end

function cmd_get_physical_address_cr3(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end

    local cr3_str = params.cr3
    local va_str  = params.virtual_address

    if not cr3_str or not va_str then
        return { success = false, error = "Parameters cr3 and virtual_address are required" }
    end

    local cr3 = type(cr3_str) == "string" and getAddressSafe(cr3_str) or cr3_str
    local va  = type(va_str)  == "string" and getAddressSafe(va_str)  or va_str
    if not cr3 or not va then
        return { success = false, error = "Invalid cr3 or virtual_address value" }
    end

    local ok, phys = pcall(getPhysicalAddressCR3, cr3, va)
    if not ok then return dbkNotLoadedError() end
    if not phys then
        return { success = false, error = "Address not paged — virtual address may not be mapped in this CR3" }
    end

    return { success = true, physical_address = toHex(phys) }
end

-- >>> END UNIT-21 <<<
-- >>> BEGIN UNIT-20a File IO Clipboard <<<
-- ============================================================================
-- UNIT-20a: Safe File I/O and Clipboard Tools
-- ============================================================================

local function sanitizeFilename(f)
    if type(f) ~= "string" or f == "" then return nil, "Invalid filename" end
    if f:find("%.%.") then return nil, "Path traversal not allowed" end
    return f, nil
end

function cmd_file_exists(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(fileExists, f)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, exists = result == true }
end

function cmd_delete_file(params)
    local filename = params.filename
    local f, err = sanitizeFilename(filename)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(deleteFile, f)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true }
end

local function listPathEntries(path, ceFn, resultKey)
    local f, err = sanitizeFilename(path)
    if not f then return { success = false, error = err } end
    local ok, result = pcall(ceFn, f)
    if not ok then return { success = false, error = tostring(result) } end
    local entries = {}
    if type(result) == "table" then
        for _, v in ipairs(result) do table.insert(entries, v) end
    end
    return { success = true, count = #entries, [resultKey] = entries }
end

function cmd_get_file_list(params)
    return listPathEntries(params.path, getFileList, "files")
end

function cmd_get_directory_list(params)
    return listPathEntries(params.path, getDirectoryList, "directories")
end

function cmd_get_temp_folder(params)
    local ok, result = pcall(getTempFolder)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, path = tostring(result) }
end

function cmd_get_file_version(params)
    local f, err = sanitizeFilename(params.filename)
    if not f then return { success = false, error = err } end
    -- getFileVersion returns two values; wrap in a closure so pcall captures both
    local ok, errOrRaw, verTable = pcall(function() return getFileVersion(f) end)
    if not ok then return { success = false, error = tostring(errOrRaw) } end
    if type(verTable) ~= "table" then
        return { success = false, error = "getFileVersion did not return a version table" }
    end
    local major   = verTable.major   or 0
    local minor   = verTable.minor   or 0
    local release = verTable.release or 0
    local build   = verTable.build   or 0
    return {
        success = true,
        major = major,
        minor = minor,
        release = release,
        build = build,
        version_string = string.format("%d.%d.%d.%d", major, minor, release, build)
    }
end

function cmd_read_clipboard(params)
    local ok, result = pcall(readFromClipboard)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, text = tostring(result or "") }
end

function cmd_write_clipboard(params)
    local text = params.text
    if type(text) ~= "string" then return { success = false, error = "text must be a string" } end
    local ok, err = pcall(writeToClipboard, text)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

-- >>> END UNIT-20a <<<

-- ============================================================================
-- UNIT-20b: Shell Execution Handlers
-- NOTE: Security gate (CE_MCP_ALLOW_SHELL env var check) is enforced on the
--       Python side, before this Lua code is ever reached.
-- ============================================================================

-- run_command: Wraps CE's runCommand(exepath, parameters, pathtoexecutein)
-- Returns output string and exit code. SECURITY: arbitrary code execution.
function cmd_run_command(params)
    local command = params.command
    local args = params.args or ""

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    local ok, output, exitCode = pcall(runCommand, command, args)

    if not ok then
        return { success = false, error = "runCommand failed: " .. tostring(output) }
    end

    return {
        success = true,
        output = tostring(output or ""),
        exit_code = tonumber(exitCode) or 0
    }
end

-- shell_execute: Wraps CE's shellExecute(command, parameters, folder, showcommand)
-- SECURITY: arbitrary code execution via Windows ShellExecute.
function cmd_shell_execute(params)
    local command = params.command
    local args = params.args or ""
    local verb = string.lower(params.verb or "open")
    local workingDir = params.working_dir or ""
    local showCommand = params.showcommand

    if not command or command == "" then
        return { success = false, error = "No command provided" }
    end

    -- CE's shellExecute wrapper does not expose an explicit "verb" argument.
    -- Keep compatibility explicit to avoid silent behavior differences.
    if verb ~= "open" then
        return { success = false, error = "Unsupported verb for shell_execute: " .. tostring(verb), error_code = "INVALID_PARAMS" }
    end

    if showCommand ~= nil and type(showCommand) ~= "number" then
        return { success = false, error = "showcommand must be a number when provided", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(shellExecute, command, args, workingDir ~= "" and workingDir or nil, showCommand)

    if not ok then
        return { success = false, error = "shellExecute failed: " .. tostring(err) }
    end

    return { success = true }
end

-- >>> END UNIT-20b <<<

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

-- >>> BEGIN UNIT-19 Structure Management <<<

serverState.structures = serverState.structures or {}
serverState.structure_next_id = serverState.structure_next_id or 1

local vartypeMap = {
    byte      = vtByte,
    word      = vtWord,
    dword     = vtDword,
    qword     = vtQword,
    float     = vtSingle,
    single    = vtSingle,
    double    = vtDouble,
    string    = vtString,
    aob       = vtByteArray,
    bytearray = vtByteArray,
    pointer   = vtPointer,
}

local vtypeNames = {
    [vtByte]      = "byte",
    [vtWord]      = "word",
    [vtDword]     = "dword",
    [vtQword]     = "qword",
    [vtSingle]    = "float",
    [vtDouble]    = "double",
    [vtString]    = "string",
    [vtByteArray] = "aob",
    [vtPointer]   = "pointer",
}

local function vtypeToString(vt)
    return vtypeNames[vt] or tostring(vt)
end

-- Hoisted so it is not re-created on every export call.
local function xmlEscape(s)
    s = tostring(s)
    s = s:gsub("&", "&amp;")
    s = s:gsub("<", "&lt;")
    s = s:gsub(">", "&gt;")
    s = s:gsub('"', "&quot;")
    s = s:gsub("'", "&apos;")
    return s
end

-- Returns structure object on success, or nil + error-result table on failure.
local function resolveStructure(params)
    local sid = params.structure_id
    if not sid then
        return nil, { success = false, error = "structure_id is required", error_code = "INVALID_PARAMS" }
    end
    local structure = serverState.structures[sid]
    if not structure then
        return nil, { success = false, error = "Unknown structure_id: " .. tostring(sid), error_code = "NOT_FOUND" }
    end
    return structure, nil
end

-- Reads element properties via pcall-guarded property access.
local function readElementProps(el)
    local name, offset, vt, size
    pcall(function() name   = el.Name    end)
    pcall(function() offset = el.Offset  end)
    pcall(function() vt     = el.Vartype end)
    pcall(function() size   = el.Bytesize end)
    return name or "", offset or 0, vt, size or 0
end

function cmd_create_structure(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, structure = pcall(createStructure, name)
    if not ok or not structure then
        return { success = false, error = "createStructure failed: " .. tostring(structure), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function() structure.addToGlobalStructureList() end)
    if not ok2 then
        return { success = false, error = "addToGlobalStructureList failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local id = serverState.structure_next_id
    serverState.structure_next_id = serverState.structure_next_id + 1
    serverState.structures[id] = structure

    return { success = true, structure_id = id }
end

function cmd_get_structure_by_name(params)
    local name = params.name
    if not name or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end

    local ok, count = pcall(getStructureCount)
    if not ok then
        return { success = false, error = "getStructureCount failed: " .. tostring(count), error_code = "CE_API_UNAVAILABLE" }
    end

    for i = 0, count - 1 do
        local ok2, s = pcall(getStructure, i)
        if ok2 and s then
            local ok3, sname = pcall(function() return s.Name end)
            if ok3 and sname == name then
                local sid = nil
                for id, stored in pairs(serverState.structures) do
                    local ok4, sn = pcall(function() return stored.Name end)
                    if ok4 and sn == name then sid = id; break end
                end
                if not sid then
                    sid = serverState.structure_next_id
                    serverState.structure_next_id = serverState.structure_next_id + 1
                    serverState.structures[sid] = s
                end
                local ok5, sz  = pcall(function() return s.Size end)
                local ok6, cnt = pcall(function() return s.Count end)
                return {
                    success       = true,
                    structure_id  = sid,
                    name          = name,
                    element_count = ok6 and cnt or 0,
                    size          = ok5 and sz  or 0,
                }
            end
        end
    end

    return { success = false, error = "Structure not found: " .. name, error_code = "NOT_FOUND" }
end

function cmd_add_element_to_structure(params)
    local ename  = params.name
    local offset = params.offset
    local etype  = params.type

    local structure, err = resolveStructure(params)
    if not structure then return err end

    if not ename or offset == nil or not etype then
        return { success = false, error = "name, offset, type are required", error_code = "INVALID_PARAMS" }
    end

    local vt = vartypeMap[string.lower(tostring(etype))]
    if not vt then
        return { success = false, error = "Unknown type: " .. tostring(etype), error_code = "INVALID_PARAMS" }
    end

    local ok, element = pcall(function() return structure.addElement() end)
    if not ok or not element then
        return { success = false, error = "addElement failed: " .. tostring(element), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok2, err2 = pcall(function()
        element.Name    = ename
        element.Offset  = offset
        element.Vartype = vt
    end)
    if not ok2 then
        return { success = false, error = "Setting element properties failed: " .. tostring(err2), error_code = "CE_API_UNAVAILABLE" }
    end

    local ok3, cnt = pcall(function() return structure.Count end)
    local idx = (ok3 and cnt) and (cnt - 1) or nil

    return { success = true, element_index = idx }
end

function cmd_get_structure_elements(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, cnt = pcall(function() return structure.Count end)
    if not ok then
        return { success = false, error = "Failed to read structure count: " .. tostring(cnt), error_code = "CE_API_UNAVAILABLE" }
    end

    local elements = {}
    for i = 0, cnt - 1 do
        local ok2, el = pcall(function() return structure.getElement(i) end)
        if ok2 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            elements[#elements + 1] = {
                name   = elName,
                offset = elOffset,
                type   = vtypeToString(elVt),
                size   = elSize,
            }
        end
    end

    return { success = true, structure_id = params.structure_id, elements = elements }
end

function cmd_export_structure_to_xml(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    local ok, sname = pcall(function() return structure.Name end)
    if not ok then sname = "Unknown" end
    local ok2, sz  = pcall(function() return structure.Size end)
    if not ok2 then sz = 0 end
    local ok3, cnt = pcall(function() return structure.Count end)
    if not ok3 then cnt = 0 end

    local lines = {}
    lines[#lines + 1] = '<?xml version="1.0" encoding="utf-8"?>'
    lines[#lines + 1] = string.format('<Structure Name="%s" Size="%d">', xmlEscape(sname), sz)

    for i = 0, cnt - 1 do
        local ok4, el = pcall(function() return structure.getElement(i) end)
        if ok4 and el then
            local elName, elOffset, elVt, elSize = readElementProps(el)
            lines[#lines + 1] = string.format(
                '  <Element Name="%s" Offset="%d" Type="%s" Size="%d"/>',
                xmlEscape(elName), elOffset, xmlEscape(vtypeToString(elVt)), elSize
            )
        end
    end

    lines[#lines + 1] = '</Structure>'

    return { success = true, xml = table.concat(lines, "\n") }
end

function cmd_delete_structure(params)
    local structure, err = resolveStructure(params)
    if not structure then return err end

    pcall(function() structure.removeFromGlobalStructureList() end)
    pcall(function() structure.destroy() end)

    serverState.structures[params.structure_id] = nil
    return { success = true }
end
-- >>> BEGIN UNIT-18 Cheat Table Records <<<

local UNIT18_TYPE_MAP = {
    byte          = "vtByte",
    word          = "vtWord",
    dword         = "vtDword",
    qword         = "vtQword",
    float         = "vtSingle",
    single        = "vtSingle",
    double        = "vtDouble",
    string        = "vtString",
    bytearray     = "vtByteArray",
    aob           = "vtByteArray",
    binary        = "vtBinary",
    bits          = "vtBinary",
    autoassembler = "vtAutoAssembler",
    auto_assemble = "vtAutoAssembler",
    aa            = "vtAutoAssembler",
    script        = "vtAutoAssembler",
}

-- Returns (al, nil) on success or (nil, error-response-table) on failure.
local function unit18_get_al()
    local ok, al = pcall(getAddressList)
    if not ok or not al then
        return nil, { success = false, error = "Cannot get AddressList", error_code = "CE_API_UNAVAILABLE" }
    end
    return al, nil
end

-- Returns (rec, nil) on success or (nil, error-response-table) when not found.
local function unit18_get_rec_by_id(al, id)
    local ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
    if not ok or not rec then
        return nil, { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end
    return rec, nil
end

-- Validates a table-file path: non-empty string, no directory traversal.
local function unit18_check_filename(filename)
    if type(filename) ~= "string" or filename == "" then
        return { success = false, error = "filename required", error_code = "INVALID_PARAMS" }
    end
    if filename:find("%.%.") then
        return { success = false, error = "Path traversal not allowed", error_code = "INVALID_PARAMS" }
    end
end

local function unit18_rec_to_table(rec)
    if not rec then return nil end

    local function prop(name)
        local ok, v = pcall(function() return rec[name] end)
        return ok and v or nil
    end

    local offsetCount = prop("OffsetCount") or 0
    local offsets = {}
    for i = 0, offsetCount - 1 do
        local ok, off = pcall(function() return rec.Offset[i] end)
        table.insert(offsets, ok and off or nil)
    end

    -- Resolved final address (symbol/pointer expression applied). Useful for
    -- follow-up read/write calls; nil when the address cannot be evaluated.
    local currentAddress, currentAddressHex = prop("CurrentAddress"), nil
    if type(currentAddress) == "number" then
        currentAddressHex = toHex(currentAddress)
    end

    return {
        id              = prop("ID"),
        description     = prop("Description") or "",
        address         = prop("Address")     or "",
        current_address = currentAddressHex,
        type            = prop("VarType")     or "",
        value           = prop("Value")       or "",
        offsets         = offsets,
        enabled         = prop("Active")      or false,
        child_count     = prop("Count")       or 0,
        is_group_header = prop("IsGroupHeader") or false,
    }
end

function cmd_load_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(loadTable, filename, params.merge or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_save_table(params)
    local filename = params.filename
    local err = unit18_check_filename(filename)
    if err then return err end

    local ok, cerr = pcall(saveTable, filename, params.protect or false)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

-- ----------------------------------------------------------------------------
-- API introspection / table state / script hot-patching (v15.4.0)
-- ----------------------------------------------------------------------------

function cmd_list_apis(params)
    local limit, offset = clampPaging(params, 200, 2000)
    local filter = type(params.filter) == "string" and params.filter:lower() or nil

    local names = {}
    for k, v in pairs(_G) do
        if type(v) == "function" then
            local name = tostring(k)
            if not filter or name:lower():find(filter, 1, true) then
                names[#names + 1] = name
            end
        end
    end
    table.sort(names)

    local total = #names
    local page = {}
    for i = offset + 1, math.min(offset + limit, total) do
        page[#page + 1] = names[i]
    end
    return { success = true, total = total, offset = offset, limit = limit,
             returned = #page, apis = page }
end

-- FNV-1a 32-bit over file contents: drift detector for "is the on-disk table
-- the one CE has loaded". Pure Lua, no crypto dependency.
-- Runs on CE's main thread, so the byte-wise loop is capped: hashing a
-- pathologically large file would freeze the whole UI (same rationale as
-- AA_MAX_SCRIPT_SIZE).
local FNV_MAX_HASH_BYTES = 32 * 1024 * 1024
local function fnv1a_file(path, maxBytes)
    local fh = io.open(path, "rb")
    if not fh then return nil, "cannot open" end
    local hash = 2166136261
    local budget = math.max(1, tonumber(maxBytes) or FNV_MAX_HASH_BYTES)
    local consumed = 0
    while consumed < budget do
        local chunk = fh:read(math.min(65536, budget - consumed))
        if not chunk or chunk == "" then break end
        consumed = consumed + #chunk
        -- one chunk:byte(1,-1) call is several times faster than a per-byte
        -- method call in this tight loop
        local bytes = { chunk:byte(1, -1) }
        for i = 1, #bytes do
            hash = (hash ~ bytes[i]) * 16777619
            hash = hash % 4294967296
        end
    end
    local truncated = false
    if consumed >= budget and fh:read(1) ~= nil then truncated = true end
    fh:close()
    return string.format("%08x", hash), truncated
end

function cmd_table_state(params)
    local state = { success = true }

    -- getTableFile() exists on CE 7.4+; degrade gracefully when absent
    local okP, path = pcall(getTableFile)
    if okP and type(path) == "string" and path ~= "" then
        state.table_path = path
        local okF, size = pcall(function()
            local fh = io.open(path, "rb")
            if not fh then return nil end
            local sz = fh:seek("end")
            fh:close()
            return sz
        end)
        if okF and size then
            state.disk_size = size
            local okH, h, hcap = pcall(fnv1a_file, path)
            if okH and h then
                state.disk_fnv1a = h
                if hcap then state.hash_truncated = true end
            end
        else
            state.disk_exists = false
        end
    else
        state.note = "getTableFile unavailable or no table loaded"
    end

    local al = unit18_get_al()
    local okC, count = false, 0
    if al then okC, count = pcall(function() return al.Count end) end
    state.memory_records = okC and count or 0
    return state
end

-- Script hot-patch: uniqueness-guarded find/replace with a bounded undo ring,
-- so repeated hot fixes stop relying on external backup chains.
local MAX_UNDO_PER_RECORD = 5
local scriptUndoRing = {}  -- id -> array of { script = previousText }

local function occurrenceCount(hay, needle)
    local n, pos = 0, 1
    while true do
        local s, e = hay:find(needle, pos, true)
        if not s then return n end
        n = n + 1
        pos = e + 1
    end
end

function cmd_patch_memory_record_script(params)
    if params.id == nil or type(params.find) ~= "string" or params.find == "" then
        return { success = false, error = "id and find (non-empty string) required",
                 error_code = "INVALID_PARAMS" }
    end
    local replace = params.replace
    if type(replace) ~= "string" then replace = "" end  -- deletion is a valid patch
    local all = params.all == true

    local al, aerr = unit18_get_al()
    if not al then return aerr end
    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return rerr end

    local okS, script = pcall(function() return rec.Script end)
    if not okS or type(script) ~= "string" then
        return { success = false, error = "Record has no readable Script",
                 error_code = "NO_SCRIPT" }
    end

    local occurrences = occurrenceCount(script, params.find)
    if occurrences == 0 then
        return { success = false, error = "find text not present in Script",
                 error_code = "NO_MATCH" }
    end
    if occurrences > 1 and not all then
        return { success = false,
                 error = "find matches " .. occurrences .. " times; pass all=true or widen the anchor",
                 error_code = "AMBIGUOUS_MATCH" }
    end

    local ring = scriptUndoRing[params.id] or {}
    ring[#ring + 1] = { script = script }
    if #ring > MAX_UNDO_PER_RECORD then table.remove(ring, 1) end
    scriptUndoRing[params.id] = ring

    local replaced, pos = 0, 1
    local newScript = script
    while true do
        local s, e = newScript:find(params.find, pos, true)
        if not s then break end
        newScript = newScript:sub(1, s - 1) .. replace .. newScript:sub(e + 1)
        replaced = replaced + 1
        pos = s + #replace
        if not all or replaced > 10000 then break end
    end

    local okW, werr = pcall(function() rec.Script = newScript end)
    if not okW then
        table.remove(scriptUndoRing[params.id])  -- roll back the undo push
        return { success = false, error = "Script write failed: " .. tostring(werr),
                 error_code = "INTERNAL_ERROR" }
    end

    return { success = true, replaced = replaced, old_length = #script,
             new_length = #newScript,
             note = "undo via undo_memory_record_script_patch" }
end

function cmd_undo_memory_record_script_patch(params)
    if params.id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    local ring = scriptUndoRing[params.id]
    if not ring or #ring == 0 then
        return { success = false, error = "no patch history for this record",
                 error_code = "NO_HISTORY" }
    end
    local al, aerr = unit18_get_al()
    if not al then return aerr end
    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return rerr end

    local prev = table.remove(ring)
    local okW, werr = pcall(function() rec.Script = prev.script end)
    if not okW then
        return { success = false, error = "Script restore failed: " .. tostring(werr),
                 error_code = "INTERNAL_ERROR" }
    end
    return { success = true, restored_length = #prev.script, remaining_history = #ring }
end


function cmd_get_address_list(params)
    local limit, offset = clampPaging(params, 100)

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, count = pcall(function() return al.Count end)
    if not okC then count = 0 end

    local records = {}
    local returned = 0
    for i = offset, math.min(offset + limit - 1, count - 1) do
        local okR, rec = pcall(function() return al[i] end)
        if okR and rec then
            table.insert(records, unit18_rec_to_table(rec))
            returned = returned + 1
        end
    end

    return {
        success  = true,
        total    = count,
        offset   = offset,
        limit    = limit,
        returned = returned,
        records  = records,
    }
end

function cmd_get_memory_record(params)
    local id   = params.id
    local desc = params.description

    if id == nil and desc == nil then
        return { success = false, error = "id or description required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec
    if id ~= nil then
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByID(id) end)
        if not ok then rec = nil end
    else
        local ok
        ok, rec = pcall(function() return al:getMemoryRecordByDescription(desc) end)
        if not ok then rec = nil end
    end

    if not rec then
        return { success = false, error = "Memory record not found", error_code = "NOT_FOUND" }
    end

    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_create_memory_record(params)
    local description = params.description
    local address     = params.address
    local typeStr     = string.lower(params.type or "dword")

    if type(description) ~= "string" or description == "" then
        return { success = false, error = "description required", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" or address == "" then
        return { success = false, error = "address required", error_code = "INVALID_PARAMS" }
    end

    local vtName = UNIT18_TYPE_MAP[typeStr]
    if not vtName then
        return { success = false, error = "Unknown type: " .. typeStr, error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, rec = pcall(function() return al:createMemoryRecord() end)
    if not okC or not rec then
        return { success = false, error = tostring(rec), error_code = "INTERNAL_ERROR" }
    end

    -- Helper: set a property, rolling back the record on failure.
    local function set_prop(name, val)
        local ok = pcall(function() rec[name] = val end)
        if not ok then
            pcall(function() rec:delete() end)
            return { success = false, error = "Failed to set " .. name, error_code = "INTERNAL_ERROR" }
        end
    end

    local perr = set_prop("Description", description)
    if perr then return perr end

    perr = set_prop("Address", address)
    if perr then return perr end

    -- VarType accepts the string constant name; fall back to the global numeric value.
    if not pcall(function() rec.VarType = vtName end) then
        pcall(function() rec.VarType = _G[vtName] end)
    end

    local okId, recId = pcall(function() return rec.ID end)
    if not okId then recId = nil end

    return { success = true, id = recId, record = unit18_rec_to_table(rec) }
end

function cmd_delete_memory_record(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec:delete() end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_get_memory_record_value(params)
    local id = params.id
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, value = pcall(function() return rec.Value end)
    if not ok then
        return { success = false, error = tostring(value), error_code = "INTERNAL_ERROR" }
    end

    return { success = true, value = tostring(value or "") }
end

function cmd_set_memory_record_value(params)
    local id    = params.id
    local value = params.value
    if id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    if value == nil then
        return { success = false, error = "value required", error_code = "INVALID_PARAMS" }
    end

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, id)
    if not rec then return rerr end

    local ok, cerr = pcall(function() rec.Value = tostring(value) end)
    if not ok then
        return { success = false, error = tostring(cerr), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

-- >>> END UNIT-19 <<<

-- >>> END UNIT-18 <<<

-- >>> BEGIN UNIT-17 Input Automation <<<
-- ============================================================================
-- COMMAND HANDLERS - INPUT AUTOMATION (mouse, keyboard, screen)
-- These APIs operate system-wide and require NO attached process.
-- ============================================================================

-- Shared helpers (local to this section)
local function parse_xy(params)
    if params.x == nil then return nil, nil, "Missing parameter: x" end
    if params.y == nil then return nil, nil, "Missing parameter: y" end
    local x, y = tonumber(params.x), tonumber(params.y)
    if x == nil or y == nil then return nil, nil, "Parameters x and y must be numbers" end
    return x, y, nil
end

local function parse_vk(params)
    if params.vk == nil then return nil, "Missing parameter: vk (Windows virtual-key code, e.g. 0x41 for 'A')" end
    local vk = tonumber(params.vk)
    if vk == nil then return nil, "Parameter vk must be a number" end
    return vk, nil
end

-- Execute a no-return CE key API (keyDown / keyUp / doKeyPress) and return {success}.
local function run_key_action(fn, vk, fn_name)
    local ok, err = pcall(fn, vk)
    if not ok then return { success = false, error = fn_name .. " failed: " .. tostring(err) } end
    return { success = true }
end

function cmd_get_pixel(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, rgb = pcall(getPixel, x, y)
    if not ok then return { success = false, error = "getPixel failed: " .. tostring(rgb) } end
    -- Windows COLORREF format: 0x00BBGGRR
    local r = rgb % 256
    local g = math.floor(rgb / 256) % 256
    local b = math.floor(rgb / 65536) % 256
    return { success = true, r = r, g = g, b = b, rgb = rgb }
end

function cmd_get_mouse_pos(params)
    local ok, x, y = pcall(getMousePos)
    if not ok then return { success = false, error = "getMousePos failed: " .. tostring(x) } end
    return { success = true, x = x, y = y }
end

function cmd_set_mouse_pos(params)
    local x, y, err = parse_xy(params)
    if err then return { success = false, error = err } end

    local ok, e = pcall(setMousePos, x, y)
    if not ok then return { success = false, error = "setMousePos failed: " .. tostring(e) } end
    return { success = true }
end

function cmd_is_key_pressed(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end

    local ok, pressed = pcall(isKeyPressed, vk)
    if not ok then return { success = false, error = "isKeyPressed failed: " .. tostring(pressed) } end
    return { success = true, pressed = pressed == true }
end

function cmd_key_down(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyDown, vk, "keyDown")
end

function cmd_key_up(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(keyUp, vk, "keyUp")
end

function cmd_do_key_press(params)
    local vk, err = parse_vk(params)
    if err then return { success = false, error = err } end
    return run_key_action(doKeyPress, vk, "doKeyPress")
end

function cmd_get_screen_info(params)
    local ok_w, width  = pcall(getScreenWidth)
    local ok_h, height = pcall(getScreenHeight)
    local ok_d, dpi    = pcall(getScreenDPI)

    if not ok_w then return { success = false, error = "getScreenWidth failed: " .. tostring(width) } end
    if not ok_h then return { success = false, error = "getScreenHeight failed: " .. tostring(height) } end
    if not ok_d then return { success = false, error = "getScreenDPI failed: " .. tostring(dpi) } end

    return { success = true, width = width, height = height, dpi = dpi }
end

-- >>> END UNIT-17 <<<

-- >>> BEGIN UNIT-16 Window GUI <<<
-- ============================================================================
-- WINDOW / GUI COMMAND HANDLERS
-- No process guard required: these APIs are system-wide window operations.
-- ============================================================================

-- Shared helper: parse a hex window-handle string into a number.
-- Returns the number, or nil if the string is missing/invalid.
local function parseHandle(hexStr)
    return tonumber(hexStr, 16)
end

function cmd_find_window(params)
    local title      = params.title
    local class_name = params.class_name

    if not title and not class_name then
        return { success = false, error = "At least one of title or class_name must be provided" }
    end

    local ok, handle = pcall(function()
        return findWindow(class_name, title)
    end)

    if not ok then
        return { success = false, error = tostring(handle) }
    end

    if not handle or handle == 0 then
        return { success = false, error_code = "NOT_FOUND" }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_get_window_caption(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, caption = pcall(function()
        return getWindowCaption(handle)
    end)

    if not ok then
        return { success = false, error = tostring(caption) }
    end

    return { success = true, caption = caption or "" }
end

function cmd_get_window_class_name(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, cls = pcall(function()
        return getWindowClassName(handle)
    end)

    if not ok then
        return { success = false, error = tostring(cls) }
    end

    return { success = true, class_name = cls or "" }
end

function cmd_get_window_process_id(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local ok, pid = pcall(function()
        return getWindowProcessID(handle)
    end)

    if not ok then
        return { success = false, error = tostring(pid) }
    end

    return { success = true, process_id = pid }
end

function cmd_send_window_message(params)
    local handle = parseHandle(params.handle)
    if not handle then
        return { success = false, error = "Invalid handle" }
    end

    local msg    = params.msg    or 0
    local wparam = params.wparam or 0
    local lparam = params.lparam or 0

    local ok, result = pcall(function()
        return sendMessage(handle, msg, wparam, lparam)
    end)

    if not ok then
        return { success = false, error = tostring(result) }
    end

    return { success = true, result = result or 0 }
end

-- Modal dialog — blocks the CE main thread until the user clicks OK.
function cmd_show_message(params)
    local message = params.message
    if not message then
        return { success = false, error = "message is required" }
    end

    local ok, err = pcall(function()
        showMessage(message)
    end)

    if not ok then
        return { success = false, error = tostring(err) }
    end

    return { success = true }
end

-- Modal dialog — blocks until the user submits or cancels.
function cmd_input_query(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local default = params.default or ""

    local ok, value = pcall(function()
        return inputQuery(caption, prompt, default)
    end)

    if not ok then
        return { success = false, error = tostring(value) }
    end

    -- inputQuery returns nil on cancel (CE contract)
    if value == nil then
        return { success = true, value = "", cancelled = true }
    end

    return { success = true, value = value, cancelled = false }
end

-- Modal dialog — blocks until the user selects an item or cancels.
function cmd_show_selection_list(params)
    local caption = params.caption or ""
    local prompt  = params.prompt  or ""
    local options = params.options

    if type(options) ~= "table" then
        return { success = false, error = "options must be a list of strings" }
    end

    local sl = createStringlist()
    for _, v in ipairs(options) do
        sl.add(tostring(v))
    end

    local ok, idx, selected = pcall(function()
        return showSelectionList(caption, prompt, sl)
    end)

    sl.destroy()

    if not ok then
        return { success = false, error = tostring(idx) }
    end

    if idx == nil or idx < 0 then
        return { success = true, selected_index = -1, selected_value = "", cancelled = true }
    end

    return {
        success        = true,
        selected_index = idx,
        selected_value = selected or "",
        cancelled      = false
    }
end

-- >>> END UNIT-16 <<<

-- >>> BEGIN UNIT-15 Advanced Scanning <<<
-- ============================================================================
-- UNIT 15: Advanced Scanning (module-scoped, unique, persistent)
-- ============================================================================

-- Persistent scan state (Unit 15)
serverState.persistent_scans = serverState.persistent_scans or {}

-- Helper: NO_PROCESS guard used by all Unit-15 commands

-- Helper: map human-readable var-type string to CE constant
local function resolveVarType(vtype)
    local t = (vtype or "dword"):lower()
    -- v15.8.2: unknown names return nil (callers fail fast with
    -- INVALID_PARAMS) instead of silently scanning as dword.
    if t == "byte"   then return vtByte
    elseif t == "word"   then return vtWord
    elseif t == "dword"  then return vtDword
    elseif t == "qword"  then return vtQword
    elseif t == "float"  then return vtSingle
    elseif t == "double" then return vtDouble
    elseif t == "string" then return vtString
    else return nil
    end
end

-- Helper: map human-readable scan_option to CE constant
local function resolveScanOption(opt)
    local o = (opt or "exact"):lower()
    -- v15.8.2: unknown names return nil so callers fail fast with
    -- INVALID_PARAMS. The old silent fallback to soExactValue made e.g.
    -- scan_option "value_between" (wrong name; the real one is "between",
    -- now accepted as an alias) run an exact scan for a literal "0;10000"
    -- string and silently corrupt the scan session.
    if o == "exact"          then return soExactValue
    elseif o == "unknown"    then return soUnknownValue
    elseif o == "between" or o == "value_between" then return soValueBetween
    elseif o == "bigger"     then return soBiggerThan
    elseif o == "smaller"    then return soSmallerThan
    elseif o == "increased"  then return soIncreasedValue
    elseif o == "decreased"  then return soDecreasedValue
    elseif o == "changed"    then return soChanged
    elseif o == "unchanged"  then return soUnchanged
    else return nil
    end
end

function cmd_aob_scan_unique(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local pattern    = params.pattern
    local protection = params.protection or "+X"

    if not pattern then
        return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" }
    end

    -- AOBScan lets us count matches; AOBScanUnique returns first-found (non-deterministic on multiple hits)
    local results
    local scanOk, scanMsg = pcall(function()
        results = AOBScan(pattern, protection)
    end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
    end

    local count = results and results.Count or 0
    if count ~= 1 then
        if results then pcall(function() results.destroy() end) end
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    local addrStr = results.getString(0)
    local addr    = tonumber(addrStr, 16)
    pcall(function() results.destroy() end)

    return {
        success = true,
        address = "0x" .. (addrStr or "0"),
        value   = addr
    }
end

function cmd_aob_scan_module(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local pattern     = params.pattern
    local _texp, _terr = expandSigTokens(pattern)
    if _texp == nil then return _terr end
    pattern = _texp
    local module_name = params.module_name
    local protection  = params.protection or "+X"

    if not pattern     then return { success = false, error = "No pattern provided",     error_code = "INVALID_PARAMS" } end
    if not module_name then return { success = false, error = "No module_name provided", error_code = "INVALID_PARAMS" } end

    local modBase, modSize
    local modBaseOk = pcall(function() modBase = getAddress(module_name) end)
    if not modBaseOk or not modBase or modBase == 0 then
        return { success = false, error = "Module not found: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modSizeOk = pcall(function() modSize = getModuleSize(module_name) end)
    if not modSizeOk or not modSize or modSize == 0 then
        return { success = false, error = "Cannot get module size for: " .. tostring(module_name), error_code = "INVALID_PARAMS" }
    end

    local modEnd = modBase + modSize

    local results
    local scanOk, scanMsg = pcall(function() results = AOBScan(pattern, protection) end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
    end

    local addresses = {}
    if results and results.Count > 0 then
        for i = 0, results.Count - 1 do
            local addrStr = results.getString(i)
            local addr    = tonumber(addrStr, 16)
            if addr and addr >= modBase and addr < modEnd then
                table.insert(addresses, "0x" .. addrStr)
            end
        end
    end
    if results then pcall(function() results.destroy() end) end

    return {
        success     = true,
        count       = #addresses,
        module_name = module_name,
        pattern     = pattern,
        addresses   = addresses
    }
end

function cmd_aob_scan_module_unique(params)
    -- requireProcess() is also called inside cmd_aob_scan_module; early-exit here gives a cleaner error path
    local ok, err = requireProcess()
    if not ok then return err end

    local r = cmd_aob_scan_module(params)
    if not r.success then return r end

    local count = r.count or 0
    if count ~= 1 then
        return {
            success    = false,
            error      = "Pattern matched " .. tostring(count) .. " times in module (expected 1)",
            error_code = "INVALID_PARAMS",
            count      = count
        }
    end

    return {
        success = true,
        address = r.addresses[1],
        module_name = params.module_name
    }
end

function cmd_pointer_rescan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local value               = params.value
    local previous_results_file = params.previous_results_file

    if not value then
        return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" }
    end

    local rescanOk, rescanMsg = pcall(function()
        if previous_results_file then
            pointerRescan(value, previous_results_file)
        else
            pointerRescan(value)
        end
    end)

    if not rescanOk then
        return {
            success    = false,
            error      = "pointerRescan failed: " .. tostring(rescanMsg),
            error_code = "SCAN_ERROR",
            note       = "A prior pointer scan must exist in CE before calling pointer_rescan"
        }
    end

    return { success = true, result_count = -1, note = "Pointer rescan complete. Check CE Pointer Scanner window for results." }
end

function cmd_create_persistent_scan(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local name = params.name
    if not name or name == "" then
        return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" }
    end

    local existing = serverState.persistent_scans[name]
    if existing then
        if existing.fl then pcall(function() existing.fl.destroy() end) end
        pcall(function() existing.ms.destroy() end)
        serverState.persistent_scans[name] = nil
    end

    local ms
    local msOk, msMsg = pcall(function() ms = createMemScan() end)
    if not msOk or not ms then
        return { success = false, error = "createMemScan failed: " .. tostring(msMsg), error_code = "SCAN_ERROR" }
    end

    serverState.persistent_scans[name] = {
        ms       = ms,
        fl       = nil,
        has_scan = false
    }

    return { success = true, scan_name = name }
end

function cmd_persistent_scan_first_scan(params)
    local name        = params.name
    local value       = params.value
    local vtype       = params.type or "dword"
    local scan_option = params.scan_option or "exact"

    if not name  then return { success = false, error = "No name provided",  error_code = "INVALID_PARAMS" } end
    if not value then return { success = false, error = "No value provided", error_code = "INVALID_PARAMS" } end

    -- v15.8.2: strict name validation BEFORE the process guard so callers
    -- learn about typos immediately instead of silently scanning as
    -- dword/exact and corrupting the session.
    local varType = resolveVarType(vtype)
    if not varType then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "unknown value type '" .. tostring(vtype) .. "' (valid: " .. VAR_TYPE_NAMES .. ")" }
    end
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "unknown scan_option '" .. tostring(scan_option) .. "' (valid: " .. SCAN_OPTION_NAMES .. ")" }
    end

    local ok, err = requireProcess()
    if not ok then return err end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found. Call create_persistent_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms = entry.ms

    -- v15.8.2: same between-form guard as the next-scan path.
    if scanOpt == soValueBetween and (type(value) ~= "string" or not value:find(";", 1, true)) then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "scan_option 'between' requires value in 'v1;v2' form" }
    end

    local fsOk, fsMsg = pcall(function()
        if scanOpt == soValueBetween and value and string.find(value, ";") then
            local v1, v2 = string.match(value, "^(.-);(.-)$")
            ms.firstScan(scanOpt, varType, rtRounded, v1, v2,
                         0, 0x7FFFFFFFFFFFFFFF, "+W-C", fsmNotAligned, "1",
                         false, false, false, false)
        else
            ms.firstScan(scanOpt, varType, rtRounded, tostring(value), nil,
                         0, 0x7FFFFFFFFFFFFFFF, "+W-C", fsmNotAligned, "1",
                         false, false, false, false)
        end
        ms.waitTillDone()
    end)
    if not fsOk then
        return { success = false, error = "firstScan failed: " .. tostring(fsMsg), error_code = "SCAN_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "SCAN_ERROR" }
    end

    entry.fl       = fl
    entry.has_scan = true

    return { success = true, scan_name = name, count = fl.getCount() }
end

function cmd_persistent_scan_next_scan(params)
    local name        = params.name
    local value       = params.value
    local scan_option = params.scan_option or "exact"

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    -- v15.8.2: strict option validation BEFORE the process guard (fail fast
    -- on typos instead of silently running an exact scan).
    local scanOpt = resolveScanOption(scan_option)
    if not scanOpt then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "unknown scan_option '" .. tostring(scan_option) .. "' (valid: " .. SCAN_OPTION_NAMES .. ")" }
    end

    local ok, err = requireProcess()
    if not ok then return err end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.has_scan then
        return { success = false, error = "No first scan done for '" .. name .. "'. Call persistent_scan_first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local ms = entry.ms

    -- v15.8.2: a between filter without the "v1;v2" separator would hand a
    -- bare value to CE's between scan; reject it up front.
    if scanOpt == soValueBetween and (type(value) ~= "string" or not value:find(";", 1, true)) then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "scan_option 'between' requires value in 'v1;v2' form" }
    end

    local nsOk, nsMsg = pcall(function()
        if scanOpt == soValueBetween and value and string.find(value, ";") then
            local v1, v2 = string.match(value, "^(.-);(.-)$")
            ms.nextScan(scanOpt, rtRounded, v1, v2, false, false, false, false, false)
        elseif scanOpt == soExactValue or scanOpt == soValueBetween or scanOpt == soBiggerThan or scanOpt == soSmallerThan then
            ms.nextScan(scanOpt, rtRounded, tostring(value or ""), nil, false, false, false, false, false)
        else
            ms.nextScan(scanOpt, rtRounded, nil, nil, false, false, false, false, false)
        end
        ms.waitTillDone()
    end)
    if not nsOk then
        return { success = false, error = "nextScan failed: " .. tostring(nsMsg), error_code = "SCAN_ERROR" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    local fl
    local flOk, flMsg = pcall(function()
        fl = createFoundList(ms)
        fl.initialize()
    end)
    if not flOk then
        return { success = false, error = "createFoundList failed: " .. tostring(flMsg), error_code = "SCAN_ERROR" }
    end

    entry.fl = fl

    return { success = true, scan_name = name, count = fl.getCount() }
end

function cmd_persistent_scan_get_results(params)
    local name   = params.name
    local offset = params.offset or 0
    local limit  = math.min(params.limit or 100, 10000)

    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end
    if not entry.fl then
        return { success = false, error = "No results for '" .. name .. "'. Run first_scan first.", error_code = "INVALID_PARAMS" }
    end

    local fl      = entry.fl
    local total   = fl.getCount()
    local results = {}

    local stop = math.min(offset + limit - 1, total - 1)
    for i = offset, stop do
        local addrStr = fl.getAddress(i)
        if addrStr and not addrStr:match("^0[xX]") then
            addrStr = "0x" .. addrStr
        end
        table.insert(results, {
            address = addrStr,
            value   = fl.getValue(i)
        })
    end

    return {
        success   = true,
        scan_name = name,
        total     = total,
        offset    = offset,
        limit     = limit,
        results   = results
    }
end

function cmd_persistent_scan_destroy(params)
    local name = params.name
    if not name then return { success = false, error = "No name provided", error_code = "INVALID_PARAMS" } end

    local entry = serverState.persistent_scans[name]
    if not entry then
        return { success = false, error = "Scan '" .. name .. "' not found.", error_code = "INVALID_PARAMS" }
    end

    if entry.fl then pcall(function() entry.fl.destroy() end) end
    pcall(function() entry.ms.destroy() end)
    serverState.persistent_scans[name] = nil

    return { success = true, scan_name = name, destroyed = true }
end

-- >>> END UNIT-15 <<<

-- >>> BEGIN UNIT-14 Memory Operations <<<
-- ============================================================================
-- COMMAND HANDLERS - MEMORY OPERATIONS (Unit 14)
-- ============================================================================


function cmd_copy_memory(params)
    -- Params first, process guard second: INVALID_PARAMS is actionable even
    -- before a process is attached.
    local src = params.source
    local size = params.size
    local dest = params.dest  -- may be nil
    local method = params.method or 0

    if not src then return { success = false, error = "Missing source address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end
    if size > 64 * 1024 * 1024 then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "size exceeds the 64 MiB copy_memory limit" }
    end

    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    if type(src) == "string" then src = getAddressSafe(src) end
    if not src then return { success = false, error = "Invalid source address" } end

    local destAddr = nil
    if dest ~= nil then
        if type(dest) == "string" then destAddr = getAddressSafe(dest)
        else destAddr = dest end
        if not destAddr then return { success = false, error = "Invalid dest address" } end
    end

    local ok, result = pcall(copyMemory, src, size, destAddr, method)
    if not ok or not result then
        return { success = false, error = "copyMemory failed: " .. tostring(result) }
    end

    return { success = true, dest_address = toHex(result), size = size }
end

function cmd_compare_memory(params)
    -- Params first, process guard second (see cmd_copy_memory).
    local addr1 = params.addr1
    local addr2 = params.addr2
    local size = params.size
    local method = params.method or 0

    if not addr1 then return { success = false, error = "Missing addr1" } end
    if not addr2 then return { success = false, error = "Missing addr2" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end
    if size > 64 * 1024 * 1024 then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "size exceeds the 64 MiB compare_memory limit" }
    end

    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    if type(addr1) == "string" then addr1 = getAddressSafe(addr1) end
    if type(addr2) == "string" then addr2 = getAddressSafe(addr2) end
    if not addr1 then return { success = false, error = "Invalid addr1" } end
    if not addr2 then return { success = false, error = "Invalid addr2" } end

    local ok, r1, r2 = pcall(compareMemory, addr1, addr2, size, method)
    if not ok then
        return { success = false, error = "compareMemory failed: " .. tostring(r1) }
    end

    if r1 == true then
        return { success = true, equal = true, first_diff = -1 }
    else
        return { success = true, equal = false, first_diff = r2 or -1 }
    end
end

function cmd_write_region_to_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local addr = params.address
    local size = params.size
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    if not addr then return { success = false, error = "Missing address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local ok, bytes_written = pcall(writeRegionToFile, sanitized, addr, size)
    if not ok then
        return { success = false, error = "writeRegionToFile failed: " .. tostring(bytes_written) }
    end

    return { success = true, bytes_written = bytes_written or 0, filename = sanitized }
end

function cmd_read_region_from_file(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local filename = params.filename
    local destination = params.destination

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    if not destination then return { success = false, error = "Missing destination address" } end

    if type(destination) == "string" then destination = getAddressSafe(destination) end
    if not destination then return { success = false, error = "Invalid destination address" } end

    local ok, bytes_read = pcall(readRegionFromFile, sanitized, destination)
    if not ok then
        return { success = false, error = "readRegionFromFile failed: " .. tostring(bytes_read) }
    end

    return { success = true, bytes_read = bytes_read or 0 }
end

function cmd_md5_memory(params)
    -- Params first, process guard second (see cmd_copy_memory).
    local addr = params.address
    local size = params.size

    if not addr then return { success = false, error = "Missing address" } end
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end
    -- Matches the documented 16 MiB cap (AGENTS.md "memory-MD5 size <= 16 MiB");
    -- md5memory walks the whole region on the CE main thread.
    if size > 16 * 1024 * 1024 then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "size exceeds the 16 MiB md5_memory limit; hash in chunks (checksum_memory)" }
    end

    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local ok, result = pcall(md5memory, addr, size)
    if not ok or not result then
        return { success = false, error = "md5memory failed: " .. tostring(result) }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_md5_file(params)
    local filename = params.filename

    local sanitized, err = sanitizeFilename(filename)
    if not sanitized then return { success = false, error = err } end

    local ok, result = pcall(md5file, sanitized)
    if not ok or not result then
        return { success = false, error = "md5file failed: " .. tostring(result) }
    end

    return { success = true, md5 = tostring(result) }
end

function cmd_create_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local size = params.size
    if not size or size <= 0 then return { success = false, error = "Missing or invalid size" } end

    local ok, handle = pcall(createSection, size)
    if not ok or not handle then
        return { success = false, error = "createSection failed: " .. tostring(handle) }
    end

    return { success = true, handle = toHex(handle) }
end

function cmd_map_view_of_section(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then return { success = false, error = "No process attached" } end

    local handle = params.handle
    local address = params.address  -- optional preferred base

    if not handle then return { success = false, error = "Missing handle" } end

    if type(handle) == "string" then handle = tonumber(handle, 16) end
    if not handle then return { success = false, error = "Invalid handle" } end

    local prefAddr = nil
    if address ~= nil then
        if type(address) == "string" then prefAddr = getAddressSafe(address)
        else prefAddr = address end
        if not prefAddr then return { success = false, error = "Invalid address" } end
    end

    local ok, mapped
    if prefAddr then
        ok, mapped = pcall(mapViewOfSection, handle, prefAddr)
    else
        ok, mapped = pcall(mapViewOfSection, handle)
    end

    if not ok or not mapped then
        return { success = false, error = "mapViewOfSection failed: " .. tostring(mapped) }
    end

    return { success = true, mapped_address = toHex(mapped) }
end

-- >>> END UNIT-14 <<<

-- >>> BEGIN UNIT-13 Assembly & Compilation <<<
-- ============================================================================
-- ASSEMBLY & COMPILATION TOOLS (Unit 13)
-- ============================================================================

-- Helper: check process is attached (for tools that need a target process address)
-- >>> BEGIN UNIT-12 Symbol Management <<<
function cmd_register_symbol(params)
    local name = params.name
    local address = params.address
    local do_not_save = params.do_not_save
    if do_not_save == nil then do_not_save = false end
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    if type(address) ~= "string" and type(address) ~= "number" then
        return { success = false, error = "Parameter 'address' must be a string or integer", error_code = "INVALID_PARAMS" }
    end
    local resolvedAddr = address
    if type(address) == "string" then
        resolvedAddr = getAddressSafe(address)
    end
    if not resolvedAddr or resolvedAddr == 0 then
        return { success = false, error = "Invalid address: " .. tostring(address), error_code = "INVALID_ADDRESS" }
    end
    local ok, err = pcall(registerSymbol, name, resolvedAddr, do_not_save)
    if not ok then
        return { success = false, error = "registerSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, name = name, address = toHex(resolvedAddr) }
end

function cmd_unregister_symbol(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, err = pcall(unregisterSymbol, name)
    if not ok then
        return { success = false, error = "unregisterSymbol failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enum_registered_symbols(params)
    local ok, result = pcall(enumRegisteredSymbols)
    if not ok then
        return { success = false, error = "enumRegisteredSymbols failed: " .. tostring(result), error_code = "INTERNAL_ERROR" }
    end
    local symbols = {}
    if result and type(result) == "table" then
        for i = 1, #result do
            local sym = result[i]
            if sym then
                local addrVal = sym.address or 0
                local modName = sym.module or sym.modulename or ""
                table.insert(symbols, {
                    name    = sym.symbolname or sym.name or "",
                    address = toHex(addrVal),
                    module  = tostring(modName)
                })
            end
        end
    end
    return { success = true, count = #symbols, symbols = symbols }
end

function cmd_delete_all_registered_symbols(params)
    -- Count before deleting (CE returns no count from deleteAllRegisteredSymbols)
    local countOk, symResult = pcall(enumRegisteredSymbols)
    local deletedCount = 0
    if countOk and symResult and type(symResult) == "table" then
        deletedCount = #symResult
    end
    local ok, err = pcall(deleteAllRegisteredSymbols)
    if not ok then
        return { success = false, error = "deleteAllRegisteredSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true, deleted_count = deletedCount }
end

function cmd_enable_windows_symbols(params)
    local ok, err = pcall(enableWindowsSymbols)
    if not ok then
        return { success = false, error = "enableWindowsSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_enable_kernel_symbols(params)
    local ok, err = pcall(enableKernelSymbols)
    if not ok then
        local errMsg = tostring(err)
        if errMsg:lower():find("dbk") or errMsg:lower():find("kernel") or errMsg:lower():find("driver") then
            return { success = false, error = "Kernel driver not loaded", error_code = "DBK_NOT_LOADED" }
        end
        return { success = false, error = "enableKernelSymbols failed: " .. errMsg, error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_get_symbol_info(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "Parameter 'name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, info = pcall(getSymbolInfo, name)
    if not ok then
        return { success = false, error = "getSymbolInfo failed: " .. tostring(info), error_code = "INTERNAL_ERROR" }
    end
    if not info then
        return { success = false, error = "Symbol not found: " .. name, error_code = "NOT_FOUND" }
    end
    local addrVal = info.address or 0
    local modName = info.modulename or info.module or ""
    return {
        success = true,
        name    = info.searchkey or info.name or name,
        address = toHex(addrVal),
        module  = tostring(modName),
        size    = info.size or 0
    }
end

function cmd_get_module_size(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    local module_name = params.module_name
    if type(module_name) ~= "string" or module_name == "" then
        return { success = false, error = "Parameter 'module_name' must be a non-empty string", error_code = "INVALID_PARAMS" }
    end
    local ok, sz = pcall(getModuleSize, module_name)
    if not ok then
        return { success = false, error = "getModuleSize failed: " .. tostring(sz), error_code = "INTERNAL_ERROR" }
    end
    if not sz then
        return { success = false, error = "Module not found: " .. module_name, error_code = "NOT_FOUND" }
    end
    return { success = true, size = sz }
end

function cmd_load_new_symbols(params)
    local ok, err = pcall(loadNewSymbols)
    if not ok then
        return { success = false, error = "loadNewSymbols failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end

function cmd_reinitialize_symbol_handler(params)
    local ok, err = pcall(reinitializeSymbolhandler)
    if not ok then
        return { success = false, error = "reinitializeSymbolhandler failed: " .. tostring(err), error_code = "INTERNAL_ERROR" }
    end
    return { success = true }
end
-- >>> END UNIT-12 <<<
-- >>> BEGIN UNIT-11 Context + ThreadBPs <<<
-- ============================================================================
-- UNIT-11: DEBUG CONTEXT INSPECTION + PER-THREAD BREAKPOINTS
-- ============================================================================

local function u11_guard()
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return false, { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return true, nil
end

function cmd_assemble_instruction(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local line = params.line
    local address = params.address
    local preference = params.preference or 0
    local skipRangeCheck = params.skip_range_check or false

    if not line or line == "" then
        return { success = false, error = "No instruction line provided" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address) }
    end

    -- assemble() accepts nil address; it skips relative-offset resolution in that case
    local asmOk, result = pcall(assemble, line, address, preference, skipRangeCheck)

    if not asmOk then
        return { success = false, error = "assemble() raised error: " .. tostring(result) }
    end

    if not result then
        return { success = false, error = "assemble() returned nil (invalid instruction or address)" }
    end

    local bytes = {}
    for i = 1, #result do bytes[i] = result[i] end

    return { success = true, bytes = bytes, size = #bytes }
end

function cmd_auto_assemble_check(params)
    local script = params.script
    local _sexp, _serr = expandSigTokens(script)
    if _sexp == nil then return _serr end
    script = _sexp
    local enable = params.enable
    if enable == nil then enable = true end
    local targetSelf = params.target_self or false

    if not script or script == "" then
        return { success = false, error = "No script provided" }
    end

    -- Size gate: autoAssembleCheck on large scripts is a documented
    -- main-thread hang (real case: a 38 KB script froze CE). Fail fast and
    -- let the caller review statically or split the script instead.
    if #script > AA_MAX_SCRIPT_SIZE then
        return { success = false, valid = false,
                 error = string.format("Script too large: %d bytes (max %d). "
                     .. "Assembly-level check on scripts this size can freeze CE's "
                     .. "main thread. Review it statically or split it into sections.",
                     #script, AA_MAX_SCRIPT_SIZE),
                 error_code = "SCRIPT_TOO_LARGE" }
    end

    local checkOk, valid, errMsg = pcall(autoAssembleCheck, script, enable, targetSelf)

    if not checkOk then
        return { success = false, valid = false, errors = { tostring(valid) } }
    end

    if valid then
        return { success = true, valid = true, errors = {} }
    end

    local errors = {}
    if errMsg then table.insert(errors, tostring(errMsg)) end
    return { success = true, valid = false, errors = errors }
end

function cmd_compile_c_code(params)
    -- No NO_PROCESS guard: pure compilation without an address doesn't require a target process
    local source = params.source
    local address = params.address
    local targetSelf = params.target_self or false
    local kernelMode = params.kernelmode or false

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compile) ~= "function" then
        return { success = false, error = "TCC compiler not available", error_code = "CE_API_UNAVAILABLE" }
    end

    if type(address) == "string" then address = getAddressSafe(address) end
    if address == nil and params.address ~= nil then
        return { success = false, error = "Invalid address: " .. tostring(params.address) }
    end

    local compOk, symbols, errMsg = pcall(compile, source, address, targetSelf, kernelMode, false)

    if not compOk then
        return { success = false, symbols = {}, errors = { tostring(symbols) } }
    end

    if not symbols then
        local errors = {}
        if errMsg then table.insert(errors, tostring(errMsg)) end
        return { success = false, symbols = {}, errors = errors }
    end

    local symResult = {}
    for name, addr in pairs(symbols) do
        symResult[tostring(name)] = toHex(addr)
    end

    return { success = true, symbols = symResult, errors = {} }
end

function cmd_compile_cs_code(params)
    local source = params.source
    local references = params.references or {}
    local coreAssembly = params.core_assembly

    if not source or source == "" then
        return { success = false, error = "No source code provided" }
    end

    if type(compileCS) ~= "function" then
        return { success = false, error = ".NET runtime or compileCS not available", error_code = "CE_API_UNAVAILABLE" }
    end

    -- compileCS(text, references, coreAssembly OPTIONAL) — pass coreAssembly only when provided
    local csOk, result = pcall(compileCS, source, references, coreAssembly)

    if not csOk then
        return { success = false, assembly_handle = nil, error = tostring(result) }
    end

    if not result then
        return { success = false, assembly_handle = nil, error = "compileCS returned nil" }
    end

    return { success = true, assembly_handle = tostring(result) }
end

function cmd_generate_api_hook_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    local targetAddress = params.target_address
    local codeToExecute = params.code_to_execute or ""

    if not address then return { success = false, error = "No address provided" } end
    if not targetAddress then return { success = false, error = "No target_address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if type(targetAddress) == "string" then targetAddress = getAddressSafe(targetAddress) end

    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end
    if not targetAddress then return { success = false, error = "Invalid target_address: " .. tostring(params.target_address) } end

    -- CE signature: generateAPIHookScript(address, addresstojumpto, addresstogetnewcalladdress OPT, ext OPT, targetself OPT)
    -- code_to_execute maps to ext (4th param); 3rd param (new-call-address) is unused here
    local ext = codeToExecute ~= "" and codeToExecute or nil
    local genOk, result = pcall(generateAPIHookScript, address, targetAddress, nil, ext)

    if not genOk then
        return { success = false, error = "generateAPIHookScript failed: " .. tostring(result) }
    end

    if not result then
        return { success = false, error = "generateAPIHookScript returned nil" }
    end

    return { success = true, script = tostring(result) }
end

function cmd_generate_code_injection_script(params)
    local ok, err = requireProcess()
    if not ok then return err end

    local address = params.address
    if not address then return { success = false, error = "No address provided" } end

    if type(address) == "string" then address = getAddressSafe(address) end
    if not address then return { success = false, error = "Invalid address: " .. tostring(params.address) } end

    -- generateCodeInjectionScript(script: TStrings, address, farjmp) mutates TStrings in-place
    local sl = createStringlist()
    local genOk, genErr = pcall(generateCodeInjectionScript, sl, address)

    if not genOk then
        sl.destroy()
        return { success = false, error = "generateCodeInjectionScript failed: " .. tostring(genErr) }
    end

    local script = sl.Text
    sl.destroy()

    if not script or script == "" then
        return { success = false, error = "generateCodeInjectionScript produced empty script" }
    end

    return { success = true, script = script }
end

-- >>> END UNIT-13 <<<

-- All settable register names shared between get and set handlers
local U11_REG_NAMES = {
    "RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","RIP",
    "R8","R9","R10","R11","R12","R13","R14","R15",
    "EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP",
    "EFLAGS"
}

function cmd_debug_get_context(params)
    local extraRegs = params.extra_regs == true

    local ok, err = u11_guard()
    if not ok then return err end

    local callOk, callErr = pcall(debug_getContext, extraRegs)
    if not callOk then
        return { success = false, error = "debug_getContext failed: " .. tostring(callErr), error_code = "CE_API_ERROR" }
    end

    -- captureRegisters() reads the same CE globals that debug_getContext just populated
    local regs = captureRegisters()
    local arch  = regs.arch
    regs.arch   = nil  -- arch is returned at top level, not inside registers

    local result = { success = true, arch = arch, registers = regs }

    if extraRegs then
        local extra = {}
        local is64  = arch == "x64"
        -- XMM0-15 (0-7 on 32-bit): each pointer is a CE-local address of 16 raw bytes
        local maxXmm = is64 and 15 or 7
        for i = 0, maxXmm do
            local xmmOk, xmmPtr = pcall(debug_getXMMPointer, i)
            if xmmOk and xmmPtr then
                local rawBytes = readBytes(xmmPtr, 16, true)
                if rawBytes then
                    local parts = {}
                    for _, b in ipairs(rawBytes) do
                        parts[#parts + 1] = string.format("%02X", b)
                    end
                    extra["xmm" .. i] = table.concat(parts)
                end
            end
        end
        -- FP0-FP7 are globals populated by debug_getContext(true)
        local fpVars = { FP0, FP1, FP2, FP3, FP4, FP5, FP6, FP7 }
        for i, v in ipairs(fpVars) do
            if v ~= nil then extra["fp" .. (i - 1)] = tostring(v) end
        end
        result.extra = extra
    end

    return result
end

function cmd_debug_set_context(params)
    local registers = params.registers
    if type(registers) ~= "table" then
        return { success = false, error = "registers must be an object/dict", error_code = "INVALID_PARAMS" }
    end

    local ok, err = u11_guard()
    if not ok then return err end

    for _, name in ipairs(U11_REG_NAMES) do
        local val = registers[name]
        if val ~= nil then
            local numVal
            if type(val) == "string" then
                numVal = tonumber(val, 16) or tonumber(val)
            elseif type(val) == "number" then
                numVal = val
            end
            if numVal then _G[name] = numVal end
        end
    end

    local setOk, setErr = pcall(debug_setContext)
    if not setOk then
        return { success = false, error = "debug_setContext failed: " .. tostring(setErr), error_code = "CE_API_ERROR" }
    end

    return { success = true }
end

function cmd_debug_get_xmm_pointer(params)
    local xmmNr = params.xmm_nr or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local ptrOk, ptr = pcall(debug_getXMMPointer, xmmNr)
    if not ptrOk then
        return { success = false, error = "debug_getXMMPointer failed: " .. tostring(ptr), error_code = "CE_API_ERROR" }
    end

    return { success = true, xmm_nr = xmmNr, pointer = toHex(ptr) }
end

function cmd_debug_set_last_branch_recording(params)
    local enable = params.enable == true

    local ok, err = u11_guard()
    if not ok then return err end

    -- LBR only works under kernel-mode debugger (interface == 3)
    local iface = debug_getCurrentDebuggerInterface and debug_getCurrentDebuggerInterface() or nil
    if iface ~= 3 then
        return {
            success            = false,
            error              = "LBR requires kernel debugger",
            error_code         = "CE_API_UNAVAILABLE",
            debugger_interface = iface
        }
    end

    local lbrOk, lbrErr = pcall(debug_setLastBranchRecording, enable)
    if not lbrOk then
        return { success = false, error = "debug_setLastBranchRecording failed: " .. tostring(lbrErr), error_code = "CE_API_ERROR" }
    end

    return { success = true, enabled = enable }
end

function cmd_debug_get_last_branch_record(params)
    local index = params.index or 0

    local ok, err = u11_guard()
    if not ok then return err end

    local recOk, record = pcall(debug_getLastBranchRecord, index)
    if not recOk then
        return { success = false, error = "debug_getLastBranchRecord failed: " .. tostring(record), error_code = "CE_API_ERROR" }
    end

    if type(record) ~= "table" then
        return { success = false, error = "Unexpected return from debug_getLastBranchRecord: " .. tostring(record), error_code = "CE_API_ERROR" }
    end

    return {
        success = true,
        index   = index,
        from    = record.from and toHex(record.from) or nil,
        to      = record.to   and toHex(record.to)   or nil,
    }
end

function cmd_debug_set_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address
    local size     = params.size    or 1
    local trigger  = params.trigger or "execute"

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    local bpTrigger
    if trigger == "write" then
        bpTrigger = bptWrite
    elseif trigger == "read" or trigger == "access" then
        bpTrigger = bptAccess
    else
        bpTrigger = bptExecute
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoint_hits[bpHandle] = {}

    local setOk, setErr = pcall(debug_setBreakpointForThread, threadId, addr, size, bpTrigger, bpmDebugRegister, function()
        table.insert(serverState.breakpoint_hits[bpHandle], {
            handle    = bpHandle,
            thread_id = threadId,
            address   = toHex(addr),
            timestamp = os.time(),
            registers = captureRegisters(),
        })
        debug_continueFromBreakpoint(co_run)
        return 1
    end)

    if not setOk then
        serverState.breakpoint_hits[bpHandle] = nil
        return { success = false, error = "debug_setBreakpointForThread failed: " .. tostring(setErr), error_code = "CE_API_ERROR" }
    end

    serverState.breakpoints[bpHandle] = { address = addr, type = "thread_bp", thread_id = threadId }

    return {
        success   = true,
        bp_handle = bpHandle,
        thread_id = threadId,
        address   = toHex(addr),
        trigger   = trigger,
        size      = size,
    }
end

function cmd_debug_remove_breakpoint_for_thread(params)
    local threadId = params.thread_id
    local addr     = params.address

    if not threadId then return { success = false, error = "thread_id is required", error_code = "INVALID_PARAMS" } end

    local ok, err = u11_guard()
    if not ok then return err end

    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address", error_code = "INVALID_PARAMS" } end

    -- CE has no dedicated per-thread remove; debug_removeBreakpoint by address is the supported path
    local remOk, remErr = pcall(debug_removeBreakpoint, addr)
    if not remOk then
        return { success = false, error = "debug_removeBreakpoint failed: " .. tostring(remErr), error_code = "CE_API_ERROR" }
    end

    local bpHandle = "thread_" .. tostring(threadId) .. "_" .. toHex(addr)
    serverState.breakpoints[bpHandle]     = nil
    serverState.breakpoint_hits[bpHandle] = nil

    return { success = true, thread_id = threadId, address = toHex(addr) }
end

-- >>> END UNIT-11 <<<
-- >>> BEGIN UNIT-10 Debugger Control <<<
-- ============================================================================
-- COMMAND HANDLERS - DEBUGGER CONTROL (Unit 10)
-- ============================================================================
-- Wraps CE's native debugger control APIs: debugProcess, debug_isDebugging,
-- debug_getCurrentDebuggerInterface, debug_breakThread,
-- debug_continueFromBreakpoint, detachIfPossible, pause, unpause.
--
-- pause() and unpause() are confirmed CE global functions (celua.txt lines 441-442).
-- co_run, co_stepinto, co_stepover are CE global constants used by
-- debug_continueFromBreakpoint (celua.txt line 822).

-- Maps debugProcess interface int to a readable name.
-- Input domain: 0=default, 1=Windows(native), 2=VEH, 3=Kernel(DBK), 4=DBVM
local DEBUGGER_INTERFACE_INPUT_NAME = {
    [0] = "default",
    [1] = "windows_native",
    [2] = "veh",
    [3] = "kernel_dbk",
    [4] = "dbvm",
}

-- Maps debug_getCurrentDebuggerInterface() output to a readable name.
-- CE docs: 1=windows, 2=VEH, 3=Kernel, 4=mac_native, 5=gdb, nil=none
local DEBUGGER_INTERFACE_CURRENT_NAME = {
    [1] = "windows_native",
    [2] = "veh",
    [3] = "kernel",
    [4] = "mac_native",
    [5] = "gdb",
}

function cmd_debug_process(params)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end
    local iface = params.interface or 0
    if type(iface) ~= "number" then iface = tonumber(iface) or 0 end
    local ok, err = pcall(debugProcess, iface)
    if not ok then
        return { success = false, error = tostring(err) }
    end
    return {
        success = true,
        interface_used = iface,
        interface_name = DEBUGGER_INTERFACE_INPUT_NAME[iface] or "unknown",
    }
end

function cmd_debug_is_debugging(params)
    local ok, result = pcall(debug_isDebugging)
    if not ok then
        return { success = false, error = tostring(result) }
    end
    return { success = true, is_debugging = result == true }
end

function cmd_debug_get_current_debugger_interface(params)
    if not debug_getCurrentDebuggerInterface then
        return { success = false, error = "debug_getCurrentDebuggerInterface not available in this CE version", error_code = "CE_API_UNAVAILABLE" }
    end
    if not debug_isDebugging or not debug_isDebugging() then
        return { success = true, interface = nil, interface_name = "none", note = "Not currently debugging" }
    end
    local ok, iface = pcall(debug_getCurrentDebuggerInterface)
    if not ok then
        return { success = false, error = tostring(iface), error_code = "INTERNAL_ERROR" }
    end
    local ifaceName = iface ~= nil
        and (DEBUGGER_INTERFACE_CURRENT_NAME[iface] or ("unknown_" .. tostring(iface)))
        or "none"
    return {
        success = true,
        interface = iface,
        interface_name = ifaceName,
    }
end

-- Returns nil when the debugger is active, or an error table when it is not.
local function requireDebugger()
    local ok, isDbg = pcall(debug_isDebugging)
    if not ok or not isDbg then
        return { success = false, error = "Debugger is not attached" }
    end
end

-- Calls fn() with no args, guarded by a NO_PROCESS check. Returns {success}.
local function callWithProcessGuard(fn)
    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached" }
    end
    local ok, err = pcall(fn)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_debug_break_thread(params)
    local guard = requireDebugger()
    if guard then return guard end
    local tid = params.thread_id
    if type(tid) ~= "number" then tid = tonumber(tid) end
    if not tid then
        return { success = false, error = "Missing required param: thread_id" }
    end
    local ok, err = pcall(debug_breakThread, tid)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_debug_continue(params)
    local guard = requireDebugger()
    if guard then return guard end
    local method = params.method or "run"
    -- Map string to CE constant. co_run, co_stepinto, co_stepover are CE globals.
    local ceMethod
    if method == "run" then
        ceMethod = co_run
    elseif method == "step_into" then
        ceMethod = co_stepinto
    elseif method == "step_over" then
        ceMethod = co_stepover
    else
        return { success = false, error = "Unknown method: " .. tostring(method) .. ". Valid: run, step_into, step_over" }
    end
    local ok, err = pcall(debug_continueFromBreakpoint, ceMethod)
    if not ok then return { success = false, error = tostring(err) } end
    return { success = true }
end

function cmd_debug_detach(params)
    local ok, result = pcall(detachIfPossible)
    if not ok then return { success = false, error = tostring(result) } end
    return { success = true, detached = result == true }
end

function cmd_pause_process(params)   return callWithProcessGuard(pause)   end
function cmd_unpause_process(params) return callWithProcessGuard(unpause) end

-- >>> END UNIT-10 <<<
-- >>> BEGIN UNIT-09 Code Injection <<<
-- ============================================================================
-- COMMAND HANDLERS - CODE INJECTION & EXECUTION
-- ============================================================================

-- Lua 5.1 compat: 'unpack' moved to 'table.unpack' in Lua 5.2+
local unpack = unpack or table.unpack


function cmd_inject_dll(params)
    if not requireProcess() then return { success = false, error = "No process attached" } end
    local filepath = params.filepath
    if not filepath then return { success = false, error = "No filepath provided" } end
    local skip = params.skip_symbol_reload or false

    local ok, result = pcall(injectDLL, filepath, skip)
    if not ok then
        return { success = false, error = "injectDLL failed: " .. tostring(result) }
    end
    return { success = result == true }
end

function cmd_inject_dotnet_dll(params)
    if not requireProcess() then return { success = false, error = "No process attached" } end
    local dllpath    = params.filepath
    local className  = params.class_name
    local methodName = params.method_name
    local param      = params.param or ""
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end

    if not dllpath    then return { success = false, error = "No filepath provided" } end
    if not className  then return { success = false, error = "No class_name provided" } end
    if not methodName then return { success = false, error = "No method_name provided" } end

    local ok, result = pcall(injectDotNetDLL, dllpath, className, methodName, param, timeout)
    if not ok then
        return { success = false, error = "injectDotNetDLL failed: " .. tostring(result) }
    end
    return { success = true, result = result }
end

function cmd_execute_code(params)
    if not requireProcess() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local param   = params.param   or 0
    local timeout = params.timeout
    if timeout == nil then timeout = -1 end

    local ok, retval = pcall(executeCode, addr, param, timeout)
    if not ok then
        return { success = false, error = "executeCode failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_code_ex(params)
    if not requireProcess() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeCodeEx, callMethod, timeout, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeEx failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

function cmd_execute_method(params)
    if not requireProcess() then return { success = false, error = "No process attached" } end
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local instance = params.instance
    if type(instance) == "string" then instance = getAddressSafe(instance) end

    local callMethod = params.call_method or 0
    local timeout    = params.timeout
    if timeout == nil then timeout = -1 end
    local args = params.args or {}

    local ok, retval = pcall(executeMethod, callMethod, timeout, addr, instance, unpack(args))
    if not ok then
        return { success = false, error = "executeMethod failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local param = params.param or 0

    local ok, retval = pcall(executeCodeLocal, addr, param)
    if not ok then
        return { success = false, error = "executeCodeLocal failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- No requireProcess() guard: runs in CE's own process, not the target.
function cmd_execute_code_local_ex(params)
    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr then return { success = false, error = "Invalid address" } end

    local callMethod = params.call_method or 0
    local args = params.args or {}

    local ok, retval = pcall(executeCodeLocalEx, callMethod, addr, unpack(args))
    if not ok then
        return { success = false, error = "executeCodeLocalEx failed: " .. tostring(retval) }
    end
    return { success = true, return_value = retval }
end

-- >>> END UNIT-09 <<<
-- >>> BEGIN UNIT-08 Memory Allocation <<<

-- Windows PAGE_* protection constants used by allocateMemory
local PROT_CONSTANTS = {
    r   = 0x02,  -- PAGE_READONLY
    rw  = 0x04,  -- PAGE_READWRITE
    rx  = 0x20,  -- PAGE_EXECUTE_READ
    rwx = 0x40,  -- PAGE_EXECUTE_READWRITE
}

-- Reconstruct a PAGE_* name string from r/w/x booleans
local function protectionName(r, w, x)
    if x and w and r then return "PAGE_EXECUTE_READWRITE" end
    if x and r        then return "PAGE_EXECUTE_READ"      end
    if w and r        then return "PAGE_READWRITE"         end
    if r              then return "PAGE_READONLY"          end
    if x              then return "PAGE_EXECUTE"           end
    if w              then return "PAGE_WRITECOPY"         end
    return "PAGE_NOACCESS"
end

function cmd_allocate_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local baseAddr = params.base_address
    if type(baseAddr) == "string" then baseAddr = getAddressSafe(baseAddr) end

    local protStr = params.protection or "rwx"
    local protConst = PROT_CONSTANTS[protStr]
    if not protConst then
        return { success = false, error = "Invalid protection string; use r, rw, rx, or rwx", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateMemory, size, baseAddr, protConst)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

function cmd_free_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size or 0

    local ok, err = pcall(deAlloc, addr, size)
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_allocate_shared_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local name = params.name
    if not name or name == "" then
        return { success = false, error = "Invalid name parameter", error_code = "INVALID_PARAMS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateSharedMemory, name, size)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Shared memory allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

function cmd_get_memory_protection(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local ok, allRegs = pcall(enumMemoryRegions)
    if not ok or not allRegs then
        return { success = false, error = "enumMemoryRegions failed: " .. tostring(allRegs), error_code = "INTERNAL_ERROR" }
    end

    for _, r in ipairs(allRegs) do
        local base = r.BaseAddress or 0
        local sz   = r.RegionSize or 0
        if addr >= base and addr < base + sz then
            local prot = r.Protect or 0
            local rd = (prot == 0x02 or prot == 0x04 or prot == 0x20 or prot == 0x40)
            local wr = (prot == 0x04 or prot == 0x08 or prot == 0x40 or prot == 0x80)
            local ex = (prot == 0x10 or prot == 0x20 or prot == 0x40 or prot == 0x80)
            return {
                success = true,
                read    = rd,
                write   = wr,
                execute = ex,
                raw     = protectionName(rd, wr, ex),
                protect = prot,
                base    = toHex(base),
                size    = sz,
                state   = r.State or 0
            }
        end
    end

    return { success = false, error = "Address not found in any memory region", error_code = "NOT_FOUND" }
end

function cmd_set_memory_protection(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local r = params.read  ~= false
    local w = params.write ~= false
    local x = params.execute ~= false

    local ok, err = pcall(setMemoryProtection, addr, size, { r = r, w = w, x = x })
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_full_access(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local addr = params.address
    if type(addr) == "string" then addr = getAddressSafe(addr) end
    if not addr or addr == 0 then
        return { success = false, error = "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, err = pcall(fullAccess, addr, size)
    if not ok then
        return { success = false, error = tostring(err), error_code = "INTERNAL_ERROR" }
    end

    return { success = true }
end

function cmd_allocate_kernel_memory(params)
    if (getOpenedProcessID() or 0) == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    if not dbk_initialized() then
        return { success = false, error = "Kernel driver (DBK) not loaded", error_code = "DBK_NOT_LOADED" }
    end

    local size = params.size
    if not size or type(size) ~= "number" or size <= 0 then
        return { success = false, error = "Invalid size parameter", error_code = "INVALID_PARAMS" }
    end

    local ok, result = pcall(allocateKernelMemory, size)
    if not ok then
        return { success = false, error = tostring(result), error_code = "OUT_OF_RESOURCES" }
    end
    if not result or result == 0 then
        return { success = false, error = "Kernel allocation returned null address", error_code = "OUT_OF_RESOURCES" }
    end

    return { success = true, address = toHex(result) }
end

-- >>> END UNIT-08 <<<
-- >>> BEGIN UNIT-07 Process Lifecycle <<<

function cmd_open_process(params)
    local target = params.process_id_or_name
    if not target then return { success = false, error = "Missing process_id_or_name" } end

    local numeric = tonumber(target)
    local ok, err = pcall(openProcess, numeric or target)
    if not ok then return { success = false, error = tostring(err) } end

    local ok2, pid = pcall(getOpenedProcessID)
    if not ok2 or not pid or pid == 0 then
        return { success = false, error = "Process not found or could not be opened" }
    end

    local name = (process ~= "" and process) or tostring(target)
    return { success = true, process_id = pid, process_name = name }
end

function cmd_get_process_list(params)
    local ok, list = pcall(getProcesslist)
    if not ok then return { success = false, error = tostring(list) } end

    local processes = {}
    if list then
        for k, v in pairs(list) do
            local pid, name
            if type(k) == "number" and type(v) == "string" then
                pid = k
                name = v
            elseif type(v) == "string" then
                local hex_pid, pname = v:match("^(%x+)-(.+)$")
                if hex_pid then
                    pid = tonumber(hex_pid, 16)
                    name = pname
                end
            end
            if pid and name then
                table.insert(processes, { pid = pid, name = name })
            end
        end
    end

    return { success = true, count = #processes, processes = processes }
end

function cmd_get_processid_from_name(params)
    local name = params.name
    if not name then return { success = false, error = "Missing name" } end

    local ok, pid = pcall(getProcessIDFromProcessName, name)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "Process not found", error_code = "NOT_FOUND" }
    end

    return { success = true, process_id = pid }
end

function cmd_get_foreground_process(params)
    local ok, pid = pcall(getForegroundProcess)
    if not ok then return { success = false, error = tostring(pid) } end

    local hwnd = 0
    local ok2, wh = pcall(getForegroundWindow)
    if ok2 and wh then hwnd = wh end

    return { success = true, process_id = pid or 0, window_handle = toHex(hwnd) }
end

function cmd_create_process(params)
    local path = params.path
    if not path then return { success = false, error = "Missing path" } end
    local args = params.args or ""
    local debug_flag = params.debug or false
    local break_on_entry = params.break_on_entry or false

    local ok, err = pcall(createProcess, path, args, debug_flag, break_on_entry)
    if not ok then return { success = false, error = tostring(err) } end

    local ok2, pid = pcall(getOpenedProcessID)
    local result_pid = (ok2 and pid) or 0

    return { success = true, process_id = result_pid }
end

function cmd_get_opened_process_id(params)
    local ok, pid = pcall(getOpenedProcessID)
    if not ok then return { success = false, error = tostring(pid) } end
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end
    return { success = true, process_id = pid }
end

function cmd_get_opened_process_handle(params)
    local ok, handle = pcall(getOpenedProcessHandle)
    if not ok then return { success = false, error = tostring(handle) } end
    return { success = true, handle = toHex(handle or 0) }
end

-- >>> END UNIT-07 <<<

-- ============================================================================
-- COMMAND DISPATCHER
-- ============================================================================

-- ---------- 1) token management ----------

function cmd_set_signature_tokens(params)
    local ver  = params.version or gameVersionString() or "*"
    local toks = params.tokens or {}
    if type(toks) ~= "table" then
        return { success = false, error = "tokens must be an object/map", error_code = "INVALID_PARAMS" }
    end
    local all = loadSigTokens(true)
    all[ver] = all[ver] or {}
    local set = {}
    for name, bytes in pairs(toks) do
        if type(name) == "string" and type(bytes) == "string" then
            all[ver][name] = bytes
            set[#set + 1] = name
        end
    end
    if not saveSigTokens(all) then
        return { success = false, error = "cannot write " .. sigTokenPath(), error_code = "PERMISSION_DENIED" }
    end
    return { success = true, version = ver, tokens_set = set, file = sigTokenPath() }
end

function cmd_get_signature_tokens(params)
    local all = loadSigTokens(true)
    local ver = gameVersionString()
    local active = {}
    if ver and all[ver] then for k in pairs(all[ver]) do active[#active + 1] = k end end
    if all["*"] then for k in pairs(all["*"]) do active[#active + 1] = k end end
    local versions = {}
    for k in pairs(all) do versions[#versions + 1] = k end
    table.sort(versions)
    table.sort(active)
    return {
        success          = true,
        game_version     = ver,
        file             = sigTokenPath(),
        versions         = versions,
        active_tokens    = active,
        raw              = all
    }
end

-- ---------- 3) bounded range scan ----------

function cmd_aob_scan_region(params)
    local prok, perr = requireProcess()
    if not prok then return perr end

    local pattern = params.pattern
    if not pattern then return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" } end

    local startA, err = parseAddress(params.start)
    if not startA then return { success = false, error = err, error_code = "INVALID_PARAMS" } end

    local stopA
    if params["end"] ~= nil then
        stopA, err = parseAddress(params["end"])
        if not stopA then return { success = false, error = err, error_code = "INVALID_PARAMS" } end
    elseif params.size then
        stopA = startA + params.size
    else
        return { success = false, error = "Provide 'end' or 'size'", error_code = "INVALID_PARAMS" }
    end
    if stopA <= startA then
        return { success = false, error = "'end' must be greater than 'start'", error_code = "INVALID_PARAMS" }
    end

    local expanded, terr = expandSigTokens(pattern)
    if not expanded then return terr end

    local protection = params.protection or "+X"
    local limit      = params.limit or 100

    -- fast path: bounded memscan, first hit only
    if params.unique then
        local found
        local scanOk, scanMsg = pcall(function()
            local ms = createMemScan()
            ms.setOnlyOneResult(true)
            ms.firstScan(soExactValue, vtByteArray, nil, expanded, nil, startA, stopA,
                         protection, fsmNotAligned, "1", true, false, false, false)
            ms.waitTillDone()
            found = ms.getOnlyResult()
            ms.destroy()
        end)
        if not scanOk then
            return { success = false, error = "region scan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
        end
        return { success = true, count = found and 1 or 0,
                 address = found and toHex(found) or nil,
                 start = toHex(startA), ["end"] = toHex(stopA), pattern = expanded }
    end

    local results
    local scanOk, scanMsg = pcall(function() results = AOBScan(expanded, protection) end)
    if not scanOk then
        return { success = false, error = "AOBScan failed: " .. tostring(scanMsg), error_code = "SCAN_ERROR" }
    end

    local addresses, total = {}, 0
    if results and results.Count > 0 then
        for i = 0, results.Count - 1 do
            local s = results.getString(i)
            local a = tonumber(s, 16)
            if a and a >= startA and a < stopA then
                total = total + 1
                if #addresses < limit then addresses[#addresses + 1] = "0x" .. s end
            end
        end
    end
    if results then pcall(function() results.destroy() end) end

    return { success = true, total = total, returned = #addresses, count = #addresses,
             start = toHex(startA), ["end"] = toHex(stopA), pattern = expanded, addresses = addresses }
end

-- ---------- 2) scan-failure diagnosis ----------

local function fixedRuns(pattern, minLen)
    -- maximal runs of concrete bytes in a CE pattern string
    local runs, cur = {}, {}
    for tok in pattern:gmatch("%S+") do
        if tok:match("^%x%x$") then
            cur[#cur + 1] = tok
        else
            if #cur >= minLen then runs[#runs + 1] = cur end
            cur = {}
        end
    end
    if #cur >= minLen then runs[#runs + 1] = cur end
    table.sort(runs, function(a, b) return #a > #b end)
    return runs
end

local function fileOffsetOf(filepath, needle)
    local f = io.open(filepath, "rb")
    if not f then return nil, "cannot open " .. tostring(filepath) end
    local chunkSize, overlap = 8 * 1024 * 1024, #needle
    local pos, prevTail = 0, ""
    while true do
        local chunk = f:read(chunkSize)
        if not chunk then break end
        local buf = prevTail .. chunk
        local baseOff = pos - #prevTail
        local at = buf:find(needle, 1, true)
        if at then f:close(); return baseOff + at - 1 end
        prevTail = buf:sub(-(overlap - 1))
        pos = pos + #chunk
    end
    f:close()
    return nil, "not found in file"
end

local function bytesToPattern(bytes)
    local out = {}
    for i = 1, #bytes do out[#out + 1] = string.format("%02X", bytes:byte(i)) end
    return table.concat(out, " ")
end

-- file offset -> virtual address of the loaded module, via the on-disk PE section table
local function fileOffsetToVA(filepath, off)
    local f = io.open(filepath, "rb")
    if not f then return nil end
    local dos = f:read(0x40)
    if not dos or #dos < 0x40 then f:close(); return nil end
    local peOff = dos:byte(0x3C) + dos:byte(0x3D) * 0x100 + dos:byte(0x3E) * 0x10000 + dos:byte(0x3F) * 0x1000000
    f:seek("set", peOff)
    local pe = f:read(0x18)
    if not pe or pe:sub(1, 4) ~= "PE\0\0" then f:close(); return nil end
    local nsec   = pe:byte(7) + pe:byte(8) * 0x100
    local optSz  = pe:byte(0x15) + pe:byte(0x16) * 0x100
    f:seek("set", peOff + 24 + optSz)
    for i = 0, nsec - 1 do
        local sh = f:read(40)
        if not sh then break end
        local function d32(o) return sh:byte(o) + sh:byte(o+1)*0x100 + sh:byte(o+2)*0x10000 + sh:byte(o+3)*0x1000000 end
        local va, rawSize, raw = d32(13), d32(17), d32(21)
        if raw and off >= raw and off < raw + rawSize then
            f:close()
            return va + (off - raw)
        end
    end
    f:close()
    return nil
end

local function likelyMods()
    local pid = getOpenedProcessID() or 0
    local modules
    pcall(function()
        modules = enumModules(pid)
        if not modules or #modules == 0 then modules = enumModules() end
    end)
    local out = {}
    for _, m in ipairs(modules or {}) do
        local p = (m.PathToFile or m.path or "")
        local n = (m.Name or m.name or "")
        if p ~= "" and not p:lower():find("\\windows\\", 1, true) then
            if (n:lower():sub(-4) == ".dll") then
                out[#out + 1] = { name = n, path = p, size = m.Size or m.size }
            end
        end
    end
    return out
end

function cmd_diagnose_scan_failure(params)
    local prok, perr = requireProcess()
    if not prok then return perr end

    local pattern = params.pattern
    if not pattern then return { success = false, error = "No pattern provided", error_code = "INVALID_PARAMS" } end
    local moduleName = params.module_name or process
    local expanded = expandSigTokens(pattern) or pattern

    -- in-memory
    local memCount, memAddrs = 0, {}
    local modBase, modSize
    pcall(function() modBase = getAddress(moduleName); modSize = getModuleSize(moduleName) end)
    local results
    pcall(function() results = AOBScan(expanded, params.protection or "+X") end)
    if results and results.Count > 0 then
        for i = 0, results.Count - 1 do
            local a = tonumber(results.getString(i), 16)
            if a and (not modBase or (a >= modBase and a < modBase + modSize)) then
                memCount = memCount + 1
                if #memAddrs < 5 then memAddrs[#memAddrs + 1] = toHex(a) end
            end
        end
    end
    if results then pcall(function() results.destroy() end) end

    -- on disk
    local exePath = mainModuleExePath()
    local runs = fixedRuns(expanded, 6)
    local disk = { checked = false, found = false, exe = exePath }
    if exePath and #runs > 0 then
        disk.checked  = true
        disk.needle   = bytesToPattern(table.concat(runs[1]))
        local off, ferr = fileOffsetOf(exePath, (table.concat(runs[1])):gsub(" ", ""):gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
        if off then
            disk.found        = true
            disk.file_offset  = off
            disk.file_offset_hex = string.format("0x%X", off)
            local rva = fileOffsetToVA(exePath, off)
            if rva and modBase then
                local va = modBase + rva
                disk.expected_va = toHex(va)
                disk.memory_at_expected_va = bytesToPattern(readString(va, math.min(16, 8 + #runs[1])) or "")
            end
        else
            disk.reason = ferr
        end
    end

    local mods = likelyMods()
    local verdict, hint
    if memCount > 0 then
        verdict = "pattern matches in memory"
        hint    = "no problem detected"
    elseif disk.found then
        verdict = "pattern EXISTS IN THE EXE ON DISK but NOT in memory -> the code was patched at runtime"
        hint    = "almost always a mod loader / DLL mod hooking that site. Check mods.txt under the game folder and the non-system modules listed below; disable the matching mod and retry. (See lesson: CT vs mod conflict.)"
    else
        verdict = "pattern not found on disk either -> the signature is wrong for this build"
        hint    = "the game build changed the bytes, or the pattern itself is wrong. Re-derive the signature (and use {tokens} for version-varying bytes)."
    end

    return {
        success          = true,
        pattern          = expanded,
        module           = moduleName,
        in_memory_count  = memCount,
        in_memory_sample = memAddrs,
        on_disk          = disk,
        non_system_modules = mods,
        verdict          = verdict,
        hint             = hint
    }
end
-- >>> END UNIT-24 <<<

local commandHandlers = {
    -- Process & Modules
    get_process_info = cmd_get_process_info,
    enum_modules = cmd_enum_modules,
    get_symbol_address = cmd_get_symbol_address,

    -- >>> BEGIN UNIT-07 Process Lifecycle <<<
    open_process = cmd_open_process,
    get_process_list = cmd_get_process_list,
    get_processid_from_name = cmd_get_processid_from_name,
    get_foreground_process = cmd_get_foreground_process,
    create_process = cmd_create_process,
    get_opened_process_id = cmd_get_opened_process_id,
    get_opened_process_handle = cmd_get_opened_process_handle,
    -- >>> END UNIT-07 <<<
    
    -- Memory Read
    read_memory = cmd_read_memory,
    read_bytes = cmd_read_memory,  -- Alias
    read_integer = cmd_read_integer,
    read_string = cmd_read_string,
    read_pointer = cmd_read_pointer,
    
    -- Pattern Scanning
    aob_scan = cmd_aob_scan,
    pattern_scan = cmd_aob_scan,  -- Alias
    scan_all = cmd_scan_all,
    next_scan = cmd_next_scan,
    write_integer = cmd_write_integer,
    write_memory = cmd_write_memory,
    write_string = cmd_write_string,
    get_scan_results = cmd_get_scan_results,
    search_string = cmd_search_string,
    
    -- Disassembly & Analysis
    disassemble = cmd_disassemble,
    get_instruction_info = cmd_get_instruction_info,
    find_function_boundaries = cmd_find_function_boundaries,
    analyze_function = cmd_analyze_function,
    
    -- Reference Finding
    find_references = cmd_find_references,
    find_call_references = cmd_find_call_references,
    
    -- Breakpoints
    set_breakpoint = cmd_set_breakpoint,
    set_execution_breakpoint = cmd_set_breakpoint,  -- Alias
    set_data_breakpoint = cmd_set_data_breakpoint,
    set_write_breakpoint = cmd_set_data_breakpoint,  -- Alias
    remove_breakpoint = cmd_remove_breakpoint,
    get_breakpoint_hits = cmd_get_breakpoint_hits,
    list_breakpoints = cmd_list_breakpoints,
    clear_all_breakpoints = cmd_clear_all_breakpoints,
    
    -- Memory Regions
    get_memory_regions = cmd_get_memory_regions,
    enum_memory_regions_full = cmd_enum_memory_regions_full,  -- More accurate, uses native API
    
    -- Lua Evaluation
    evaluate_lua = cmd_evaluate_lua,

    -- Threading & Synchronization (Unit-22)
    create_thread           = cmd_create_thread,
    get_global_variable     = cmd_get_global_variable,
    set_global_variable     = cmd_set_global_variable,
    queue_to_main_thread    = cmd_queue_to_main_thread,
    check_synchronize       = cmd_check_synchronize,
    in_main_thread          = cmd_in_main_thread,
    
    -- High-Level Analysis Tools
    dissect_structure = cmd_dissect_structure,
    get_thread_list = cmd_get_thread_list,
    auto_assemble = cmd_auto_assemble,
    read_pointer_chain = cmd_read_pointer_chain,
    get_rtti_classname = cmd_get_rtti_classname,
    get_address_info = cmd_get_address_info,
    checksum_memory = cmd_checksum_memory,
    generate_signature = cmd_generate_signature,
    
    -- DBVM Hypervisor Tools (Safe Dynamic Tracing - Ring -1)
    get_physical_address = cmd_get_physical_address,
    start_dbvm_watch = cmd_start_dbvm_watch,
    poll_dbvm_watch = cmd_poll_dbvm_watch,  -- Poll logs without stopping watch
    stop_dbvm_watch = cmd_stop_dbvm_watch,
    -- Semantic aliases for ease of use
    find_what_writes_safe = cmd_start_dbvm_watch,  -- Alias: start watching for writes
    find_what_accesses_safe = cmd_start_dbvm_watch,  -- Alias: start watching for accesses
    get_watch_results = cmd_stop_dbvm_watch,  -- Alias: retrieve results and stop
    
    -- Utility
    ping = cmd_ping,

    -- Debug Output & Multimedia (Unit 23)
    output_debug_string = cmd_output_debug_string,
    speak_text = cmd_speak_text,
    play_sound = cmd_play_sound,
    beep = cmd_beep,
    set_progress_state = cmd_set_progress_state,
    set_progress_value = cmd_set_progress_value,
    -- Unit-21: Kernel Mode / DBVM Extensions
    dbk_get_cr0 = cmd_dbk_get_cr0,
    dbk_get_cr3 = cmd_dbk_get_cr3,
    dbk_get_cr4 = cmd_dbk_get_cr4,
    read_process_memory_cr3 = cmd_read_process_memory_cr3,
    write_process_memory_cr3 = cmd_write_process_memory_cr3,
    map_memory = cmd_map_memory,
    unmap_memory = cmd_unmap_memory,
    dbk_writes_ignore_write_protection = cmd_dbk_writes_ignore_write_protection,
    get_physical_address_cr3 = cmd_get_physical_address_cr3,

    -- Shell Execution (UNIT-20b) - Security gate enforced on Python side
    run_command = cmd_run_command,
    shell_execute = cmd_shell_execute,
    file_exists = cmd_file_exists,
    delete_file = cmd_delete_file,
    get_file_list = cmd_get_file_list,
    get_directory_list = cmd_get_directory_list,
    get_temp_folder = cmd_get_temp_folder,
    get_file_version = cmd_get_file_version,
    read_clipboard = cmd_read_clipboard,
    write_clipboard = cmd_write_clipboard,

    -- >>> BEGIN UNIT-19 dispatcher entries <<<
    create_structure           = cmd_create_structure,
    get_structure_by_name      = cmd_get_structure_by_name,
    add_element_to_structure   = cmd_add_element_to_structure,
    get_structure_elements     = cmd_get_structure_elements,
    export_structure_to_xml    = cmd_export_structure_to_xml,
    delete_structure           = cmd_delete_structure,
    -- >>> END UNIT-19 <<<
    -- >>> BEGIN UNIT-18 dispatcher entries <<<
    load_table               = cmd_load_table,
    save_table               = cmd_save_table,
    get_address_list         = cmd_get_address_list,
    get_memory_record        = cmd_get_memory_record,
    create_memory_record     = cmd_create_memory_record,
    delete_memory_record     = cmd_delete_memory_record,
    get_memory_record_value  = cmd_get_memory_record_value,
    set_memory_record_value  = cmd_set_memory_record_value,
    -- >>> END UNIT-18 <<<
    -- Input Automation (Unit-17) — system-wide, no process guard required
    get_pixel = cmd_get_pixel,
    get_mouse_pos = cmd_get_mouse_pos,
    set_mouse_pos = cmd_set_mouse_pos,
    is_key_pressed = cmd_is_key_pressed,
    key_down = cmd_key_down,
    key_up = cmd_key_up,
    do_key_press = cmd_do_key_press,
    get_screen_info = cmd_get_screen_info,

    -- Window / GUI (Unit-16)
    find_window             = cmd_find_window,
    get_window_caption      = cmd_get_window_caption,
    get_window_class_name   = cmd_get_window_class_name,
    get_window_process_id   = cmd_get_window_process_id,
    send_window_message     = cmd_send_window_message,
    show_message            = cmd_show_message,
    input_query             = cmd_input_query,
    show_selection_list     = cmd_show_selection_list,
    -- Unit 15: Advanced Scanning
    aob_scan_unique           = cmd_aob_scan_unique,
    aob_scan_module           = cmd_aob_scan_module,
    aob_scan_module_unique    = cmd_aob_scan_module_unique,
    pointer_rescan            = cmd_pointer_rescan,
    create_persistent_scan    = cmd_create_persistent_scan,
    persistent_scan_first_scan    = cmd_persistent_scan_first_scan,
    persistent_scan_next_scan     = cmd_persistent_scan_next_scan,
    persistent_scan_get_results   = cmd_persistent_scan_get_results,
    persistent_scan_destroy       = cmd_persistent_scan_destroy,
    -- Memory Operations (Unit 14)
    copy_memory = cmd_copy_memory,
    compare_memory = cmd_compare_memory,
    write_region_to_file = cmd_write_region_to_file,
    read_region_from_file = cmd_read_region_from_file,
    md5_memory = cmd_md5_memory,
    md5_file = cmd_md5_file,
    create_section = cmd_create_section,
    map_view_of_section = cmd_map_view_of_section,
    -- Assembly & Compilation (Unit 13)
    assemble_instruction = cmd_assemble_instruction,
    auto_assemble_check = cmd_auto_assemble_check,
    compile_c_code = cmd_compile_c_code,
    compile_cs_code = cmd_compile_cs_code,
    generate_api_hook_script = cmd_generate_api_hook_script,
    generate_code_injection_script = cmd_generate_code_injection_script,
    -- >>> BEGIN UNIT-12 dispatcher entries <<<
    register_symbol                = cmd_register_symbol,
    unregister_symbol              = cmd_unregister_symbol,
    enum_registered_symbols        = cmd_enum_registered_symbols,
    delete_all_registered_symbols  = cmd_delete_all_registered_symbols,
    enable_windows_symbols         = cmd_enable_windows_symbols,
    enable_kernel_symbols          = cmd_enable_kernel_symbols,
    get_symbol_info                = cmd_get_symbol_info,
    get_module_size                = cmd_get_module_size,
    load_new_symbols               = cmd_load_new_symbols,
    reinitialize_symbol_handler    = cmd_reinitialize_symbol_handler,
    -- >>> END UNIT-12 <<<
    -- Unit-11: Debug Context + Per-Thread Breakpoints
    debug_get_context                  = cmd_debug_get_context,
    debug_set_context                  = cmd_debug_set_context,
    debug_get_xmm_pointer              = cmd_debug_get_xmm_pointer,
    debug_set_last_branch_recording    = cmd_debug_set_last_branch_recording,
    debug_get_last_branch_record       = cmd_debug_get_last_branch_record,
    debug_set_breakpoint_for_thread    = cmd_debug_set_breakpoint_for_thread,
    debug_remove_breakpoint_for_thread = cmd_debug_remove_breakpoint_for_thread,
    -- Debugger Control (Unit 10)
    debug_process                      = cmd_debug_process,
    debug_is_debugging                 = cmd_debug_is_debugging,
    debug_get_current_debugger_interface = cmd_debug_get_current_debugger_interface,
    debug_break_thread                 = cmd_debug_break_thread,
    debug_continue                     = cmd_debug_continue,
    debug_detach                       = cmd_debug_detach,
    pause_process                      = cmd_pause_process,
    unpause_process                    = cmd_unpause_process,
    -- Code Injection & Execution (Unit-09)
    inject_dll            = cmd_inject_dll,
    inject_dotnet_dll     = cmd_inject_dotnet_dll,
    execute_code          = cmd_execute_code,
    execute_code_ex       = cmd_execute_code_ex,
    execute_method        = cmd_execute_method,
    execute_code_local    = cmd_execute_code_local,
    execute_code_local_ex = cmd_execute_code_local_ex,
    -- >>> BEGIN UNIT-08 dispatcher entries <<<
    allocate_memory        = cmd_allocate_memory,
    free_memory            = cmd_free_memory,
    allocate_shared_memory = cmd_allocate_shared_memory,
    get_memory_protection  = cmd_get_memory_protection,
    set_memory_protection  = cmd_set_memory_protection,
    full_access            = cmd_full_access,
    allocate_kernel_memory = cmd_allocate_kernel_memory,
    -- >>> END UNIT-08 <<<
    -- >>> BEGIN UNIT-24 dispatcher entries <<<
    aob_scan_region          = cmd_aob_scan_region,
    diagnose_scan_failure    = cmd_diagnose_scan_failure,
    set_signature_tokens     = cmd_set_signature_tokens,
    get_signature_tokens     = cmd_get_signature_tokens,
    -- >>> END UNIT-24 <<<

}

-- ============================================================================
-- >>> BEGIN UNIT-25 Batch Execution, Introspection & Error Normalisation <<<
-- ============================================================================
-- Three things that make the bridge friendlier to an automating agent:
--   1. one round trip can carry N sub-commands (cmd_batch)
--   2. the bridge can describe itself (cmd_status / cmd_list_methods)
--   3. every failure carries a machine-readable error_code, inferred from the
--      message when a legacy handler did not set one itself.
-- Defined AFTER the dispatcher table so they can close over it directly
-- (the handler functions themselves must stay globals; see AGENTS.md).
-- ============================================================================

local BATCH_MAX_CALLS = 64

-- Ordered rules: the first substring hit wins, so put specific causes before
-- generic ones ("no process" before "failed", "dbk" before "driver").
local ERROR_CODE_RULES = {
    { "NO_PROCESS",       "no process" },
    { "PARSE_ERROR",      "parse error" },
    { "METHOD_NOT_FOUND", "method not found" },
    { "UNKNOWN_SIG_TOKEN","signature token" },
    { "DBVM_NOT_LOADED",  "dbvm not running" },
    { "DBK_NOT_LOADED",   "dbk" },
    { "DBK_NOT_LOADED",   "kernel driver" },
    { "INVALID_ADDRESS",  "invalid address" },
    { "INVALID_ADDRESS",  "invalid base address" },
    { "INVALID_ADDRESS",  "invalid cr3" },
    { "INVALID_ADDRESS",  "could not resolve" },
    { "NOT_FOUND",        "not found" },
    { "NOT_FOUND",        "no active watch" },
    { "NOT_FOUND",        "no scan results" },
    { "NOT_FOUND",        "no previous scan" },
    { "OUT_OF_RESOURCES", "no free hardware breakpoint slots" },
    { "OUT_OF_RESOURCES", "too many calls" },
    { "INVALID_PARAMS",   "unknown type" },
    { "INVALID_PARAMS",   "invalid filename" },
    { "INVALID_PARAMS",   "no pattern provided" },
    { "INVALID_PARAMS",   "no code provided" },
    { "INVALID_PARAMS",   "no string provided" },
    { "INVALID_PARAMS",   "no bytes provided" },
    { "INVALID_PARAMS",   "no symbol" },
    { "INVALID_PARAMS",   "must be" },
    { "INVALID_PARAMS",   "required" },
    { "INVALID_PARAMS",   "provide " },
    { "INTERNAL_ERROR",   "failed" },
    { "INTERNAL_ERROR",   "error" },
}

local function inferErrorCode(message)
    local m = tostring(message or ""):lower()
    for _, rule in ipairs(ERROR_CODE_RULES) do
        if m:find(rule[2], 1, true) then return rule[1] end
    end
    return "INTERNAL_ERROR"
end

-- Ensure every unsuccessful result carries an error_code, and record it for
-- bridge_status. Results that already declare a code are left untouched.
local function finalizeResult(result)
    if type(result) ~= "table" then return result end
    if result.success == false then
        if result.error_code == nil then
            result.error_code = inferErrorCode(result.error)
        end
        serverState.stats.errors = serverState.stats.errors + 1
        serverState.lastError = result.error
        serverState.lastErrorCode = result.error_code
    end
    return result
end

-- json.encode() can throw on circular tables or exotic CE values; never let
-- that take down the response path.
local function safeEncode(payload)
    local ok, text = pcall(json.encode, payload)
    if ok then return text end
    local id = type(payload) == "table" and payload.id or nil
    return json.encode({
        jsonrpc = "2.0", id = id,
        result = { success = false, error_code = "INTERNAL_ERROR",
                   error = "response encoding failed: " .. tostring(text) }
    })
end

function cmd_batch(params)
    local calls = params.calls
    if type(calls) ~= "table" then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "calls must be a JSON array of {method, params} objects" }
    end
    if #calls == 0 and next(calls) ~= nil then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "calls must be an array, not an object" }
    end
    if #calls > BATCH_MAX_CALLS then
        return { success = false, error_code = "INVALID_PARAMS",
                 error = "too many calls (" .. #calls .. "), max " .. BATCH_MAX_CALLS }
    end

    local stopOnError = params.stop_on_error ~= false
    local results, okCount, failCount = {}, 0, 0

    for i, call in ipairs(calls) do
        local method, sub
        if type(call) == "table" then
            method = call.method
            sub    = type(call.params) == "table" and call.params or {}
        end

        local entry
        local handler = method and commandHandlers[method] or nil
        if not handler then
            entry = { success = false, error_code = "METHOD_NOT_FOUND",
                      error = "Method not found: " .. tostring(method) }
        elseif method == "batch" then
            entry = { success = false, error_code = "INVALID_PARAMS",
                      error = "nested batch is not allowed" }
        else
            local ok2, r = pcall(handler, sub)
            if not ok2 then
                local err = { success = false, error_code = "INTERNAL_ERROR",
                              error = "Internal error: " .. tostring(r) }
                serverState.stats.errors = serverState.stats.errors + 1
                serverState.lastError = err.error
                serverState.lastErrorCode = err.error_code
                entry = err
            elseif type(r) == "table" then
                entry = finalizeResult(r)
            else
                entry = { success = true, value = r }
            end
            if isMutatingMethod(method) then
                auditLogEntry(method, sub, entry.success == true, entry.error_code)
            end
        end

        entry.index  = i
        entry.method = method
        results[i] = entry

        if entry.success == false then failCount = failCount + 1 else okCount = okCount + 1 end
        serverState.stats.subcommands = serverState.stats.subcommands + 1
        if entry.success == false and stopOnError then break end
    end

    serverState.stats.batches = serverState.stats.batches + 1

    local out = {
        success    = failCount == 0,
        requested  = #calls,
        executed   = #results,
        succeeded  = okCount,
        failed     = failCount,
        stopped_early = #results < #calls,
        results    = results,
    }
    if failCount > 0 then
        out.error      = failCount .. " of " .. #results .. " sub-command(s) failed"
        out.error_code = "PARTIAL_FAILURE"
        serverState.stats.errors = serverState.stats.errors + 1
        serverState.lastError = out.error
        serverState.lastErrorCode = out.error_code
    end
    return out
end

function cmd_status(params)
    local methodCount = 0
    for _ in pairs(commandHandlers) do methodCount = methodCount + 1 end

    local function countOf(t) local n = 0; for _ in pairs(t or {}) do n = n + 1 end; return n end

    local native = nil
    if type(mcp_tcp_status) == "function" then
        local ok, st = pcall(mcp_tcp_status)
        if ok and type(st) == "table" then native = st end
    end

    local pid = getOpenedProcessID() or 0
    local arch = "none"
    if pid > 0 then
        local ok, is64 = pcall(targetIs64Bit)
        if ok then arch = is64 and "x64" or "x86" end
    end

    return {
        success          = true,
        version          = VERSION,
        transport        = "native_tcp",
        port             = serverState.tcpPort,
        native           = native,
        process_id       = pid,
        process_attached = pid > 0,
        target_arch      = arch,
        uptime_seconds   = serverState.startedAt and (os.time() - serverState.startedAt) or 0,
        method_count     = methodCount,
        resources = {
            breakpoints      = countOf(serverState.breakpoints),
            dbvm_watches     = countOf(serverState.active_watches),
            persistent_scans = countOf(serverState.persistent_scans),
            has_scan_results = serverState.scan_foundlist ~= nil,
        },
        stats        = serverState.stats,
        last_method  = serverState.lastMethod,
        last_error   = serverState.lastError,
        last_error_code = serverState.lastErrorCode,
    }
end

function cmd_list_methods(params)
    local names = {}
    for name in pairs(commandHandlers) do names[#names + 1] = name end
    table.sort(names)
    if params.prefix then
        local prefix = tostring(params.prefix)
        local filtered = {}
        for _, n in ipairs(names) do
            if n:sub(1, #prefix) == prefix then filtered[#filtered + 1] = n end
        end
        names = filtered
    end
    local limit, offset, page, total = paginate(params, names, 500)
    return { success = true, total = total, offset = offset, limit = limit, returned = #page, methods = page }
end

-- >>> BEGIN UNIT-31 CE API Gap Coverage (v15.5.0) <<<
-- ============================================================================
-- COMMAND HANDLERS - CE API GAP COVERAGE
-- Thin adapters over documented CE Lua APIs that the v15.4.x surface lacked
-- (audited against the official celua.txt): speedhack, disassembly context,
-- structure auto-guess, hotkeys, custom value types, the code-dissection
-- database, .NET runtime inspection, embedded table files, AA command
-- extensions, HTTP, and the DBK/DBVM kernel interfaces.
--
-- Design rules for this unit:
--   * Zero new dependencies - every handler wraps a documented CE global or
--     class method; CE itself is the library.
--   * Callback-style APIs (custom type converters, hotkey actions, AA
--     commands) receive Lua source strings that are compiled with load().
--     They run inside CE's sandbox exactly like evaluate_lua payloads and are
--     audited via the register_/create_/set_ mutating prefixes.
--   * Every CE global is existence-checked (CE_API_UNAVAILABLE) and called
--     under pcall (CE_API_ERROR) so headless tests and older CE builds
--     degrade cleanly instead of throwing.
-- ============================================================================

gapHotkeys        = {}   -- id -> GenericHotkey object (keeps them alive)
gapHotkeySeq      = 0
gapCustomTypes    = {}   -- name -> byte count (for read_custom/write_custom)

-- Shared guards for this unit -------------------------------------------------
local function gapApi(name)
    local v = rawget(_G, name)
    if type(v) ~= "function" then
        return nil, { success = false, error = name .. " is not available in this CE build",
                      error_code = "CE_API_UNAVAILABLE" }
    end
    return v
end

local function gapCall(name, ...)
    local fn, err = gapApi(name)
    if not fn then return err end
    local ok, res = pcall(fn, ...)
    if not ok then
        return { success = false, error = name .. " failed: " .. tostring(res),
                 error_code = "CE_API_ERROR" }
    end
    return res
end

-- Resolve "address" param (number or hex string) -> number, else error table.
local function gapAddr(params, key)
    local a = params[key or "address"]
    if type(a) == "number" then return a end
    if type(a) == "string" then
        local n = getAddressSafe(a)
        if n then return n end
    end
    return nil, { success = false, error = "Invalid or missing '" .. (key or "address") .. "'",
                  error_code = "INVALID_ADDRESS" }
end

-- ---- Speedhack (speedhack_setSpeed / speedhack_getSpeed) --------------------

function cmd_set_speed(params)
    local speed = tonumber(params.speed)
    if not speed or speed <= 0 then
        return { success = false, error = "speed must be a positive number", error_code = "INVALID_PARAMS" }
    end
    local res = gapCall("speedhack_setSpeed", speed)
    if type(res) == "table" then return res end
    return { success = true, speed = speed }
end

function cmd_get_speed()
    local res = gapCall("speedhack_getSpeed")
    if type(res) == "table" then return res end
    return { success = true, speed = tonumber(res) }
end

-- ---- Disassembly context -----------------------------------------------------

function cmd_get_previous_opcode(params)
    local addr, err = gapAddr(params)
    if not addr then return err end
    local res = gapCall("getPreviousOpcode", addr)
    if type(res) == "table" then return res end
    return { success = true, address = toHex(addr), previous = res and toHex(res) or nil }
end

function cmd_get_last_disassemble_data()
    local res = gapCall("getLastDisassembleData")
    if type(res) == "table" and res.error_code then return res end
    if res == nil then return { success = true, data = nil } end
    return { success = true, data = res }
end

-- ---- Structure auto-guess (structure.autoGuess) -------------------------------

function cmd_auto_guess_structure(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end
    local base, err = gapAddr(params, "base_address")
    if not base then return err end
    local offset = tonumber(params.offset) or 0
    local size   = tonumber(params.size) or 0

    local fn = gapApi("getStructureByName")
    if not fn then return { success = false, error = "getStructureByName unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okS, st = pcall(fn, name)
    if not okS then st = nil end
    if not st then
        local mk = gapApi("createStructure")
        if not mk then return { success = false, error = "createStructure unavailable", error_code = "CE_API_UNAVAILABLE" } end
        local okC, created = pcall(mk, name, true)
        if not okC or not created then
            return { success = false, error = "cannot create structure '" .. name .. "'", error_code = "CE_API_ERROR" }
        end
        st = created
    end

    local okG, gerr = pcall(function() st.autoGuess(st, base, offset, size) end)
    if not okG then
        return { success = false, error = "autoGuess failed: " .. tostring(gerr), error_code = "CE_API_ERROR" }
    end
    local count = 0
    pcall(function() count = tonumber(st.Count) or 0 end)
    return { success = true, name = name, base_address = toHex(base), elements = count }
end

-- ---- Hotkeys (createHotkey / GenericHotkey) -----------------------------------

function cmd_create_hotkey(params)
    local keys = params.keys
    if type(keys) ~= "table" or #keys == 0 then
        return { success = false, error = "keys must be a non-empty array (max 5)", error_code = "INVALID_PARAMS" }
    end
    if #keys > 5 then
        return { success = false, error = "CE hotkeys accept at most 5 keys", error_code = "INVALID_PARAMS" }
    end
    if type(params.action_lua) ~= "string" or params.action_lua == "" then
        return { success = false, error = "action_lua (Lua source) is required", error_code = "INVALID_PARAMS" }
    end
    local mk = gapApi("createHotkey")
    if not mk then return { success = false, error = "createHotkey unavailable", error_code = "CE_API_UNAVAILABLE" } end

    local chunk, cerr = load(params.action_lua, "hotkey_action", "t")
    if not chunk then
        return { success = false, error = "action_lua compile error: " .. tostring(cerr), error_code = "INVALID_PARAMS" }
    end

    local okH, hk = pcall(mk, chunk, keys)
    if not okH or not hk then
        return { success = false, error = "createHotkey failed: " .. tostring(hk), error_code = "CE_API_ERROR" }
    end
    if params.delay and tonumber(params.delay) then
        pcall(function() hk.DelayBetweenActivate = tonumber(params.delay) end)
    end

    gapHotkeySeq = gapHotkeySeq + 1
    local id = "hk_" .. gapHotkeySeq
    gapHotkeys[id] = hk
    return { success = true, id = id, keys = keys, delay = tonumber(params.delay) }
end

function cmd_list_hotkeys(params)
    params = params or {}
    local items = {}
    for id in pairs(gapHotkeys) do
        items[#items + 1] = { id = id }
    end
    local limit, offset, _, total = paginate(params, items, 100)
    local out = {}
    for i = offset + 1, math.min(offset + limit, #items) do out[#out + 1] = items[i] end
    return { success = true, total = total, offset = offset, limit = limit,
             returned = #out, hotkeys = out }
end

function cmd_remove_hotkey(params)
    local id = params.id
    local hk = id and gapHotkeys[id] or nil
    if not hk then
        return { success = false, error = "unknown hotkey id", error_code = "NOT_FOUND" }
    end
    pcall(function() hk.destroy() end)
    gapHotkeys[id] = nil
    return { success = true, id = id }
end

-- ---- Custom value types (registerCustomTypeLua / registerCustomTypeAA) --------

function cmd_register_custom_type(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end
    local byteCount = tonumber(params.byte_count)
    if not byteCount or byteCount < 1 or byteCount > 8 then
        return { success = false, error = "byte_count must be 1..8", error_code = "INVALID_PARAMS" }
    end
    if type(params.bytes_to_value_lua) ~= "string" or type(params.value_to_bytes_lua) ~= "string" then
        return { success = false, error = "bytes_to_value_lua and value_to_bytes_lua are required",
                 error_code = "INVALID_PARAMS" }
    end
    local mk = gapApi("registerCustomTypeLua")
    if not mk then return { success = false, error = "registerCustomTypeLua unavailable", error_code = "CE_API_UNAVAILABLE" } end

    local fB2V, e1 = load(params.bytes_to_value_lua, "b2v", "t")
    local fV2B, e2 = load(params.value_to_bytes_lua, "v2b", "t")
    if not fB2V then return { success = false, error = "bytes_to_value_lua compile error: " .. tostring(e1), error_code = "INVALID_PARAMS" } end
    if not fV2B then return { success = false, error = "value_to_bytes_lua compile error: " .. tostring(e2), error_code = "INVALID_PARAMS" } end

    local okR, ct = pcall(mk, name, byteCount, fB2V, fV2B, params.is_float == true)
    if not okR or not ct then
        return { success = false, error = "registerCustomTypeLua failed: " .. tostring(ct), error_code = "CE_API_ERROR" }
    end
    gapCustomTypes[name] = byteCount
    return { success = true, name = name, byte_count = byteCount, is_float = params.is_float == true }
end

function cmd_register_custom_type_aa(params)
    local name = params.name
    local script = params.script
    if type(name) ~= "string" or type(script) ~= "string" or script == "" then
        return { success = false, error = "name and script are required", error_code = "INVALID_PARAMS" }
    end
    local mk = gapApi("registerCustomTypeAutoAssembler")
    if not mk then return { success = false, error = "registerCustomTypeAutoAssembler unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okR, ct = pcall(mk, script)
    if not okR or not ct then
        return { success = false, error = "registerCustomTypeAutoAssembler failed: " .. tostring(ct), error_code = "CE_API_ERROR" }
    end
    return { success = true, name = name, note = "byte_count unknown for AA types; pass byte_count to read_custom/write_custom" }
end

function cmd_get_custom_type(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end
    local get = gapApi("getCustomType")
    if not get then return { success = false, error = "getCustomType unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okG, ct = pcall(get, name)
    if not okG or not ct then
        return { success = false, error = "custom type not found", error_code = "NOT_FOUND" }
    end
    return { success = true, name = name, registered_byte_count = gapCustomTypes[name],
             uses_float = (pcall(function() return ct.scriptUsesFloat end) and ct.scriptUsesFloat) or false }
end

local function gapCustomByteCount(params, name)
    if tonumber(params.byte_count) then return tonumber(params.byte_count) end
    return gapCustomTypes[name]
end

function cmd_read_custom(params)
    local name = params.type_name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "type_name is required", error_code = "INVALID_PARAMS" }
    end
    local addr, err = gapAddr(params)
    if not addr then return err end
    local get = gapApi("getCustomType")
    if not get then return { success = false, error = "getCustomType unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okG, ct = pcall(get, name)
    if not okG or not ct then
        return { success = false, error = "custom type not found", error_code = "NOT_FOUND" }
    end
    local n = gapCustomByteCount(params, name)
    if not n then
        return { success = false, error = "byte_count required (not tracked for this type)", error_code = "INVALID_PARAMS" }
    end
    local rb = gapApi("readBytes")
    if not rb then return { success = false, error = "readBytes unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okR, bytes = pcall(rb, addr, n, true)
    if not okR or type(bytes) ~= "table" then
        return { success = false, error = "read failed: " .. tostring(bytes), error_code = "CE_API_ERROR" }
    end
    local okV, value = pcall(function() return ct:byteTableToValue(bytes, addr) end)
    if not okV then
        return { success = false, error = "byteTableToValue failed: " .. tostring(value), error_code = "CE_API_ERROR" }
    end
    return { success = true, address = toHex(addr), type_name = name, value = value }
end

function cmd_write_custom(params)
    local name = params.type_name
    if type(name) ~= "string" or name == "" or params.value == nil then
        return { success = false, error = "type_name and value are required", error_code = "INVALID_PARAMS" }
    end
    local addr, err = gapAddr(params)
    if not addr then return err end
    local get = gapApi("getCustomType")
    if not get then return { success = false, error = "getCustomType unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okG, ct = pcall(get, name)
    if not okG or not ct then
        return { success = false, error = "custom type not found", error_code = "NOT_FOUND" }
    end
    local okB, bytes = pcall(function() return ct:valueToByteTable(params.value, addr) end)
    if not okB or type(bytes) ~= "table" then
        return { success = false, error = "valueToByteTable failed: " .. tostring(bytes), error_code = "CE_API_ERROR" }
    end
    local wb = gapApi("writeBytes")
    if not wb then return { success = false, error = "writeBytes unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okW, werr = pcall(wb, addr, bytes)
    if not okW then
        return { success = false, error = "write failed: " .. tostring(werr), error_code = "CE_API_ERROR" }
    end
    return { success = true, address = toHex(addr), type_name = name, wrote = #bytes }
end

-- ---- Code dissection database (getDissectCode) ---------------------------------

local function gapDissect()
    local get = gapApi("getDissectCode")
    if not get then return nil, { success = false, error = "getDissectCode unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okD, dc = pcall(get)
    if not okD or not dc then
        return nil, { success = false, error = "getDissectCode failed: " .. tostring(dc), error_code = "CE_API_ERROR" }
    end
    return dc
end

function cmd_dissect_code_start(params)
    local dc, err = gapDissect()
    if not dc then return err end
    local okR, res
    if type(params.module) == "string" and params.module ~= "" then
        okR, res = pcall(function() return dc.dissect(dc, params.module) end)
    elseif params.base ~= nil then
        local base, aerr = gapAddr(params, "base")
        if not base then return aerr end
        local size = tonumber(params.size) or 0
        okR, res = pcall(function() return dc.dissect(dc, base, size) end)
    else
        return { success = false, error = "provide 'module' or 'base'+'size'", error_code = "INVALID_PARAMS" }
    end
    if not okR then
        return { success = false, error = "dissect failed: " .. tostring(res), error_code = "CE_API_ERROR" }
    end
    return { success = true, scope = params.module or (toHex(params.base) .. "+" .. tostring(params.size)) }
end

function cmd_dissect_code_references(params)
    local dc, err = gapDissect()
    if not dc then return err end
    local addr, aerr = gapAddr(params)
    if not addr then return aerr end
    local okR, refs = pcall(function() return dc.getReferences(dc, addr) end)
    if not okR then
        return { success = false, error = "getReferences failed: " .. tostring(refs), error_code = "CE_API_ERROR" }
    end
    local items = {}
    if type(refs) == "table" then
        for from, typ in pairs(refs) do
            items[#items + 1] = { from = (type(from) == "number") and toHex(from) or from,
                                  type = (type(typ) == "number") and tostring(typ) or typ }
        end
    end
    local limit, offset, page, total = paginate(params, items, 50)
    local out = {}
    for i = offset + 1, math.min(offset + limit, #items) do out[#out + 1] = items[i] end
    return { success = true, address = toHex(addr), total = total, offset = offset,
             limit = limit, returned = #out, references = out }
end

function cmd_dissect_code_strings(params)
    local dc, err = gapDissect()
    if not dc then return err end
    local okR, strs = pcall(function() return dc.getReferencedStrings(dc) end)
    if not okR then
        return { success = false, error = "getReferencedStrings failed: " .. tostring(strs), error_code = "CE_API_ERROR" }
    end
    local items = {}
    if type(strs) == "table" then
        for addr, s in pairs(strs) do
            items[#items + 1] = { address = (type(addr) == "number") and toHex(addr) or addr, string = tostring(s) }
        end
    end
    local limit, offset, _, total = paginate(params, items, 100)
    local out = {}
    for i = offset + 1, math.min(offset + limit, #items) do out[#out + 1] = items[i] end
    return { success = true, total = #items, offset = offset, limit = limit,
             returned = #out, strings = out }
end

function cmd_dissect_code_functions(params)
    local dc, err = gapDissect()
    if not dc then return err end
    local okR, fns = pcall(function() return dc.getReferencedFunctions(dc) end)
    if not okR then
        return { success = false, error = "getReferencedFunctions failed: " .. tostring(fns), error_code = "CE_API_ERROR" }
    end
    local items = {}
    if type(fns) == "table" then
        for addr in pairs(fns) do
            items[#items + 1] = { address = (type(addr) == "number") and toHex(addr) or addr }
        end
    end
    local limit, offset, _, total = paginate(params, items, 100)
    local out = {}
    for i = offset + 1, math.min(offset + limit, #items) do out[#out + 1] = items[i] end
    return { success = true, total = #items, offset = offset, limit = limit,
             returned = #out, functions = out }
end

function cmd_dissect_code_manage(params)
    local dc, err = gapDissect()
    if not dc then return err end
    local action = params.action
    if action == "save" then
        if type(params.filename) ~= "string" or params.filename == "" then
            return { success = false, error = "filename is required for save", error_code = "INVALID_PARAMS" }
        end
        local okS, serr = pcall(function() return dc.saveToFile(dc, params.filename) end)
        if not okS then return { success = false, error = "saveToFile failed: " .. tostring(serr), error_code = "CE_API_ERROR" } end
        return { success = true, action = "save", filename = params.filename }
    elseif action == "load" then
        if type(params.filename) ~= "string" or params.filename == "" then
            return { success = false, error = "filename is required for load", error_code = "INVALID_PARAMS" }
        end
        local okL, lerr = pcall(function() return dc.loadFromFile(dc, params.filename) end)
        if not okL then return { success = false, error = "loadFromFile failed: " .. tostring(lerr), error_code = "CE_API_ERROR" } end
        return { success = true, action = "load", filename = params.filename }
    elseif action == "clear" then
        pcall(function() return dc.clear(dc) end)
        return { success = true, action = "clear" }
    end
    return { success = false, error = "action must be save|load|clear", error_code = "INVALID_PARAMS" }
end

-- ---- .NET runtime inspection (DotNetDataCollector) ------------------------------

local function gapDotnet()
    local get = gapApi("getDotNetDataCollector")
    if not get then
        return nil, { success = false, error = "getDotNetDataCollector unavailable", error_code = "CE_API_UNAVAILABLE" }
    end
    local okD, dc = pcall(get)
    if not okD or not dc then
        return nil, { success = false, error = "getDotNetDataCollector failed: " .. tostring(dc), error_code = "CE_API_ERROR" }
    end
    return dc
end

function cmd_dotnet_status()
    local dc, err = gapDotnet()
    if not dc then return err end
    local attached = false
    pcall(function() attached = dc.Attached == true end)
    return { success = true, attached = attached }
end

local function gapDotnetCall(method, ...)
    local dc, err = gapDotnet()
    if not dc then return err end
    local args = table.pack(...)
    local okR, res = pcall(function()
        return dc[method](dc, table.unpack(args, 1, args.n))
    end)
    if not okR then
        return { success = false, error = method .. " failed: " .. tostring(res), error_code = "CE_API_ERROR" }
    end
    return res
end

function cmd_dotnet_enum_domains()
    local res = gapDotnetCall("enumDomains")
    if type(res) == "table" and res.success == false then return res end
    return { success = true, domains = res or {} }
end

function cmd_dotnet_enum_modules(params)
    local dh = tonumber(params.domain_handle)
    if not dh then return { success = false, error = "domain_handle is required", error_code = "INVALID_PARAMS" } end
    local res = gapDotnetCall("enumModuleList", dh)
    if type(res) == "table" and res.success == false then return res end
    return { success = true, modules = res or {} }
end

function cmd_dotnet_enum_types(params)
    local mh = tonumber(params.module_handle)
    if not mh then return { success = false, error = "module_handle is required", error_code = "INVALID_PARAMS" } end
    local res = gapDotnetCall("enumTypeDefs", mh)
    if type(res) == "table" and res.success == false then return res end
    return { success = true, typedefs = res or {} }
end

function cmd_dotnet_type_details(params)
    local dh = tonumber(params.domain_handle)
    local tk = tonumber(params.typedef_token)
    if not dh or not tk then
        return { success = false, error = "domain_handle and typedef_token are required", error_code = "INVALID_PARAMS" }
    end
    local data = gapDotnetCall("getTypeDefData", dh, tk)
    if type(data) == "table" and data.success == false then return data end
    local methods = gapDotnetCall("getTypeDefMethods", dh, tk)
    if type(methods) == "table" and methods.success == false then methods = nil end
    local parent = gapDotnetCall("getTypeDefParent", dh, tk)
    if type(parent) == "table" and parent.success == false then parent = nil end
    return { success = true, fields = data or {}, methods = methods or {}, parent = parent }
end

function cmd_dotnet_method_params(params)
    local dh = tonumber(params.domain_handle)
    local mt = tonumber(params.method_token)
    if not dh or not mt then
        return { success = false, error = "domain_handle and method_token are required", error_code = "INVALID_PARAMS" }
    end
    local res = gapDotnetCall("getMethodParameters", dh, mt)
    if type(res) == "table" and res.success == false then return res end
    return { success = true, parameters = res or {} }
end

function cmd_dotnet_address_info(params)
    local addr, err = gapAddr(params)
    if not addr then return err end
    local res = gapDotnetCall("getAddressData", addr)
    if type(res) == "table" and res.success == false then return res end
    return { success = true, address = toHex(addr), data = res }
end

function cmd_dotnet_enum_objects(params)
    local res
    if params.type_name ~= nil then
        res = gapDotnetCall("enumAllObjectsOfType", params.type_name)
    else
        res = gapDotnetCall("enumAllObjects")
    end
    if type(res) == "table" and res.success == false then return res end
    return { success = true, objects = res or {} }
end

-- ---- Embedded table files (TableFile) --------------------------------------------

function cmd_table_file_create(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end
    local mk = gapApi("createTableFile")
    if not mk then return { success = false, error = "createTableFile unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okC, tf = pcall(mk, name, params.source_path)
    if not okC or not tf then
        return { success = false, error = "createTableFile failed: " .. tostring(tf), error_code = "CE_API_ERROR" }
    end
    return { success = true, name = name, from = params.source_path }
end

function cmd_table_file_find(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" } end
    local find = gapApi("findTableFile")
    if not find then return { success = false, error = "findTableFile unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okF, tf = pcall(find, name)
    if not okF or not tf then
        return { success = false, error = "table file not found", error_code = "NOT_FOUND" }
    end
    return { success = true, name = name }
end

function cmd_table_file_export(params)
    local name, dest = params.name, params.dest_path
    if type(name) ~= "string" or type(dest) ~= "string" or dest == "" then
        return { success = false, error = "name and dest_path are required", error_code = "INVALID_PARAMS" }
    end
    local find = gapApi("findTableFile")
    if not find then return { success = false, error = "findTableFile unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okF, tf = pcall(find, name)
    if not okF or not tf then
        return { success = false, error = "table file not found", error_code = "NOT_FOUND" }
    end
    local okS, serr = pcall(function() return tf.saveToFile(tf, dest) end)
    if not okS then
        return { success = false, error = "saveToFile failed: " .. tostring(serr), error_code = "CE_API_ERROR" }
    end
    return { success = true, name = name, dest = dest }
end

function cmd_table_file_delete(params)
    local name = params.name
    if type(name) ~= "string" or name == "" then
        return { success = false, error = "name is required", error_code = "INVALID_PARAMS" }
    end
    local find = gapApi("findTableFile")
    if not find then return { success = false, error = "findTableFile unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okF, tf = pcall(find, name)
    if not okF or not tf then
        return { success = false, error = "table file not found", error_code = "NOT_FOUND" }
    end
    local okD, derr = pcall(function() return tf.delete(tf) end)
    if not okD then
        return { success = false, error = "delete failed: " .. tostring(derr), error_code = "CE_API_ERROR" }
    end
    return { success = true, name = name }
end

-- ---- Auto Assembler command extensions --------------------------------------------

function cmd_register_aa_command(params)
    local command = params.command
    if type(command) ~= "string" or command == "" then
        return { success = false, error = "command is required", error_code = "INVALID_PARAMS" }
    end
    if type(params.lua_code) ~= "string" or params.lua_code == "" then
        return { success = false, error = "lua_code is required", error_code = "INVALID_PARAMS" }
    end
    local reg = gapApi("registerAutoAssemblerCommand")
    if not reg then return { success = false, error = "registerAutoAssemblerCommand unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local chunk, cerr = load(params.lua_code, "aa_cmd", "t")
    if not chunk then
        return { success = false, error = "lua_code compile error: " .. tostring(cerr), error_code = "INVALID_PARAMS" }
    end
    local okR, rerr = pcall(reg, command, chunk)
    if not okR then
        return { success = false, error = "registerAutoAssemblerCommand failed: " .. tostring(rerr), error_code = "CE_API_ERROR" }
    end
    return { success = true, command = command }
end

function cmd_unregister_aa_command(params)
    local command = params.command
    if type(command) ~= "string" or command == "" then
        return { success = false, error = "command is required", error_code = "INVALID_PARAMS" }
    end
    local res = gapCall("unregisterAutoAssemblerCommand", command)
    if type(res) == "table" then return res end
    return { success = true, command = command }
end

-- ---- HTTP (Internet class) ----------------------------------------------------------

function cmd_http_get(params)
    local url = params.url
    if type(url) ~= "string" or url == "" then
        return { success = false, error = "url is required", error_code = "INVALID_PARAMS" }
    end
    local gi = gapApi("getInternet")
    if not gi then return { success = false, error = "getInternet unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okI, net = pcall(gi, "cheatengine-mcp")
    if not okI or not net then
        return { success = false, error = "getInternet failed: " .. tostring(net), error_code = "CE_API_ERROR" }
    end
    if type(params.header) == "string" then
        pcall(function() net.Header = params.header end)
    end
    local okG, body = pcall(function() return net.getURL(net, url) end)
    if not okG then
        return { success = false, error = "getURL failed: " .. tostring(body), error_code = "CE_API_ERROR" }
    end
    if body == nil then
        return { success = false, error = "request failed (nil body)", error_code = "CE_API_ERROR" }
    end
    body = tostring(body)
    local maxLen = tonumber(params.max_len) or 65536
    local truncated = #body > maxLen
    return { success = true, url = url, length = #body, truncated = truncated,
             body = body:sub(1, maxLen) }
end

function cmd_http_post(params)
    local url, data = params.url, params.data
    if type(url) ~= "string" or type(data) ~= "string" then
        return { success = false, error = "url and data are required", error_code = "INVALID_PARAMS" }
    end
    local gi = gapApi("getInternet")
    if not gi then return { success = false, error = "getInternet unavailable", error_code = "CE_API_UNAVAILABLE" } end
    local okI, net = pcall(gi, "cheatengine-mcp")
    if not okI or not net then
        return { success = false, error = "getInternet failed: " .. tostring(net), error_code = "CE_API_ERROR" }
    end
    local okP, res = pcall(function() return net.postURL(net, url, data) end)
    if not okP then
        return { success = false, error = "postURL failed: " .. tostring(res), error_code = "CE_API_ERROR" }
    end
    return { success = true, url = url, response = res and tostring(res) or nil }
end

-- ---- DBK kernel interface (safe subset) ----------------------------------------------

function cmd_dbk_initialize()
    local res = gapCall("dbk_initialize")
    if type(res) == "table" then return res end
    return { success = res == true, loaded = res == true,
             note = res ~= true and "driver not loaded (check test-signing / service)" or nil }
end

function cmd_dbk_use_kernelmode(params)
    local mode = params.mode
    local map = {
        openprocess   = "dbk_useKernelmodeOpenProcess",
        memoryaccess  = "dbk_useKernelmodeProcessMemoryAccess",
        queryregions  = "dbk_useKernelmodeQueryMemoryRegions",
    }
    local fname = type(mode) == "string" and map[mode] or nil
    if not fname then
        return { success = false, error = "mode must be openprocess|memoryaccess|queryregions", error_code = "INVALID_PARAMS" }
    end
    local res = gapCall(fname)
    if type(res) == "table" then return res end
    return { success = true, mode = mode }
end

-- MSR handlers come in read/write pairs that differ only in the CE function
-- and whether a value is passed; build them from one factory each way.
local function makeMsrRead(gapFn)
    return function(params)
        local msr = tonumber(params.msr)
        if not msr then return { success = false, error = "msr index is required", error_code = "INVALID_PARAMS" } end
        local res = gapCall(gapFn, msr)
        if type(res) == "table" then return res end
        return { success = true, msr = msr, value = res }
    end
end

local function makeMsrWrite(gapFn)
    return function(params)
        local msr = tonumber(params.msr)
        local value = params.value
        if not msr or value == nil then
            return { success = false, error = "msr and value are required", error_code = "INVALID_PARAMS" }
        end
        local res = gapCall(gapFn, msr, value)
        if type(res) == "table" then return res end
        return { success = true, msr = msr }
    end
end

cmd_dbk_read_msr  = makeMsrRead("dbk_readMSR")
cmd_dbk_write_msr = makeMsrWrite("dbk_writeMSR")

-- ---- DBVM hypervisor interface (safe subset) -------------------------------------------
-- traceonbp_* and bp_* families are intentionally NOT wrapped: they require
-- blocking event waits that are incompatible with the 1ms single-thread poll
-- loop. dbvm_watch (already exposed) covers the polling pattern.

function cmd_dbvm_initialize(params)
    local res = gapCall("dbvm_initialize", params.offloados == true, params.reason)
    if type(res) == "table" then return res end
    return { success = true }
end

cmd_dbvm_read_msr  = makeMsrRead("dbvm_readMSR")
cmd_dbvm_write_msr = makeMsrWrite("dbvm_writeMSR")

-- ---- UNIT-33 (v15.7.0): CT runtime memory / pointer health diagnostics -----

-- One readability probe: returns true when at least one byte is readable.
-- Kept trivial so the per-record/per-step cost stays one CE main-thread call.
local function addrReadable(addr)
    if not addr then return false end
    local ok, b = pcall(readBytes, addr, 1, true)
    return ok and b ~= nil
end

-- Validate a pointer chain step by step and report exactly where it breaks.
-- Unlike read_pointer_chain (which answers "what is the final address"), this
-- answers "is the chain alive, and if not, which hop died" — each step carries
-- readability of the pointer source and of the dereferenced target.
function cmd_validate_pointer_chain(params)
    local base = params.base
    if type(base) == "string" then base = getAddressSafe(base) end
    if not base then
        return { success = false, error = "Invalid base address", error_code = "INVALID_ADDRESS" }
    end

    local offsets = params.offsets or {}
    if type(offsets) ~= "table" then
        return { success = false, error = "offsets must be an array", error_code = "INVALID_PARAMS" }
    end
    -- One dereference + two readability probes per offset; unclamped = freeze.
    if #offsets > 32 then
        return { success = false, error = "too many offsets (" .. #offsets .. "), max 32",
                 error_code = "INVALID_PARAMS" }
    end

    local steps = {}
    local currentAddr = base
    local baseReadable = addrReadable(currentAddr)
    if not baseReadable then
        return { success = true, valid = false, failed_step = 0,
                 error = "base address is not readable",
                 base = toHex(base), steps = steps }
    end

    for i, off in ipairs(offsets) do
        local offN = tonumber(off)
        if offN == nil then
            return { success = false, error = "offset " .. i .. " is not a number",
                     error_code = "INVALID_PARAMS" }
        end
        local okPtr, ptr = pcall(readPointer, currentAddr)
        if not okPtr or not ptr then
            return { success = true, valid = false, failed_step = i,
                     error = "pointer read failed at step " .. i,
                     base = toHex(base), steps = steps,
                     failed_at_address = toHex(currentAddr) }
        end
        local nextAddr = ptr + offN
        local nextReadable = addrReadable(nextAddr)
        steps[#steps + 1] = {
            step = i,
            address = toHex(currentAddr),
            offset = offN,
            hex_offset = string.format("%+d", offN),
            pointer_value = toHex(ptr),
            next_address = toHex(nextAddr),
            next_readable = nextReadable,
        }
        if not nextReadable then
            return { success = true, valid = false, failed_step = i,
                     error = "dereferenced address at step " .. i .. " is not readable",
                     base = toHex(base), steps = steps,
                     failed_at_address = toHex(nextAddr) }
        end
        currentAddr = nextAddr
    end

    return { success = true, valid = true, base = toHex(base),
             final_address = toHex(currentAddr),
             final_readable = addrReadable(currentAddr),
             steps = steps }
end

-- Health check for every memory record in the loaded CT: is its address still
-- resolvable, and is the target memory still readable? Answers "which entries
-- of my cheat table died" without clicking through the GUI. Per-record status:
--   ok          address resolved and target readable
--   unresolved  address expression (symbol/pointer path) no longer evaluates
--   unreadable  address resolved but target memory is not readable
--   script      AA-script record, no address to check (has_script=true)
--   group       group header, nothing to check
function cmd_ct_memory_records_health(params)
    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local okC, total = pcall(function() return al.Count end)
    if not okC or type(total) ~= "number" then total = 0 end

    -- getAddressSafe + readBytes per record, both on the CE main thread.
    local MAX_RECORDS = 5000
    local budget = math.max(1, math.min(tonumber(params.limit) or 1000, MAX_RECORDS))
    local records, truncated = {}, false
    local counts = { ok = 0, unresolved = 0, unreadable = 0, script = 0, group = 0, skipped = 0 }

    for i = 0, total - 1 do
        if #records >= budget then truncated = true break end
        local okR, rec = pcall(function() return al[i] end)
        if okR and rec then
            local prop = function(name)
                local ok, v = pcall(function() return rec[name] end)
                return ok and v or nil
            end
            local id = prop("ID")
            local desc = prop("Description") or ""
            local isGroup = prop("IsGroupHeader") == true
            local hasScript = false
            local script = prop("Script")
            if type(script) == "string" and script ~= "" then hasScript = true end

            local entry = { id = id, description = desc, address = prop("Address") or "" }
            if isGroup then
                counts.group = counts.group + 1
                entry.status = "group"
            elseif hasScript then
                counts.script = counts.script + 1
                entry.status = "script"
                entry.has_script = true
            else
                local addr = getAddressSafe(entry.address)
                if not addr then
                    counts.unresolved = counts.unresolved + 1
                    entry.status = "unresolved"
                elseif not addrReadable(addr) then
                    counts.unreadable = counts.unreadable + 1
                    entry.status = "unreadable"
                    entry.resolved_address = toHex(addr)
                else
                    counts.ok = counts.ok + 1
                    entry.status = "ok"
                    entry.resolved_address = toHex(addr)
                end
            end
            records[#records + 1] = entry
        else
            counts.skipped = counts.skipped + 1
        end
    end

    return {
        success = true,
        total = total,
        checked = #records,
        truncated = truncated,
        summary = counts,
        records = records,
    }
end

-- ---- UNIT-33 end -----------------------------------------------------------

-- ---- UNIT-34: session health tools (borrowed from big-CT self-check chains) -
-- Curated additions: every command here is strictly read-only, so it is safe
-- before any write/inject workflow. Deliberately NOT ported: auto-resetting
-- toggles (already covered by set_memory_record_active + read-back) and
-- heuristic AOB signature quality scoring (unstable, deferred).

-- One-shot session preflight: process, main module, game version, loaded
-- table, and optional symbol resolution in a single round trip. Mirrors the
-- big CT's [ENABLE] self-check chain (process -> module -> version -> table)
-- as a read-only probe. Works without an attached process: it reports the
-- failed checks honestly instead of erroring out.
function cmd_preflight(params)
    params = params or {}
    local checks = {}

    -- 1) process
    local pid = getOpenedProcessID() or 0
    local arch = "none"
    if pid > 0 then
        local okA, is64 = pcall(targetIs64Bit)
        arch = okA and (is64 and "x64" or "x86") or "unknown"
    end
    checks[#checks + 1] = { name = "process", ok = pid > 0,
        detail = pid > 0 and ("pid " .. pid .. " (" .. arch .. ")") or "no process attached" }

    -- 2) main module
    local modInfo = nil
    if pid > 0 then
        local modules
        pcall(function()
            modules = enumModules(pid)
            if not modules or #modules == 0 then modules = enumModules() end
        end)
        if modules then
            local base = getAddressSafe(process)
            local pick = nil
            for _, m in ipairs(modules) do
                local addr = m.Address or m.address
                if addr and (base == nil or addr == base) then pick = m break end
            end
            if pick then
                modInfo = {
                    name = pick.Name or pick.name or "???",
                    base = toHex(pick.Address or pick.address or 0),
                    size = pick.Size or pick.size or 0,
                    is_64bit = pick.Is64Bit or false,
                    path = pick.PathToFile or pick.path or "",
                }
            end
        end
    end
    checks[#checks + 1] = { name = "main_module", ok = modInfo ~= nil,
        detail = modInfo and (modInfo.name .. " @ " .. modInfo.base) or "main module not found" }

    -- 3) game version (advisory: nil when the exe carries no version resource)
    local ver = nil
    if pid > 0 then ver = gameVersionString() end
    checks[#checks + 1] = { name = "game_version", ok = ver ~= nil,
        detail = ver or "no version resource on main module" }

    -- 4) loaded table (advisory)
    local tablePath, recordCount = nil, 0
    local okP, tpath = pcall(getTableFile)
    if okP and type(tpath) == "string" and tpath ~= "" then tablePath = tpath end
    local al = unit18_get_al()
    if al then
        local okC, count = pcall(function() return al.Count end)
        if okC and type(count) == "number" then recordCount = count end
    end
    checks[#checks + 1] = { name = "table", ok = tablePath ~= nil,
        detail = tablePath and (tablePath .. " (" .. recordCount .. " records)")
                            or "no table loaded" }

    -- 5) optional core-symbol resolution (advisory, up to 32)
    local symbols = params.symbols
    local symbolResults = nil
    if symbols ~= nil then
        if type(symbols) ~= "table" or #symbols == 0 then
            return { success = false, error = "symbols must be a non-empty array",
                     error_code = "INVALID_PARAMS" }
        end
        if #symbols > 32 then
            return { success = false,
                     error = "too many symbols (" .. #symbols .. "), max 32",
                     error_code = "INVALID_PARAMS" }
        end
        symbolResults = {}
        local resolvedCount = 0
        for i, sym in ipairs(symbols) do
            if type(sym) ~= "string" or sym == "" then
                return { success = false, error = "symbol " .. i .. " is not a non-empty string",
                         error_code = "INVALID_PARAMS" }
            end
            local addr = getAddressSafe(sym)
            if addr then resolvedCount = resolvedCount + 1 end
            symbolResults[#symbolResults + 1] = { symbol = sym, resolved = addr ~= nil,
                                                  address = addr and toHex(addr) or nil }
        end
        checks[#checks + 1] = { name = "symbols", ok = resolvedCount == #symbols,
            detail = resolvedCount .. "/" .. #symbols .. " resolved" }
    end

    return {
        success = true,
        ok = pid > 0 and modInfo ~= nil,
        bridge_version = VERSION,
        process_id = pid,
        target_arch = arch,
        main_module = modInfo,
        game_version = ver,
        table_path = tablePath,
        memory_records = recordCount,
        symbols = symbolResults,
        checks = checks,
    }
end

-- Batch AOB health scan: verify a list of anchor patterns against a module's
-- address range in one call. This ports the big CT's aobList idea (all anchors
-- registered in one place, verified together at startup) into the bridge.
-- Per-pattern status: "hit" (found, address returned), "miss" (no match in
-- module range), "error" (bad pattern or scan failure).
function cmd_aob_health_scan(params)
    params = params or {}
    local patterns = params.patterns
    if type(patterns) ~= "table" or #patterns == 0 then
        return { success = false, error = "patterns must be a non-empty array",
                 error_code = "INVALID_PARAMS" }
    end
    -- Hard cap: each pattern costs one native memscan on the CE main thread.
    if #patterns > 256 then
        return { success = false,
                 error = "too many patterns (" .. #patterns .. "), max 256",
                 error_code = "INVALID_PARAMS" }
    end

    local prok, perr = requireProcess()
    if not prok then return perr end

    -- Scan scope: named module, else the main module.
    local modBase, modSize, modName
    local moduleName = params.module
    if moduleName ~= nil and moduleName ~= "" then
        if type(moduleName) ~= "string" then
            return { success = false, error = "module must be a string",
                     error_code = "INVALID_PARAMS" }
        end
        local b = getAddressSafe(moduleName)
        if not b then
            return { success = false, error = "cannot resolve module: " .. moduleName,
                     error_code = "INVALID_ADDRESS" }
        end
        modBase, modName = b, moduleName
        local okS, sz = pcall(getModuleSize, moduleName)
        modSize = okS and sz or nil
    else
        local modules
        pcall(function()
            modules = enumModules(getOpenedProcessID())
            if not modules or #modules == 0 then modules = enumModules() end
        end)
        if not modules then
            return { success = false, error = "module enumeration failed",
                     error_code = "SCAN_ERROR" }
        end
        local base = getAddressSafe(process)
        for _, m in ipairs(modules) do
            local addr = m.Address or m.address
            if addr and (base == nil or addr == base) then
                modBase = addr
                modName = m.Name or m.name
                modSize = m.Size or m.size
                break
            end
        end
    end
    if not modBase or not modSize or modSize <= 0 then
        return { success = false, error = "module size unavailable; pass 'module' explicitly",
                 error_code = "SCAN_ERROR" }
    end

    local protection = params.protection or "+X"
    local results = {}
    local hits, misses, errors = 0, 0, 0

    for i, p in ipairs(patterns) do
        if type(p) ~= "string" or p == "" then
            results[#results + 1] = { index = i, status = "error",
                                      error = "pattern must be a non-empty string" }
            errors = errors + 1
        else
            local expanded, terr = expandSigTokens(p)
            if not expanded then
                results[#results + 1] = { index = i, pattern = p, status = "error",
                                          error = (terr and terr.error) or "token expansion failed" }
                errors = errors + 1
            else
                local found
                local scanOk, scanMsg = pcall(function()
                    local ms = createMemScan()
                    ms.setOnlyOneResult(true)
                    ms.firstScan(soExactValue, vtByteArray, nil, expanded, nil,
                                 modBase, modBase + modSize, protection,
                                 fsmNotAligned, "1", true, false, false, false)
                    ms.waitTillDone()
                    found = ms.getOnlyResult()
                    ms.destroy()
                end)
                if not scanOk then
                    results[#results + 1] = { index = i, pattern = expanded,
                                              status = "error", error = tostring(scanMsg) }
                    errors = errors + 1
                elseif found then
                    hits = hits + 1
                    results[#results + 1] = { index = i, pattern = expanded,
                                              status = "hit", address = toHex(found) }
                else
                    misses = misses + 1
                    results[#results + 1] = { index = i, pattern = expanded, status = "miss" }
                end
            end
        end
    end

    return {
        success = true,
        module = modName,
        module_base = toHex(modBase),
        module_size = modSize,
        protection = protection,
        total = #patterns,
        hits = hits,
        misses = misses,
        errors = errors,
        hit_ratio = math.floor((hits / #patterns) * 100 + 0.5) / 100,
        results = results,
    }
end

-- Byte fingerprint gate: compare the bytes currently at an address against the
-- expected hex bytes BEFORE any write/inject. A mismatch means the game
-- version changed or the anchor hit the wrong spot (an AOB can hit a wrong
-- location with identical instruction bytes elsewhere); refusing to patch
-- then is the last line of defence against corrupting the target.
-- Strictly read-only. Wildcards are not accepted: a fingerprint must be exact.
function cmd_inject_preview(params)
    params = params or {}

    local addr, err = parseAddress(params.address)
    if not addr then
        return { success = false, error = err or "Invalid address", error_code = "INVALID_ADDRESS" }
    end

    local expected = params.expected
    if type(expected) ~= "string" or expected == "" then
        return { success = false, error = "expected hex byte string required",
                 error_code = "INVALID_PARAMS" }
    end
    local hexStr = expected:gsub("%s+", "")
    if #hexStr == 0 or #hexStr % 2 ~= 0 then
        return { success = false, error = "expected must be hex bytes with even length",
                 error_code = "INVALID_PARAMS" }
    end
    if not hexStr:match("^%x+$") then
        return { success = false,
                 error = "expected contains non-hex characters (wildcards not supported)",
                 error_code = "INVALID_PARAMS" }
    end
    local len = #hexStr // 2
    if len > 256 then
        return { success = false,
                 error = "expected exceeds the 256-byte inject_preview limit",
                 error_code = "INVALID_PARAMS" }
    end

    local pid = getOpenedProcessID()
    if not pid or pid == 0 then
        return { success = false, error = "No process attached", error_code = "NO_PROCESS" }
    end

    local okR, actual = pcall(readBytes, addr, len, true)
    if not okR or type(actual) ~= "table" then
        return { success = true, readable = false, match = false,
                 error = "target memory is not readable",
                 address = toHex(addr), length = len }
    end

    local expectedHex, actualHex = {}, {}
    local match, firstDiff = true, -1
    for i = 1, len do
        local e = tonumber(hexStr:sub((i - 1) * 2 + 1, i * 2), 16)
        local a = actual[i] or 0
        expectedHex[#expectedHex + 1] = string.format("%02X", e)
        actualHex[#actualHex + 1] = string.format("%02X", a)
        if e ~= a then
            if firstDiff == -1 then firstDiff = i - 1 end
            match = false
        end
    end

    return {
        success = true,
        readable = true,
        match = match,
        first_diff_offset = firstDiff,
        address = toHex(addr),
        length = len,
        expected = table.concat(expectedHex, " "),
        actual = table.concat(actualHex, " "),
    }
end

-- ---- UNIT-34 end -----------------------------------------------------------

function cmd_dbvm_cloak_activate(params)
    local phys = tonumber(params.physical_base)
    if not phys then return { success = false, error = "physical_base is required", error_code = "INVALID_PARAMS" } end
    local res
    if params.virtual_base ~= nil then
        res = gapCall("dbvm_cloak_activate", phys, tonumber(params.virtual_base))
    else
        res = gapCall("dbvm_cloak_activate", phys)
    end
    if type(res) == "table" then return res end
    return { success = true, physical_base = toHex(phys) }
end

function cmd_dbvm_cloak_deactivate(params)
    local phys = tonumber(params.physical_base)
    if not phys then return { success = false, error = "physical_base is required", error_code = "INVALID_PARAMS" } end
    local res = gapCall("dbvm_cloak_deactivate", phys)
    if type(res) == "table" then return res end
    return { success = true, physical_base = toHex(phys) }
end

function cmd_dbvm_cloak_read(params)
    local phys = tonumber(params.physical_base)
    if not phys then return { success = false, error = "physical_base is required", error_code = "INVALID_PARAMS" } end
    local res = gapCall("dbvm_cloak_readOriginal", phys)
    if type(res) == "table" and res.success == false then return res end
    if type(res) ~= "table" or #res == 0 then
        -- CE returns a 4096-entry bytetable; nil/false/empty = failure
        return { success = false, error = "cloak read failed", error_code = "CE_API_ERROR" }
    end
    local n, preview = #res, {}
    for i = 1, math.min(n, 64) do preview[i] = res[i] end
    return { success = true, physical_base = toHex(phys), size = n,
             preview_first = math.min(n, 64), preview = preview }
end

function cmd_dbvm_cloak_write(params)
    local phys = tonumber(params.physical_base)
    local bytes = params.bytes
    if not phys then return { success = false, error = "physical_base is required", error_code = "INVALID_PARAMS" } end
    if type(bytes) ~= "table" or #bytes == 0 or #bytes > 4096 then
        return { success = false, error = "bytes must be an array of 1..4096 byte values", error_code = "INVALID_PARAMS" }
    end
    local res = gapCall("dbvm_cloak_writeOriginal", phys, bytes)
    if type(res) == "table" then return res end
    return { success = true, physical_base = toHex(phys), wrote = #bytes }
end

-- UNIT-31 registrations (dotted, after the UNIT-25 alias block)
commandHandlers.set_speed                    = cmd_set_speed
commandHandlers.get_speed                    = cmd_get_speed
commandHandlers.get_previous_opcode          = cmd_get_previous_opcode
commandHandlers.get_last_disassemble_data    = cmd_get_last_disassemble_data
commandHandlers.auto_guess_structure         = cmd_auto_guess_structure
commandHandlers.create_hotkey                = cmd_create_hotkey
commandHandlers.list_hotkeys                 = cmd_list_hotkeys
commandHandlers.remove_hotkey                = cmd_remove_hotkey
commandHandlers.register_custom_type         = cmd_register_custom_type
commandHandlers.register_custom_type_aa      = cmd_register_custom_type_aa
commandHandlers.get_custom_type              = cmd_get_custom_type
commandHandlers.read_custom                  = cmd_read_custom
commandHandlers.write_custom                 = cmd_write_custom
commandHandlers.dissect_code_start           = cmd_dissect_code_start
commandHandlers.dissect_code_references      = cmd_dissect_code_references
commandHandlers.dissect_code_strings         = cmd_dissect_code_strings
commandHandlers.dissect_code_functions       = cmd_dissect_code_functions
commandHandlers.dissect_code_manage          = cmd_dissect_code_manage
commandHandlers.dotnet_status                = cmd_dotnet_status
commandHandlers.dotnet_enum_domains          = cmd_dotnet_enum_domains
commandHandlers.dotnet_enum_modules          = cmd_dotnet_enum_modules
commandHandlers.dotnet_enum_types            = cmd_dotnet_enum_types
commandHandlers.dotnet_type_details          = cmd_dotnet_type_details
commandHandlers.dotnet_method_params         = cmd_dotnet_method_params
commandHandlers.dotnet_address_info          = cmd_dotnet_address_info
commandHandlers.dotnet_enum_objects          = cmd_dotnet_enum_objects
commandHandlers.table_file_create            = cmd_table_file_create
commandHandlers.table_file_find              = cmd_table_file_find
commandHandlers.table_file_export            = cmd_table_file_export
commandHandlers.table_file_delete            = cmd_table_file_delete
commandHandlers.validate_pointer_chain       = cmd_validate_pointer_chain
commandHandlers.ct_memory_records_health     = cmd_ct_memory_records_health
commandHandlers.preflight                    = cmd_preflight
commandHandlers.aob_health_scan              = cmd_aob_health_scan
commandHandlers.inject_preview               = cmd_inject_preview
commandHandlers.register_aa_command          = cmd_register_aa_command
commandHandlers.unregister_aa_command        = cmd_unregister_aa_command
commandHandlers.http_get                     = cmd_http_get
commandHandlers.http_post                    = cmd_http_post
commandHandlers.dbk_initialize               = cmd_dbk_initialize
commandHandlers.dbk_use_kernelmode           = cmd_dbk_use_kernelmode
commandHandlers.dbk_read_msr                 = cmd_dbk_read_msr
commandHandlers.dbk_write_msr                = cmd_dbk_write_msr
commandHandlers.dbvm_initialize              = cmd_dbvm_initialize
commandHandlers.dbvm_read_msr                = cmd_dbvm_read_msr
commandHandlers.dbvm_write_msr               = cmd_dbvm_write_msr
commandHandlers.dbvm_cloak_activate          = cmd_dbvm_cloak_activate
commandHandlers.dbvm_cloak_deactivate        = cmd_dbvm_cloak_deactivate
commandHandlers.dbvm_cloak_read              = cmd_dbvm_cloak_read
commandHandlers.dbvm_cloak_write             = cmd_dbvm_cloak_write

-- >>> END UNIT-31 <<<

commandHandlers.batch        = cmd_batch
commandHandlers.status       = cmd_status
commandHandlers.bridge_status = cmd_status            -- alias
commandHandlers.list_methods = cmd_list_methods
commandHandlers.list_bridge_methods = cmd_list_methods -- alias
commandHandlers.get_audit_log = cmd_get_audit_log
commandHandlers.list_apis     = cmd_list_apis
commandHandlers.table_state   = cmd_table_state
commandHandlers.patch_memory_record_script = cmd_patch_memory_record_script
commandHandlers.undo_memory_record_script_patch = cmd_undo_memory_record_script_patch

-- >>> END UNIT-25 <<<

-- >>> BEGIN UNIT-26 Memory Record Manipulation <<<
-- ============================================================================
-- COMMAND HANDLERS - MEMORY RECORD (CHEAT TABLE ENTRY) MANIPULATION
-- Write-side operations on addresslist entries: the UNIT-18 surface was
-- read-mostly (value get/set, create, delete) with no way to freeze a record
-- (`mr.Active = true`), retarget its address, change its type, edit its AA
-- script, or walk the child tree. These handlers close that gap.
-- No process guard: table operations are legal without an attached process.
-- ============================================================================

-- Shared guard: resolve a record by id and run a setter closure, returning
-- the updated record on success or an error-response-table on failure.
local function unit26_set_prop(params, propName, apply)
    if params.id == nil then
        return nil, { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    local al, aerr = unit18_get_al()
    if not al then return nil, aerr end

    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return nil, rerr end

    local ok, cerr = pcall(apply, rec)
    if not ok then
        return nil, { success = false,
                      error = "Failed to set " .. propName .. ": " .. tostring(cerr),
                      error_code = "INTERNAL_ERROR" }
    end
    return rec, nil
end

-- Returns an error-response-table when the offsets array is malformed, else nil.
local function unit26_validate_offsets(offsets)
    if type(offsets) ~= "table" or #offsets == 0 then
        return { success = false, error = "offsets (non-empty array) required",
                 error_code = "INVALID_PARAMS" }
    end
    if #offsets > 32 then
        return { success = false, error = "Too many offsets (max 32)", error_code = "INVALID_PARAMS" }
    end
    for i, off in ipairs(offsets) do
        if type(off) ~= "number" and (type(off) ~= "string" or off == "") then
            return { success = false,
                     error = "offsets[" .. (i - 1) .. "] must be a number or interpretable string",
                     error_code = "INVALID_PARAMS" }
        end
    end
    return nil
end

-- Apply offsets to a record. Numeric entries go through setOffset; string
-- entries are interpretable text ("+10", "[base]+4") and land in OffsetText,
-- with a numeric fallback when the text parses as a plain number.
local function unit26_apply_offsets(rec, offsets)
    rec:setOffsetCount(#offsets)
    for i, off in ipairs(offsets) do
        if type(off) == "string" then
            pcall(function() rec.OffsetText[i - 1] = off end)
            off = tonumber(off) or off
        end
        if type(off) == "number" then
            rec:setOffset(i - 1, off)
        end
    end
end

function cmd_set_memory_record_active(params)
    local active = params.active
    if type(active) ~= "boolean" then
        return { success = false, error = "active (boolean) required", error_code = "INVALID_PARAMS" }
    end

    local rec, err = unit26_set_prop(params, "Active", function(r) r.Active = active end)
    if err then return err end

    -- Read back: activation of an AA script can fail silently (CE leaves
    -- Active=false when the script errors), so report the real state.
    local applied
    pcall(function() applied = (rec.Active == true) end)

    local resp = { success = true, requested = active, applied = applied,
                   record = unit18_rec_to_table(rec) }
    if applied ~= active then
        resp.warning = "Active state did not stick - check OnActivate handlers or the record's script for errors"
    end
    return resp
end

function cmd_set_memory_record_address(params)
    local address = params.address
    if type(address) ~= "string" or address == "" then
        return { success = false, error = "address (string) required", error_code = "INVALID_PARAMS" }
    end
    -- Validate offsets BEFORE touching the record: a rejected request must
    -- never leave a half-applied state.
    if params.offsets ~= nil then
        local verr = unit26_validate_offsets(params.offsets)
        if verr then return verr end
    end

    local rec, err = unit26_set_prop(params, "Address", function(r) r.Address = address end)
    if err then return err end

    if params.offsets ~= nil then
        local ok, cerr = pcall(unit26_apply_offsets, rec, params.offsets)
        if not ok then
            return { success = false, error = "Address set, but offsets failed: " .. tostring(cerr),
                     error_code = "INTERNAL_ERROR", record = unit18_rec_to_table(rec) }
        end
    end

    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_set_memory_record_type(params)
    local typeStr = string.lower(tostring(params.type or ""))
    local vtName = UNIT18_TYPE_MAP[typeStr]
    if not vtName then
        return { success = false, error = "Unknown type: " .. typeStr, error_code = "INVALID_PARAMS" }
    end

    local rec, err = unit26_set_prop(params, "Type", function(r)
        if not pcall(function() r.VarType = vtName end) then
            r.VarType = _G[vtName]
        end
    end)
    if err then return err end

    -- Type-specific sub-configuration (only valid after the type switch).
    local warnings = {}
    if vtName == "vtString" then
        if type(params.size) == "number" then
            if not pcall(function() rec.String.Size = math.floor(params.size) end) then
                table.insert(warnings, "String.Size not applied")
            end
        end
        if type(params.unicode) == "boolean" then
            if not pcall(function() rec.String.Unicode = params.unicode end) then
                table.insert(warnings, "String.Unicode not applied")
            end
        end
    elseif vtName == "vtByteArray" then
        if type(params.size) == "number" then
            if not pcall(function() rec.Aob.Size = math.floor(params.size) end) then
                table.insert(warnings, "Aob.Size not applied")
            end
        end
    elseif vtName == "vtBinary" then
        if type(params.startbit) == "number" then
            if not pcall(function() rec.Binary.Startbit = math.floor(params.startbit) end) then
                table.insert(warnings, "Binary.Startbit not applied")
            end
        end
        if type(params.bit_size) == "number" then
            if not pcall(function() rec.Binary.Size = math.floor(params.bit_size) end) then
                table.insert(warnings, "Binary.Size not applied")
            end
        end
    end

    local resp = { success = true, record = unit18_rec_to_table(rec) }
    if #warnings > 0 then resp.warnings = warnings end
    return resp
end

function cmd_set_memory_record_description(params)
    local description = params.description
    if type(description) ~= "string" or description == "" then
        return { success = false, error = "description (string) required", error_code = "INVALID_PARAMS" }
    end

    local rec, err = unit26_set_prop(params, "Description", function(r) r.Description = description end)
    if err then return err end
    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_set_memory_record_script(params)
    local script = params.script
    if type(script) ~= "string" or script == "" then
        return { success = false, error = "script (string) required", error_code = "INVALID_PARAMS" }
    end

    local rec, err = unit26_set_prop(params, "Script", function(r) r.Script = script end)
    if err then return err end
    return { success = true,
             note = "Script text stored; set_memory_record_active(id, true) to enable/execute it",
             record = unit18_rec_to_table(rec) }
end

function cmd_set_memory_record_offsets(params)
    local verr = unit26_validate_offsets(params.offsets)
    if verr then return verr end
    local offsets = params.offsets

    local rec, err = unit26_set_prop(params, "Offsets", function(r)
        unit26_apply_offsets(r, offsets)
    end)
    if err then return err end
    return { success = true, record = unit18_rec_to_table(rec) }
end

function cmd_get_memory_record_current_address(params)
    if params.id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return rerr end

    local ok, addr = pcall(function() return rec:getCurrentAddress() end)
    if not ok or type(addr) ~= "number" then
        return { success = false, error = "Cannot resolve current address: " .. tostring(addr),
                 error_code = "NOT_FOUND" }
    end
    return { success = true, address = toHex(addr), address_integer = addr }
end

function cmd_get_memory_record_children(params)
    if params.id == nil then
        return { success = false, error = "id required", error_code = "INVALID_PARAMS" }
    end
    local recursive = params.recursive == true
    local maxDepth = math.max(1, math.min(params.max_depth or 8, 16))

    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return rerr end

    -- Depth cap via maxDepth; node budget below stops a wide tree (thousands
    -- of siblings per level) from ballooning into millions of serialized
    -- records before pagination runs. Walking stops at the budget and
    -- reports truncated=true.
    local MAX_CHILD_NODES = 5000
    local children = {}
    local truncated = false
    local function walk(r, depth, out)
        if #out >= MAX_CHILD_NODES then truncated = true return end
        local count = 0
        pcall(function() count = r.Count or 0 end)
        if type(count) ~= "number" then count = 0 end
        for i = 0, count - 1 do
            if #out >= MAX_CHILD_NODES then truncated = true return end
            local okChild, child = pcall(function() return r.Child[i] end)
            if okChild and child then
                table.insert(out, unit18_rec_to_table(child))
                if recursive and depth + 1 < maxDepth then
                    walk(child, depth + 1, out)
                end
            end
        end
    end

    walk(rec, 0, children)

    local limit, offset = clampPaging(params, 100, 1000)
    local page = {}
    for i = offset + 1, math.min(offset + limit, #children) do
        table.insert(page, children[i])
    end

    return { success = true, total = #children, offset = offset, limit = limit,
             returned = #page, truncated = truncated, children = page }
end

function cmd_append_memory_record(params)
    if params.id == nil or params.parent_id == nil then
        return { success = false, error = "id and parent_id required", error_code = "INVALID_PARAMS" }
    end
    local al, aerr = unit18_get_al()
    if not al then return aerr end

    local rec, rerr = unit18_get_rec_by_id(al, params.id)
    if not rec then return rerr end

    local parent, perr = unit18_get_rec_by_id(al, params.parent_id)
    if not parent then return perr end

    local ok, cerr = pcall(function() rec:appendToEntry(parent) end)
    if not ok then
        return { success = false, error = "appendToEntry failed: " .. tostring(cerr),
                 error_code = "INTERNAL_ERROR" }
    end
    return { success = true, record = unit18_rec_to_table(rec) }
end

commandHandlers.set_memory_record_active          = cmd_set_memory_record_active
commandHandlers.set_memory_record_address         = cmd_set_memory_record_address
commandHandlers.set_memory_record_type            = cmd_set_memory_record_type
commandHandlers.set_memory_record_description     = cmd_set_memory_record_description
commandHandlers.set_memory_record_script          = cmd_set_memory_record_script
commandHandlers.set_memory_record_offsets         = cmd_set_memory_record_offsets
commandHandlers.get_memory_record_children        = cmd_get_memory_record_children
commandHandlers.get_memory_record_current_address = cmd_get_memory_record_current_address
commandHandlers.append_memory_record              = cmd_append_memory_record

-- >>> END UNIT-26 <<<

-- ============================================================================
-- MAIN COMMAND PROCESSOR
-- ============================================================================


local function executeCommand(jsonRequest)
    local ok, request = pcall(json.decode, jsonRequest)
    if not ok or type(request) ~= "table" then
        return safeEncode({ jsonrpc = "2.0", id = nil,
            error = { code = -32700, message = "Parse error",
                      data = { error_code = "PARSE_ERROR", detail = tostring(request) } } })
    end
    
    local method = request.method
    local params = request.params
    if type(params) ~= "table" then params = {} end
    local id = request.id

    -- Shared-token gate (readEnvVar("CE_MCP_AUTH_TOKEN")). Stripped from
    -- params right after the check so handlers and the audit log never see
    -- the token.
    if AUTH_TOKEN ~= nil then
        if not secureTokenEq(params._auth, AUTH_TOKEN) then
            return safeEncode({ jsonrpc = "2.0", id = id,
                error = { code = -32000, message = "Authentication failed",
                          data = { error_code = "AUTH_REQUIRED",
                                   detail = "set CE_MCP_AUTH_TOKEN and send params._auth with every request" } } })
        end
        params._auth = nil
    end

    local handler = commandHandlers[method]
    if not handler then
        return safeEncode({ jsonrpc = "2.0", id = id,
            error = { code = -32601, message = "Method not found: " .. tostring(method),
                      data = { error_code = "METHOD_NOT_FOUND", method = tostring(method) } } })
    end

    serverState.stats.commands = serverState.stats.commands + 1
    serverState.lastMethod = method

    local ok2, result = pcall(handler, params)
    if not ok2 then
        -- Surface handler crashes through the normal result path so the agent
        -- sees the documented {success=false, error_code} shape (and, inside a
        -- batch, so sibling sub-commands are not affected).
        local err = { success = false, error_code = "INTERNAL_ERROR",
                      error = "Internal error: " .. tostring(result) }
        serverState.stats.errors = serverState.stats.errors + 1
        serverState.lastError = err.error
        serverState.lastErrorCode = err.error_code
        if isMutatingMethod(method) then
            auditLogEntry(method, params, false, err.error_code)
        end
        return safeEncode({ jsonrpc = "2.0", result = err, id = id })
    end

    result = finalizeResult(result)
    if isMutatingMethod(method) then
        auditLogEntry(method, params, result.success == true, result.error_code)
    end
    return safeEncode({ jsonrpc = "2.0", result = result, id = id })
end

-- ============================================================================
-- DLL LOADING
-- ============================================================================

local NATIVE_DLL_LOADED = false

local function tryLoadNativeDLL()
    local ceDir = "."
    pcall(function()
        local exePath = getApplication().ExeName
        ceDir = exePath:match("(.+)[/\\]") or "."
    end)
    print("[MCP] CE path: " .. ceDir)

    local is64 = true
    pcall(function()
        if cheatEngineIs64Bit and not cheatEngineIs64Bit() then is64 = false end
    end)
    local dllName = is64 and "ce_mcp_tcp_x64.dll" or "ce_mcp_tcp_x86.dll"
    print("[MCP] CE " .. (is64 and "x64" or "x86") .. " - loading " .. dllName)

    local paths = {
        ceDir .. "\\" .. dllName,
        ceDir .. "/" .. dllName,
        -- Standard CE plugin directory (Cheat Engine\plugins\)
        ceDir .. "\\plugins\\" .. dllName,
        ceDir .. "/plugins/" .. dllName,
        dllName,
    }

    for _, path in ipairs(paths) do
        local ok, loader = pcall(package.loadlib, path, "luaopen_ce_mcp_tcp")
        if ok and loader then
            local ok2, info = pcall(loader)
            if ok2 then
                NATIVE_DLL_LOADED = true
                print("[MCP] DLL loaded OK from: " .. path)
                return true
            end
        end
    end
    print("[MCP] ERROR: " .. dllName .. " not found in: " .. ceDir)
    return false
end

-- ============================================================================
-- POLL LOOP
-- ----------------------------------------------------------------------------
-- createTimer(owner, OnTimerThread=false) fires this callback ON CE'S MAIN
-- THREAD — which is exactly where every CE Lua API call has to happen anyway.
-- The previous implementation wrapped each command in createThread(...) +
-- synchronize(...), i.e. a main -> worker -> main hop per request, adding a
-- thread creation and a full message-pump round trip to every call and making
-- `workerBusy` cross thread boundaries. Running inline removes that latency.
-- `workerBusy` is kept purely as a re-entrancy guard: handlers such as
-- show_message / auto_assemble can pump the message loop and re-enter us.
-- ============================================================================

local nativePollTimer = nil
local workerBusy = false

-- Only used if a CE build dispatches this timer from a non-main thread, so we
-- degrade to the old synchronize path instead of touching CE APIs off-thread.
local function runOnMainThread(fn)
    if type(inMainThread) == "function" then
        local ok, onMain = pcall(inMainThread)
        if ok and onMain == false and type(synchronize) == "function" then
            local box = {}
            local sok = pcall(function()
                synchronize(function() box.result = fn() end)
            end)
            -- If synchronize itself failed, do NOT re-run fn on the wrong
            -- thread: a side-effecting command executing twice is worse than
            -- one client timeout (response stays nil and no frame is sent).
            if sok then return box.result end
            return nil
        end
    end
    return fn()
end

local function NativePollLoop()
    if workerBusy then return end

    local cmd = mcp_tcp_poll()
    if not cmd then return end

    workerBusy = true
    local response
    local ok, err = pcall(function()
        response = runOnMainThread(function() return executeCommand(cmd) end)
    end)
    if not ok then
        response = safeEncode({
            jsonrpc = "2.0", id = nil,
            result = { success = false, error_code = "INTERNAL_ERROR",
                       error = "Internal error: " .. tostring(err) }
        })
    end
    if response then pcall(mcp_tcp_respond, response) end
    workerBusy = false
end

-- ============================================================================
-- START / STOP
-- ============================================================================

function StopMCPBridge()
    if nativePollTimer then
        nativePollTimer.Enabled = false
        nativePollTimer.destroy()
        nativePollTimer = nil
    end
    if NATIVE_DLL_LOADED and type(mcp_tcp_stop) == "function" then
        pcall(mcp_tcp_stop)
    end
    serverState.nativeInfo = nil
    cleanupZombieState()
end

function StartMCPBridge()
    StopMCPBridge()
    serverState.running = true

    if not tryLoadNativeDLL() then
        print("[MCP] FATAL: Cannot start without native DLL")
        return
    end

    if type(mcp_tcp_start) ~= "function" then
        print("[MCP] FATAL: mcp_tcp_start not available")
        return
    end

    pcall(function() mcp_tcp_stop() end)
    local bindAddr = resolveBindAddr() or TCP_BIND
    local result = mcp_tcp_start(TCP_BASE_PORT, bindAddr)
    if not result or not result.ok then
        print("[MCP] ERROR: TCP start failed: " .. tostring(result and result.err or "unknown"))
        return
    end
    serverState.tcpPort   = result.port
    serverState.startedAt = os.time()
    serverState.stats     = { commands = 0, errors = 0, batches = 0, subcommands = 0 }
    serverState.lastMethod, serverState.lastError, serverState.lastErrorCode = nil, nil, nil
    if type(mcp_tcp_status) == "function" then
        local ok, st = pcall(mcp_tcp_status)
        if ok and type(st) == "table" then serverState.nativeInfo = st end
    end

    nativePollTimer = createTimer(nil, false)
    nativePollTimer.Interval = 1
    nativePollTimer.OnTimer = NativePollLoop
    nativePollTimer.Enabled = true

    print("[MCP] Bridge v" .. VERSION .. " started on " .. bindAddr .. ":" .. result.port .. " (native TCP, 1ms poll)")
end

-- ============================================================================
-- CONSOLE / TEST HANDLE
-- ----------------------------------------------------------------------------
-- Drive the bridge straight from CE's Lua console (no socket, no MCP client):
--
--   print(MCP_Bridge.call("ping"))
--   print(MCP_Bridge.call("read_integer", { address = "0x140001000" }))
--   print(MCP_Bridge.call("batch", { calls = {
--       { method = "ping" },
--       { method = "get_process_info" },
--   }}))
--
-- call() returns the raw JSON string; MCP_Bridge.json.decode() parses it back.
-- Set the global MCP_BRIDGE_NO_AUTOSTART = true before dofile() to load the
-- script for inspection without binding a socket.
-- ============================================================================

function MCP_Bridge_call(method, params)
    return executeCommand(json.encode({
        jsonrpc = "2.0", method = method, params = params or {}, id = 1
    }))
end

MCP_Bridge = {
    version  = VERSION,
    call     = MCP_Bridge_call,
    execute  = executeCommand,
    json     = json,
    state    = serverState,
    methods  = commandHandlers,
    toHex    = toHex,
    paginate = paginate,
    start    = StartMCPBridge,
    stop     = StopMCPBridge,
    status   = cmd_status,
}

-- Auto-start
if not MCP_BRIDGE_NO_AUTOSTART then
    StartMCPBridge()
end
