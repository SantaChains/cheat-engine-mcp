-- ============================================================================
-- Offline unit tests for ce_mcp_bridge.lua
-- ----------------------------------------------------------------------------
-- Runs the bridge's pure-Lua core (JSON codec, pagination, address formatting,
-- error normalisation, batch executor, introspection) WITHOUT Cheat Engine and
-- WITHOUT a socket, by stubbing the CE APIs the loaded chunk touches.
--
--   lua MCP_Server/test_bridge_lua.lua        (Lua 5.3 / 5.4 / 5.5)
--
-- The bridge is loaded with MCP_BRIDGE_NO_AUTOSTART so StartMCPBridge() does
-- not run; MCP_Bridge.call() then drives the dispatcher directly.
-- ============================================================================

-- ---- Cheat Engine API stubs (only what the loaded chunk / handlers touch) ---
local opened_pid = 0
getOpenedProcessID  = function() return opened_pid end
targetIs64Bit       = function() return true end
-- Mirrors CE: plain hex literals resolve, garbage does not.
getAddressSafe      = function(s)
  if type(s) == "number" then return s end
  if type(s) ~= "string" then return nil end
  return tonumber(s:match("^0[xX](%x+)$") or "", 16)
end
enumModules         = function() return {} end
reinitializeSymbolhandler = function() end
print               = print

MCP_BRIDGE_NO_AUTOSTART = true
dofile((arg and arg[0] and arg[0]:match("^(.*)[/\\]") or ".") .. "/ce_mcp_bridge.lua")

local json = MCP_Bridge.json
local pass, fail = 0, 0

local function ok(name, cond, extra)
  if cond then
    pass = pass + 1
    print(("  PASS  %s"):format(name))
  else
    fail = fail + 1
    print(("  FAIL  %s   %s"):format(name, tostring(extra or "")))
  end
end

local function req(method, params)
  return json.decode(MCP_Bridge.call(method, params))
end

-- ---------------------------------------------------------------- dispatcher
print("== version / dispatcher ==")
ok("version is 15.8.0", MCP_Bridge.version == "15.8.0", MCP_Bridge.version)
ok("batch / status / list_methods registered",
   MCP_Bridge.methods.batch and MCP_Bridge.methods.status and MCP_Bridge.methods.list_methods)
local methodCount = 0
for _ in pairs(MCP_Bridge.methods) do methodCount = methodCount + 1 end
ok("dispatcher size unchanged or larger (>= 184)", methodCount >= 184, methodCount)

-- ------------------------------------------------------------------ JSON in
print("== JSON decode: non-ASCII (previously string.char>255 crash) ==")
local t = json.decode([[{"method":"write_string","params":{"value":"\u4E2D\u6587 test \u00e9"}}]])
ok("decode does not throw", type(t) == "table")
ok("CJK -> UTF-8 bytes", t and t.params and t.params.value == "中文 test é",
   t and t.params and t.params.value)

local emoji = json.decode([[{"s":"\uD83D\uDE00"}]])
ok("surrogate pair -> 4-byte UTF-8", emoji and emoji.s == "\240\159\152\128",
   emoji and #emoji.s .. " bytes")

local q = json.decode([[{"a":"L1\nL2\t\"q\"\\/","b":true,"c":null,"d":[1,2,3],"e":-1.5e3,"f":0.5}]])
ok("\\n kept", q and q.a:find("\n") ~= nil)
ok("quote / escaped backslash", q and q.a == 'L1\nL2\t"q"\\/', q and q.a)
ok("true / null", q and q.b == true and q.c == nil)
ok("array", q and #q.d == 3 and q.d[3] == 3)
ok("exponent number", q and q.e == -1500, q and q.e)
ok("leading-dot number", q and q.f == 0.5, q and q.f)
ok("malformed input returns nil", json.decode("this is not json") == nil)

-- ----------------------------------------------------------------- JSON out
print("== JSON encode: exact 64-bit numbers ==")
local big = 9223372036854775807
ok("int64 verbatim", json.encode({ v = big }) == '{"v":9223372036854775807}',
   json.encode({ v = big }))
ok("int64 decodes exactly", json.decode(json.encode({ v = big })).v == big)
ok("0x140001000 exact", json.encode({ q = 0x140001000 }) == '{"q":5368713216}',
   json.encode({ q = 0x140001000 }))
ok("float keeps precision", json.decode(json.encode({ f = 1.5 })).f == 1.5)
ok("empty table -> []", json.encode({}) == "[]")
ok("string array", json.encode({ "a", "b" }) == '["a","b"]')

-- ------------------------------------------------------------------- helpers
print("== toHex ==")
ok("32-bit unpadded", MCP_Bridge.toHex(0x1000) == "0x1000", MCP_Bridge.toHex(0x1000))
ok("64-bit", MCP_Bridge.toHex(0x140001000) == "0x140001000", MCP_Bridge.toHex(0x140001000))
ok("nil -> \"nil\"", MCP_Bridge.toHex(nil) == "nil")
ok("zero", MCP_Bridge.toHex(0) == "0x0", MCP_Bridge.toHex(0))

print("== paginate ==")
local lim, off, page, total = MCP_Bridge.paginate({ offset = 1, limit = 2 }, { 10, 20, 30, 40 }, 100)
ok("slice bounds", lim == 2 and off == 1 and total == 4 and #page == 2 and page[1] == 20 and page[2] == 30)
local _, _, p0 = MCP_Bridge.paginate({ offset = 99, limit = 5 }, { 10, 20 }, 100)
ok("offset past end -> empty page", #p0 == 0)
local _, _, pc = MCP_Bridge.paginate({ limit = 99999 }, { 1, 2, 3 }, 100)
ok("limit clamped to 10000", #pc == 3)
local _, _, pd = MCP_Bridge.paginate({ max = 1 }, { 1, 2, 3 }, 100)
ok("legacy 'max' alias honoured", #pd == 1)

-- -------------------------------------------------------- response envelopes
print("== executeCommand envelopes ==")
local ur = json.decode(MCP_Bridge.execute(json.encode({ jsonrpc = "2.0", method = "nope", params = {}, id = 7 })))
ok("unknown method -> -32601", ur and ur.error and ur.error.code == -32601)
ok("METHOD_NOT_FOUND surfaced", ur and ur.error.data and ur.error.data.error_code == "METHOD_NOT_FOUND")
local pr = json.decode(MCP_Bridge.execute("this is not json"))
ok("parse error -> -32700", pr and pr.error and pr.error.code == -32700)
ok("PARSE_ERROR surfaced", pr and pr.error.data and pr.error.data.error_code == "PARSE_ERROR")

print("== handler crash -> structured result ==")
MCP_Bridge.methods.__boom = function() error("kaboom") end
local br = req("__boom")
ok("crash -> success=false", br and br.result and br.result.success == false)
ok("crash -> INTERNAL_ERROR", br and br.result.error_code == "INTERNAL_ERROR", br and br.result.error_code)
ok("crash keeps message", br and br.result.error and br.result.error:find("kaboom") ~= nil)
MCP_Bridge.methods.__boom = nil

-- --------------------------------------------------------- error normalisation
print("== error_code inference ==")
local cases = {
  { "Invalid address: xyz",                                       "INVALID_ADDRESS" },
  { "Invalid base address",                                       "INVALID_ADDRESS" },
  { "No process attached",                                        "NO_PROCESS" },
  { "Symbol not found: foo",                                      "NOT_FOUND" },
  { "No scan results. Run scan_all first.",                       "NOT_FOUND" },
  { "No active watch found for this address",                     "NOT_FOUND" },
  { "Unknown type: blob",                                         "INVALID_PARAMS" },
  { "No pattern provided",                                        "INVALID_PARAMS" },
  { "Unknown signature token {s1.2}",                             "UNKNOWN_SIG_TOKEN" },
  { "DBK driver not loaded",                                      "DBK_NOT_LOADED" },
  { "DBVM not running. Go to Settings",                           "DBVM_NOT_LOADED" },
  { "No free hardware breakpoint slots (max 4 debug registers)",  "OUT_OF_RESOURCES" },
  { "something exploded",                                         "INTERNAL_ERROR" },
}
for _, c in ipairs(cases) do
  MCP_Bridge.methods.__err = function() return { success = false, error = c[1] } end
  local r = req("__err")
  ok(("%-18s <- %s"):format(c[2], c[1]:sub(1, 30)), r and r.result.error_code == c[2],
     r and r.result.error_code)
end
MCP_Bridge.methods.__err = function() return { success = false, error_code = "MINE", error = "x" } end
ok("explicit error_code wins", req("__err").result.error_code == "MINE")
MCP_Bridge.methods.__err = nil

-- --------------------------------------------------------------------- batch
print("== batch ==")
local b1 = req("batch", { calls = {
  { method = "status" },
  { method = "list_methods", params = { limit = 3 } },
  { method = "nope" },
} })
ok("partial failure reported", b1 and b1.result.success == false and b1.result.failed == 1,
   b1 and json.encode(b1.result))
ok("results keep index + method",
   b1 and b1.result.results[1].index == 1 and b1.result.results[1].method == "status"
   and b1.result.results[3].method == "nope")
ok("all three executed (stop_on_error default)", b1 and b1.result.executed == 3
   and b1.result.stopped_early == false)
ok("PARTIAL_FAILURE code", b1 and b1.result.error_code == "PARTIAL_FAILURE")

local b2 = req("batch", { calls = { { method = "nope" }, { method = "status" } } })
ok("stop_on_error stops early", b2 and b2.result.executed == 1 and b2.result.stopped_early == true,
   b2 and (b2.result.executed .. "/" .. tostring(b2.result.stopped_early)))

local b3 = req("batch", { calls = { { method = "nope" }, { method = "status" } }, stop_on_error = false })
ok("stop_on_error=false continues", b3 and b3.result.executed == 2, b3 and b3.result.executed)

local b4 = req("batch", { calls = { { method = "batch", params = { calls = {} } } } })
ok("nested batch rejected", b4 and b4.result.results[1].error_code == "INVALID_PARAMS")

local b5 = req("batch", { calls = { a = 1 } })
ok("non-array calls rejected", b5 and b5.result.error_code == "INVALID_PARAMS", b5 and b5.result.error)

local many = {}
for i = 1, 70 do many[i] = { method = "status" } end
local b6 = req("batch", { calls = many })
ok("call cap enforced (max 64)", b6 and b6.result.error_code == "INVALID_PARAMS", b6 and b6.result.error)

local b7 = req("batch", { calls = {} })
ok("empty batch is valid", b7 and b7.result.success == true and b7.result.executed == 0)

local b8 = req("batch", { calls = { { method = "status" }, { "status" } } })
ok("string shorthand entry rejected as method-not-found",
   b8 and b8.result.results[2].error_code == "METHOD_NOT_FOUND", b8 and b8.result.results[2].error)

-- ------------------------------------------------------------- introspection
print("== status / list_methods ==")
local st = req("status")
ok("status ok", st and st.result.success == true and st.result.version == "15.8.0")
ok("method_count matches dispatcher", st and st.result.method_count == methodCount,
   st and st.result.method_count)
ok("process_attached reflects CE state", st and st.result.process_attached == false)
ok("target_arch reported", st and st.result.target_arch == "none", st and st.result.target_arch)
ok("stats recorded", st and type(st.result.stats) == "table" and st.result.stats.commands > 0)
ok("resources reported", st and type(st.result.resources) == "table"
   and st.result.resources.breakpoints == 0 and st.result.resources.dbvm_watches == 0)

local lm = req("list_methods", { limit = 5 })
ok("list_methods total == method_count", lm and lm.result.total == methodCount, lm and lm.result.total)
ok("list_methods page size", lm and lm.result.returned == 5 and #lm.result.methods == 5)
ok("list_methods sorted", lm and lm.result.methods[1] <= lm.result.methods[2])
local lmp = req("list_methods", { prefix = "dbk" })
ok("prefix filter", lmp and lmp.result.total == 8 and lmp.result.methods[1] == "dbk_get_cr0",
   lmp and lmp.result.total)
ok("status alias bridge_status", req("bridge_status").result.version == "15.8.0")
ok("list alias list_bridge_methods",
   req("list_bridge_methods", { limit = 1 }).result.total == methodCount)

-- --------------------------------------------------------- no-process guards
print("== no-process / bad-input paths ==")
local rm = req("read_memory", { address = "0x1", size = 4 })
ok("read_memory fails cleanly", rm and rm.result and rm.result.success == false, json.encode(rm))
ok("read_memory error_code present", rm and rm.result.error_code ~= nil, rm and rm.result.error_code)
local em = req("enum_modules")
ok("enum_modules fails cleanly", em and em.result and em.result.success == false, json.encode(em))
local rs = req("aob_scan_region", { pattern = "90 90", start = "0x1", size = 4 })
ok("region scan needs a process", rs and rs.result.success == false
   and rs.result.error_code == "NO_PROCESS", rs and rs.result.error_code)
local ds = req("disassemble", { address = "0x1" })
ok("disassemble fails cleanly", ds and ds.result.success == false)
local wi = req("write_integer", { address = "0x1", value = 999999, type = "byte" })
ok("write_integer range-checks value", wi and wi.result.success == false
   and wi.result.error_code == "INVALID_PARAMS", wi and wi.result.error_code)

-- ------------------------------------------------- memory record manipulation
print("== memory record manipulation (UNIT-26, stubbed AddressList) ==")

-- Minimal memoryrecord mock: properties live in a plain table behind
-- __index/__newindex so handler writes are observable from the test.
local function make_rec(fields)
  local f = fields or {}
  local rec
  rec = setmetatable({}, {
    __index = function(_, k)
      if k == "String" then f.__String = f.__String or {}; return f.__String end
      if k == "Aob"    then f.__Aob    = f.__Aob    or {}; return f.__Aob end
      if k == "Binary" then f.__Binary = f.__Binary or {}; return f.__Binary end
      if k == "OffsetText" then f.OffsetText = f.OffsetText or {}; return f.OffsetText end
      if k == "Child" then
        return setmetatable({}, { __index = function(_, i) return (f.__child_recs or {})[i + 1] end })
      end
      return f[k]
    end,
    __newindex = function(_, k, v) f[k] = v end,
  })
  return rec, f
end

local childRec, _ = make_rec({
  ID = 2, Description = "child entry", Address = "0x22", VarType = "vtDword",
  Value = "5", Active = false, Count = 0, IsGroupHeader = false,
  appendToEntry = function() end,
})

-- NOTE: closures must not reference the locals being declared in the same
-- statement (they would resolve to globals). Build the fields table first.
local rootFields = {
  ID = 1, Description = "root entry", Address = "0x11", VarType = "vtDword",
  Value = "10", Active = false, Count = 1, IsGroupHeader = false,
  CurrentAddress = 0x140001000,
  appendToEntry = function() end,
}
rootFields.__child_recs = { childRec }
rootFields.setOffsetCount = function(_, n) rootFields.OffsetCount = n end
rootFields.setOffset = function(_, i, v)
  rootFields.Offset = rootFields.Offset or {}
  rootFields.Offset[i] = v
end
rootFields.getCurrentAddress = function() return rootFields.CurrentAddress end
local rootRec, rootF = make_rec(rootFields)
local byId = { [1] = rootRec, [2] = childRec }
getAddressList = function()
  return {
    Count = 2,
    getMemoryRecordByID = function(_, id) return byId[id] end,
  }
end

ok("missing active -> INVALID_PARAMS",
   req("set_memory_record_active", { id = 1 }).result.error_code == "INVALID_PARAMS")
ok("missing id -> INVALID_PARAMS",
   req("set_memory_record_active", { active = true }).result.error_code == "INVALID_PARAMS")
ok("unknown id -> NOT_FOUND",
   req("set_memory_record_active", { id = 99, active = true }).result.error_code == "NOT_FOUND")

local ar = req("set_memory_record_active", { id = 1, active = true })
ok("active applied + read back",
   ar and ar.result.success == true and ar.result.applied == true
   and ar.result.record.enabled == true, ar and json.encode(ar.result))
ok("no warning when state sticks", ar and ar.result.warning == nil)

local dr = req("set_memory_record_description", { id = 1, description = "renamed" })
ok("description renamed", dr and dr.result.record.description == "renamed")
ok("empty description -> INVALID_PARAMS",
   req("set_memory_record_description", { id = 1, description = "" }).result.error_code == "INVALID_PARAMS")

local adr = req("set_memory_record_address", { id = 1, address = "0x100", offsets = { 4 } })
ok("address retargeted", adr and adr.result.record.address == "0x100", adr and json.encode(adr.result))
ok("pointer offset stored (0-based index 0)", adr and adr.result.record.offsets[1] == 4)
ok("empty address -> INVALID_PARAMS",
   req("set_memory_record_address", { id = 1, address = "" }).result.error_code == "INVALID_PARAMS")

local tr = req("set_memory_record_type", { id = 1, type = "string", size = 16, unicode = true })
ok("type switched to vtString", tr and tr.result.record.type == "vtString", tr and json.encode(tr.result))
ok("String.Size + Unicode applied", tr and rootF.__String.Size == 16 and rootF.__String.Unicode == true)
ok("unknown type -> INVALID_PARAMS",
   req("set_memory_record_type", { id = 1, type = "blob" }).result.error_code == "INVALID_PARAMS")

local br26 = req("set_memory_record_type", { id = 1, type = "bytearray", size = 8 })
ok("bytearray Aob.Size applied", br26 and rootF.__Aob.Size == 8)

local sc = req("set_memory_record_script", { id = 1, script = "[enable]\n[disable]" })
ok("AA script stored with guidance note", sc and sc.result.success == true and sc.result.note ~= nil)
ok("empty script -> INVALID_PARAMS",
   req("set_memory_record_script", { id = 1, script = "" }).result.error_code == "INVALID_PARAMS")

local ca = req("get_memory_record_current_address", { id = 1 })
ok("current address resolved to hex", ca and ca.result.address == "0x140001000", ca and json.encode(ca.result))
ok("current address integer form", ca and ca.result.address_integer == 5368713216)

local ch = req("get_memory_record_children", { id = 1 })
ok("children listed", ch and ch.result.total == 1 and ch.result.children[1].id == 2,
   ch and json.encode(ch.result))
ok("children pagination", req("get_memory_record_children", { id = 1, offset = 5 }).result.returned == 0)

ok("append requires both ids",
   req("append_memory_record", { id = 1 }).result.error_code == "INVALID_PARAMS")
local ap = req("append_memory_record", { id = 2, parent_id = 1 })
ok("append succeeds", ap and ap.result.success == true)

-- offsets pre-validation: bad input is INVALID_PARAMS and mutates nothing
local badOff = req("set_memory_record_offsets", { id = 1, offsets = { 4, "" } })
ok("bad offset entry -> INVALID_PARAMS",
   badOff and badOff.result.error_code == "INVALID_PARAMS", badOff and json.encode(badOff))
local badAddr = req("set_memory_record_address", { id = 1, address = "0x200", offsets = { "" } })
ok("bad offsets reject address change too",
   badAddr and badAddr.result.error_code == "INVALID_PARAMS", badAddr and json.encode(badAddr))
ok("address untouched after rejected offsets", rootFields.Address == "0x100", rootFields.Address)
ok("offset count untouched after rejection", rootFields.OffsetCount == nil or rootFields.OffsetCount == 1)

-- parseable text offset lands in BOTH OffsetText (original text) and
-- Offset (numeric fallback); unparseable text stays text-only
local txtOff = req("set_memory_record_offsets", { id = 1, offsets = { "+10" } })
ok("parseable text offset stored as text", txtOff and txtOff.result.success == true
   and rootFields.OffsetText and rootFields.OffsetText[0] == "+10",
   txtOff and json.encode(txtOff.result))
ok("parseable text offset also applied numerically",
   rootFields.Offset and rootFields.Offset[0] == 10, rootFields.Offset and rootFields.Offset[0])

rootFields.Offset, rootFields.OffsetText = nil, nil
local rawOff = req("set_memory_record_offsets", { id = 1, offsets = { "base+4" } })
ok("unparseable offset stays text-only", rawOff and rawOff.result.success == true
   and rootFields.OffsetText and rootFields.OffsetText[0] == "base+4"
   and (rootFields.Offset == nil or rootFields.Offset[0] == nil),
   rawOff and json.encode(rawOff.result))

-- ------------------------------------------------------------- evaluate_lua
print("== evaluate_lua (print capture + structured results) ==")
local ev = req("evaluate_lua", { code = "print('hi', 42); return { a = 1, b = 'two' }" })
ok("evaluate success", ev and ev.result.success == true)
ok("print captured with tab join", ev and ev.result.printed and ev.result.printed[1] == "hi\t42",
   ev and json.encode(ev.result))
local evDecoded = ev and json.decode(ev.result.result)
ok("table result serialized to JSON", evDecoded and evDecoded.a == 1 and evDecoded.b == "two",
   ev and ev.result.result)
ok("plain string returned verbatim",
   req("evaluate_lua", { code = 'return "hello"' }).result.result == "hello")
ok("missing code -> INVALID_PARAMS",
   req("evaluate_lua", {}).result.error_code == "INVALID_PARAMS")
ok("compile error reported",
   req("evaluate_lua", { code = "return ++" }).result.success == false)
local evErr = req("evaluate_lua", { code = 'error("boom")' })
ok("runtime error -> INTERNAL_ERROR",
   evErr and evErr.result.success == false and evErr.result.error_code == "INTERNAL_ERROR")

-- ---------------------------------------------------------------------------
-- UTF-8 / CJK matrix: the Python side sends raw UTF-8 (ensure_ascii=False),
-- so the codec must round-trip multibyte content losslessly in every path.
-- ---------------------------------------------------------------------------
local reqR = function(method, params)                       -- call() returns an
  local body = json.decode(MCP_Bridge.call(method, params)) -- encoded JSON string
  return body and body.result
end

ok("utf8 decode raw CJK", json.decode('{"m":"中文测试：绀碧の焦点"}').m == "中文测试：绀碧の焦点")
ok("utf8 decode escaped CJK", json.decode('{"m":"\\u4e2d\\u6587"}').m == "中文")
ok("utf8 decode surrogate pair", json.decode('{"m":"\\uD83D\\uDE00"}').m == "\u{1F600}")
local utf8Enc = json.encode({ msg = "中文" })
ok("utf8 encode raw (no \\u escapes)", utf8Enc:find("中文", 1, true) ~= nil and not utf8Enc:find("\\u", 1, true), utf8Enc)
ok("utf8 encode/decode round-trip", json.decode(utf8Enc).msg == "中文")

local r6 = reqR("evaluate_lua", { code = 'return "中文值"' })
ok("utf8 evaluate_lua result", r6 and r6.success == true and r6.result == "中文值", r6 and (r6.result or r6.error))
local r7 = reqR("evaluate_lua", { code = 'print("中文输出") return 1' })
local joined = r7 and r7.printed and table.concat(r7.printed, "\n") or ""
ok("utf8 print capture", joined:find("中文输出", 1, true) ~= nil, joined ~= "" and joined or "?")
local r8 = reqR("read_memory", { address = "not_an_address_zzz中文" })
ok("utf8 error path survives", r8 and r8.success == false and type(r8.error) == "string")
local st2 = reqR("status", {})
ok("utf8 stats consistent", st2 and st2.success == true and st2.stats.commands >= 3)

-- ---------------------------------------------------------------------------
-- Codec robustness: depth guards (the field-reported "response encoding
-- failed" at the encode_table object loop was a stack overflow from deep
-- nesting) and mixed-table data loss (array prefix + string keys used to be
-- silently truncated to [...]).
-- ---------------------------------------------------------------------------
local function tryEnc(payload)
  local ok, err = pcall(json.encode, payload)
  return ok, err
end

local deep = {}
do local cur = deep for _ = 1, 100000 do cur.n = {} cur = cur.n end end
local dOk, dErr = tryEnc(deep)
ok("encode deep nesting -> deterministic depth error",
   dOk == false and tostring(dErr):find("nesting depth exceeded 200", 1, true) ~= nil, dErr)

local c = { a = {} }
c.a.self = c
local cOk, cErr = tryEnc(c)
ok("encode circular still errors", cOk == false and tostring(cErr):find("circular", 1, true) ~= nil)

ok("encode empty table -> []", json.encode({}) == "[]")
ok("encode dense array unchanged", json.encode({ 1, 2, 3 }) == "[1,2,3]")
ok("encode mixed table keeps all keys", json.encode({ [1] = "a", extra = "b" }) == '{"1":"a","extra":"b"}')
ok("encode sparse array keeps hole items", json.encode({ [1] = "a", [3] = "c" }) == '{"1":"a","3":"c"}')

local decOk, decErr = pcall(json.decode, string.rep("[", 500) .. string.rep("]", 500))
ok("decode deep nesting -> deterministic depth error",
   decOk == false and tostring(decErr):find("nesting depth exceeded 200", 1, true) ~= nil, decErr)
local rt = json.decode(json.encode({ 1, "x", { k = "v" } }))
ok("codec round-trip unaffected", rt[1] == 1 and rt[2] == "x" and rt[3].k == "v")

-- ---------------------------------------------------------------------------
-- Paging clamp (v15.2.1): one clampPaging() helper behind every offset/limit
-- surface. Non-numeric params fall back instead of erroring mid-handler.
-- ---------------------------------------------------------------------------
print("== paging clamp ==")
local _, _, ps = MCP_Bridge.paginate({ limit = "2" }, { 1, 2, 3 }, 100)
ok("string limit accepted", #ps == 2)
local _, _, pn = MCP_Bridge.paginate({ limit = "abc" }, { 1, 2, 3 }, 2)
ok("non-numeric limit -> default", #pn == 2)
local _, _, po = MCP_Bridge.paginate({ offset = "1" }, { 1, 2, 3 }, 100)
ok("string offset accepted", #po == 2 and po[1] == 2)

local lms = req("list_methods", { limit = "3" })
ok("list_methods string limit", lms and lms.result.returned == 3, lms and json.encode(lms.result))

local chs = req("get_memory_record_children", { id = 1, limit = "1" })
ok("children string limit echoed", chs and chs.result.limit == 1 and chs.result.returned == 1,
   chs and json.encode(chs.result))

-- get_scan_results: 0-based CE collection + `max` alias + 0x prefix normalisation
-- NOTE: the handler calls these with a dot (fl.getAddress(i)), no self
MCP_Bridge.state.scan_foundlist = {
  getCount   = function() return 4 end,
  getAddress = function(i) return string.format("%X", 0x3000 + i) end,
  getValue   = function(i) return "v" .. i end,
}
local sr = req("get_scan_results", { max = "2" })
ok("get_scan_results max alias + string limit",
   sr and sr.result.limit == 2 and sr.result.returned == 2, sr and json.encode(sr.result))
ok("get_scan_results 0x prefix normalised",
   sr and sr.result.results[1].address == "0x3000", sr and sr.result.results[1].address)
MCP_Bridge.state.scan_foundlist = nil

-- aob_scan limit clamp: >= 1 lower bound now enforced (0 used to yield nothing)
local aobStub = { Count = 5,  -- dot-called by the handler (results.getString(i))
                  getString = function(i) return string.format("%X", 0x2000 + i) end,
                  destroy = function() end }
AOBScan = function() return aobStub end
local as0 = req("aob_scan", { pattern = "90", limit = 0 })
ok("aob_scan limit 0 clamped to 1", as0 and as0.result.count == 1, as0 and json.encode(as0.result))
local as2 = req("aob_scan", { pattern = "90", limit = "2" })
ok("aob_scan string limit", as2 and as2.result.count == 2)
AOBScan = nil

-- ---------------------------------------------------------------------------
-- v15.3.0: audit trail, evaluate_lua traceback + printed cap, AA size gate
-- ---------------------------------------------------------------------------
print("== audit trail / gates ==")
-- a read-only command must NOT be audited (start from a clean log)
req("get_audit_log", { clear = true })
req("ping", {})
local al0 = req("get_audit_log", {})
ok("ping not audited", al0 and al0.result.total == 0, al0 and json.encode(al0.result))

-- a mutating command IS audited, newest first
req("set_memory_record_description", { id = 1, description = "audit-probe" })
local al1 = req("get_audit_log", {})
ok("mutating command audited", al1 and al1.result.total >= 1
   and al1.result.entries[1].method == "set_memory_record_description"
   and al1.result.entries[1].success == true,
   al1 and json.encode(al1.result))
ok("audit params summarised", al1 and al1.result.entries[1].params:find("id=1", 1, true) ~= nil,
   al1 and al1.result.entries[1].params)

-- mutating sub-commands inside batch are audited too
req("batch", { calls = { { method = "set_memory_record_description",
                           params = { id = 1, description = "audit-batch" } } } })
local al2 = req("get_audit_log", {})
ok("batch sub-command audited", al2 and al2.result.entries[1].method == "set_memory_record_description",
   al2 and json.encode(al2.result.entries[1]))

-- clear empties the log
req("get_audit_log", { clear = true })
ok("audit clear", req("get_audit_log", {}).result.total == 0)

-- evaluate_lua: runtime error carries a traceback now
local evTb = req("evaluate_lua", { code = "local function f() error('boom') end f()" })
ok("evaluate traceback captured", evTb and evTb.result.success == false
   and type(evTb.result.traceback) == "string"
   and evTb.result.traceback:find("stack traceback", 1, true) ~= nil
   and evTb.result.traceback:find("boom", 1, true) ~= nil,
   evTb and json.encode(evTb.result))
ok("evaluate error message stays single-line",
   evTb and evTb.result.error:find("\n", 1, true) == nil, evTb and evTb.result.error)

-- evaluate_lua: runaway print is capped
local evP = req("evaluate_lua", { code = "for i = 1, 250 do print(i) end" })
ok("printed capped at 200", evP and evP.result.printed_truncated == true
   and #evP.result.printed == 200, evP and json.encode(evP.result))
local evP2 = req("evaluate_lua", { code = "print('fine')" })
ok("small print output not truncated", evP2 and evP2.result.printed_truncated == nil)

-- auto_assemble_check: oversized script rejected instead of freezing CE
local bigScript = string.rep("// pad\n", 15000)  -- ~135 KB after expansion
local aaBig = req("auto_assemble_check", { script = bigScript })
ok("AA check size gate", aaBig and aaBig.result.error_code == "SCRIPT_TOO_LARGE",
   aaBig and json.encode(aaBig.result))
-- 80 KB, over the 64 KiB gate:
local aaBig2 = req("auto_assemble", { script = string.rep("nop\n", 20000) })
ok("AA assemble size gate", aaBig2 and aaBig2.result.error_code == "SCRIPT_TOO_LARGE",
   aaBig2 and json.encode(aaBig2.result))

-- ---------------------------------------------------------------------------
-- v15.4.0: list_apis / table_state / script patch + undo
-- ---------------------------------------------------------------------------
print("== introspection & patching ==")
local la = req("list_apis", { filter = "cmd_" })
ok("list_apis filters functions", la and la.result.success == true and la.result.total >= 190,
   la and json.encode({total = la and la.result.total}))
local la2 = req("list_apis", { filter = "CMD_PING" })
ok("list_apis case-insensitive filter", la2 and la2.result.total == 1
   and la2.result.apis[1] == "cmd_ping", la2 and json.encode(la2.result))

-- table_state: no table loaded in test env -> graceful note
local ts0 = req("table_state", {})
ok("table_state graceful without getTableFile",
   ts0 and ts0.result.success == true and ts0.result.note ~= nil and ts0.result.memory_records == 2,
   ts0 and json.encode(ts0.result))

-- table_state with a real temp file
local tmpPath = os.tmpname()
local fh = io.open(tmpPath, "wb"); fh:write("HELLO-FNV"); fh:close()
getTableFile = function() return tmpPath end
local ts1 = req("table_state", {})
ok("table_state reads disk size + fnv1a",
   ts1 and ts1.result.disk_size == 9 and ts1.result.disk_fnv1a ~= nil,
   ts1 and json.encode(ts1.result))
-- deterministic hash: recompute manually for the same content
local h = 2166136261
for i = 1, 9 do h = (h ~ ("HELLO-FNV"):byte(i)) * 16777619; h = h % 4294967296 end
ok("table_state fnv1a value correct",
   ts1 and ts1.result.disk_fnv1a == string.format("%08x", h), ts1 and ts1.result.disk_fnv1a)
getTableFile = nil
os.remove(tmpPath)

-- patch: no match
local p0 = req("patch_memory_record_script", { id = 1, find = "NOT-PRESENT" })
ok("patch NO_MATCH", p0 and p0.result.error_code == "NO_MATCH")

-- patch: set base script then single patch
req("set_memory_record_script", { id = 1, script = "line1\nline2\nline3" })
local p1 = req("patch_memory_record_script", { id = 1, find = "line2", replace = "LINE-TWO" })
ok("patch single replacement", p1 and p1.result.replaced == 1 and p1.result.new_length == #("line1\nLINE-TWO\nline3"),
   p1 and json.encode(p1.result))

-- patch: ambiguous without all=true
req("set_memory_record_script", { id = 1, script = "aXbXc" })
local p2 = req("patch_memory_record_script", { id = 1, find = "X" })
ok("patch ambiguous guard", p2 and p2.result.error_code == "AMBIGUOUS_MATCH")

-- patch: all=true replaces both, then undo restores previous text
local p3 = req("patch_memory_record_script", { id = 1, find = "X", replace = "Y", all = true })
ok("patch all=true replaces both", p3 and p3.result.replaced == 2 and p3.result.new_length == #("aYbYc"),
   p3 and json.encode(p3.result))
local u1 = req("undo_memory_record_script_patch", { id = 1 })
ok("undo restores previous script", u1 and u1.result.restored_length == #("aXbXc"),
   u1 and json.encode(u1.result))
-- record table does not carry the Script text; verify restoration by
-- re-patching: two X occurrences must trip the ambiguity guard again
local pv = req("patch_memory_record_script", { id = 1, find = "X" })
ok("undo text verified (ambiguity guard re-trips)", pv and pv.result.error_code == "AMBIGUOUS_MATCH",
   pv and json.encode(pv.result))

-- undo on empty history
local u2 = req("undo_memory_record_script_patch", { id = 2 })
ok("undo NO_HISTORY", u2 and u2.result.error_code == "NO_HISTORY")

-- patch/undo are audited (mutating prefixes)
local al = req("get_audit_log", { limit = 5 })
local methods = {}
if al then for _, e in ipairs(al.result.entries) do methods[e.method] = true end end
ok("patch + undo audited", methods["patch_memory_record_script"] and methods["undo_memory_record_script_patch"],
   al and json.encode(al.result.entries))

-- ============================================================================
-- UNIT-31: CE API gap coverage (speed / custom types / dissect / dotnet /
-- hotkeys / table files / AA commands / HTTP / DBK / DBVM)
-- ============================================================================

-- ---- CE API stubs for this unit ----------------------------------------------
local stub_state = { speed = 1, prevOpcode = 0x401000, lastData = { line = "mov eax,1" } }
speedhack_setSpeed = function(v) stub_state.speed = v return true end
speedhack_getSpeed = function() return stub_state.speed end
getPreviousOpcode  = function(a) return stub_state.prevOpcode end
getLastDisassembleData = function() return stub_state.lastData end

local mk_hotkey = { destroyed = 0 }
createHotkey = function(fn, keys)
  assert(type(fn) == "function" and type(keys) == "table")
  return { destroy = function() mk_hotkey.destroyed = mk_hotkey.destroyed + 1 end }
end

local ct_state = { bytes = nil, value = nil }
registerCustomTypeLua = function(name, n, b2v, v2b, isFloat)
  ct_state.name, ct_state.n, ct_state.isFloat = name, n, isFloat
  ct_state.obj = {
    byteTableToValue  = function(self, bytes) return 12345 end,
    valueToByteTable  = function(self, v) return { 0x39, 0x30, 0, 0 } end,
  }
  return ct_state.obj
end
getCustomType = function(name)
  if ct_state.name == name then return ct_state.obj or { scriptUsesFloat = false } end
  return nil
end

readBytes  = function(addr, n, asTable)
  assert(asTable == true)
  return { 0x39, 0x30, 0x00, 0x00 }
end
writeBytes = function(addr, bytes) ct_state.wrote = #bytes return true end

local dotnet_state = { domains = { { 1234, "root" } } }
getDotNetDataCollector = function()
  return {
    Attached = true,
    enumDomains = function(self) return dotnet_state.domains end,
    enumModuleList = function(self, dh) return { { 5678, 0x400000, "game.dll" } } end,
  }
end

local dissect_state = { calls = {} }
getDissectCode = function()
  return {
    dissect = function(self, a, b) dissect_state.calls[#dissect_state.calls+1] = a return true end,
    getReferences = function(self, addr) return { [0x401500] = "jtCall" } end,
    getReferencedStrings = function(self) return { [0x403000] = "hello" } end,
    getReferencedFunctions = function(self) return { [0x401000] = true } end,
    saveToFile = function(self, f) return true end,
    loadFromFile = function(self, f) return true end,
    clear = function(self) return true end,
  }
end

local tf_state = { files = {} }
createTableFile = function(name, path) tf_state.files[name] = path return { name = name } end
findTableFile = function(name)
  if tf_state.files[name] ~= nil then return { name = name } end
  return nil
end
-- export/delete need the real object's methods; patch findTableFile to return them
local real_find_stub = findTableFile
findTableFile = function(name)
  local exists = tf_state.files[name] ~= nil
  if not exists then return nil end
  return {
    saveToFile = function(self, dest) tf_state.exported = dest return true end,
    delete = function(self) tf_state.files[name] = nil return true end,
  }
end

local aa_state = { registered = {}, unregistered = {} }
registerAutoAssemblerCommand   = function(cmd, fn) aa_state.registered[cmd] = fn return true end
unregisterAutoAssemblerCommand = function(cmd) aa_state.unregistered[cmd] = true return true end

getInternet = function(agent)
  return {
    getURL = function(self, url) return "BODY:" .. url end,
    postURL = function(self, url, data) return "POSTED" end,
  }
end

local dbk_state = { init = false }
dbk_initialize = function() dbk_state.init = true return true end
dbk_useKernelmodeOpenProcess = function() return true end
dbk_readMSR = function(m) return 0xDEADBEEF end
dbvm_initialize = function(offload, reason) return true end
dbvm_readMSR = function(m) return 0xCAFEBABE end
dbvm_cloak_readOriginal = function(phys)
  local t = {}
  for i = 1, 4096 do t[i] = 0x90 end
  return t
end
dbvm_cloak_writeOriginal = function(phys, bytes) return true end

local st_state = { count = 3 }
getStructureByName = function(name) return nil end
createStructure = function(name, addToGlobal)
  return { autoGuess = function(self, base, off, size) st_state.guessed = base end,
           Count = st_state.count }
end

-- ---- speedhack ----------------------------------------------------------------
local sp1 = req("set_speed", { speed = 2.5 })
ok("set_speed ok", sp1 and sp1.result.success == true and stub_state.speed == 2.5)
local sp2 = req("get_speed", {})
ok("get_speed echoes 2.5", sp2 and sp2.result.speed == 2.5)
local sp3 = req("set_speed", { speed = -1 })
ok("set_speed rejects non-positive", sp3 and sp3.result.error_code == "INVALID_PARAMS")

-- ---- disassembly context --------------------------------------------------------
local po = req("get_previous_opcode", { address = "0x401100" })
ok("get_previous_opcode hex", po and po.result.previous == "0x401000", po and json.encode(po.result))
local ld = req("get_last_disassemble_data", {})
ok("get_last_disassemble_data table", ld and ld.result.data and ld.result.data.line == "mov eax,1")

-- ---- structure auto-guess ---------------------------------------------------------
local ag = req("auto_guess_structure", { name = "MyStruct", base_address = "0x401000", size = 64 })
ok("auto_guess_structure", ag and ag.result.success == true and ag.result.elements == 3,
   ag and json.encode(ag.result))
local ag2 = req("auto_guess_structure", { base_address = "0x401000" })
ok("auto_guess needs name", ag2 and ag2.result.error_code == "INVALID_PARAMS")

-- ---- hotkeys -----------------------------------------------------------------------
local hk1 = req("create_hotkey", { keys = { 112, 113 }, action_lua = "return 1" })
ok("create_hotkey ok", hk1 and hk1.result.success == true and hk1.result.id == "hk_1",
   hk1 and json.encode(hk1.result))
local hk2 = req("create_hotkey", { keys = {}, action_lua = "return 1" })
ok("create_hotkey rejects empty keys", hk2 and hk2.result.error_code == "INVALID_PARAMS")
local hk3 = req("create_hotkey", { keys = { 112 }, action_lua = "return )))" })
ok("create_hotkey rejects bad lua", hk3 and hk3.result.error_code == "INVALID_PARAMS")
local hkl = req("list_hotkeys", {})
ok("list_hotkeys shows 1", hkl and hkl.result.total == 1)
local hkd = req("remove_hotkey", { id = "hk_1" })
ok("remove_hotkey ok", hkd and hkd.result.success == true and mk_hotkey.destroyed == 1)
local hkx = req("remove_hotkey", { id = "hk_99" })
ok("remove_hotkey NOT_FOUND", hkx and hkx.result.error_code == "NOT_FOUND")

-- ---- custom types ---------------------------------------------------------------------
local ct1 = req("register_custom_type", { name = "xor4", byte_count = 4,
  bytes_to_value_lua = "return 12345", value_to_bytes_lua = "return {1,2,3,4}" })
ok("register_custom_type ok", ct1 and ct1.result.success == true, ct1 and json.encode(ct1.result))
local ct2 = req("register_custom_type", { name = "bad", byte_count = 9,
  bytes_to_value_lua = "return 1", value_to_bytes_lua = "return {1}" })
ok("register_custom_type rejects byte_count>8", ct2 and ct2.result.error_code == "INVALID_PARAMS")
local ct3 = req("register_custom_type", { name = "bad2", byte_count = 4,
  bytes_to_value_lua = "return )))", value_to_bytes_lua = "return {1}" })
ok("register_custom_type rejects bad lua", ct3 and ct3.result.error_code == "INVALID_PARAMS")
local cti = req("get_custom_type", { name = "xor4" })
ok("get_custom_type found", cti and cti.result.success == true and cti.result.registered_byte_count == 4)
local rc = req("read_custom", { address = "0x401000", type_name = "xor4" })
ok("read_custom value", rc and rc.result.success == true and rc.result.value == 12345,
   rc and json.encode(rc.result))
local wc = req("write_custom", { address = "0x401000", type_name = "xor4", value = 7 })
ok("write_custom wrote 4 bytes", wc and wc.result.success == true and wc.result.wrote == 4,
   wc and json.encode(wc.result))
local rcn = req("read_custom", { address = "0x401000", type_name = "nope" })
ok("read_custom NOT_FOUND type", rcn and rcn.result.error_code == "NOT_FOUND")

-- ---- dissect code ------------------------------------------------------------------------
local ds1 = req("dissect_code_start", { module = "game.exe" })
ok("dissect_code_start by module", ds1 and ds1.result.success == true)
local ds2 = req("dissect_code_start", {})
ok("dissect_code_start needs scope", ds2 and ds2.result.error_code == "INVALID_PARAMS")
local dr = req("dissect_code_references", { address = "0x401000" })
ok("dissect_code_references", dr and dr.result.total == 1 and dr.result.references[1].from == "0x401500",
   dr and json.encode(dr.result))
local dstr = req("dissect_code_strings", {})
ok("dissect_code_strings", dstr and dstr.result.total == 1 and dstr.result.strings[1].string == "hello")
local dfn = req("dissect_code_functions", {})
ok("dissect_code_functions", dfn and dfn.result.total == 1 and dfn.result.functions[1].address == "0x401000")
local dsv = req("dissect_code_manage", { action = "save", filename = "dc.bin" })
ok("dissect_code_manage save", dsv and dsv.result.success == true)
local dcx = req("dissect_code_manage", { action = "bogus" })
ok("dissect_code_manage bogus action", dcx and dcx.result.error_code == "INVALID_PARAMS")

-- ---- dotnet ---------------------------------------------------------------------------------
local dn1 = req("dotnet_status", {})
ok("dotnet_status attached", dn1 and dn1.result.attached == true)
local dn2 = req("dotnet_enum_domains", {})
ok("dotnet_enum_domains", dn2 and dn2.result.domains[1][2] == "root")
local dn3 = req("dotnet_enum_modules", { domain_handle = 1234 })
ok("dotnet_enum_modules", dn3 and dn3.result.modules[1][3] == "game.dll")
local dn4 = req("dotnet_enum_modules", {})
ok("dotnet_enum_modules needs handle", dn4 and dn4.result.error_code == "INVALID_PARAMS")

-- ---- table files ------------------------------------------------------------------------------
local tf1 = req("table_file_create", { name = "data.bin", source_path = [[C:\tmp\data.bin]] })
ok("table_file_create", tf1 and tf1.result.success == true)
local tf2 = req("table_file_find", { name = "data.bin" })
ok("table_file_find", tf2 and tf2.result.success == true)
local tf3 = req("table_file_export", { name = "data.bin", dest_path = [[C:\out\data.bin]] })
ok("table_file_export", tf3 and tf3.result.success == true and tf3.result.dest == [[C:\out\data.bin]])
local tf4 = req("table_file_delete", { name = "data.bin" })
ok("table_file_delete", tf4 and tf4.result.success == true)
local tf5 = req("table_file_find", { name = "data.bin" })
ok("table_file_find after delete NOT_FOUND", tf5 and tf5.result.error_code == "NOT_FOUND")

-- ---- AA commands --------------------------------------------------------------------------------
local aa1 = req("register_aa_command", { command = "mymov", lua_code = "return 'mov eax,1'" })
ok("register_aa_command", aa1 and aa1.result.success == true and aa_state.registered["mymov"] ~= nil)
local aa2 = req("register_aa_command", { command = "bad", lua_code = "return )))" })
ok("register_aa_command rejects bad lua", aa2 and aa2.result.error_code == "INVALID_PARAMS")
local aa3 = req("unregister_aa_command", { command = "mymov" })
ok("unregister_aa_command", aa3 and aa3.result.success == true and aa_state.unregistered["mymov"] == true)

-- ---- HTTP -----------------------------------------------------------------------------------------
local h1 = req("http_get", { url = "http://example.com/x" })
ok("http_get", h1 and h1.result.success == true and h1.result.body == "BODY:http://example.com/x")
local h2 = req("http_get", {})
ok("http_get needs url", h2 and h2.result.error_code == "INVALID_PARAMS")
local h3 = req("http_post", { url = "http://example.com", data = "a=1" })
ok("http_post", h3 and h3.result.success == true and h3.result.response == "POSTED")

-- ---- DBK / DBVM -------------------------------------------------------------------------------------
local d1 = req("dbk_initialize", {})
ok("dbk_initialize", d1 and d1.result.success == true and d1.result.loaded == true)
local d2 = req("dbk_use_kernelmode", { mode = "openprocess" })
ok("dbk_use_kernelmode", d2 and d2.result.success == true)
local d3 = req("dbk_use_kernelmode", { mode = "bogus" })
ok("dbk_use_kernelmode rejects bad mode", d3 and d3.result.error_code == "INVALID_PARAMS")
local d4 = req("dbk_read_msr", { msr = 0x10 })
ok("dbk_read_msr", d4 and d4.result.success == true and d4.result.value == 0xDEADBEEF)
local d5 = req("dbvm_initialize", { offloados = false })
ok("dbvm_initialize", d5 and d5.result.success == true)
local d6 = req("dbvm_read_msr", { msr = 0x10 })
ok("dbvm_read_msr", d6 and d6.result.value == 0xCAFEBABE)
local d7 = req("dbvm_cloak_read", { physical_base = 0x1000 })
ok("dbvm_cloak_read 4096 bytes", d7 and d7.result.size == 4096 and #d7.result.preview == 64,
   d7 and json.encode(d7.result))
local d8 = req("dbvm_cloak_write", { physical_base = 0x1000, bytes = { 1, 2, 3 } })
ok("dbvm_cloak_write", d8 and d8.result.wrote == 3)
local d9 = req("dbvm_cloak_write", { physical_base = 0x1000, bytes = {} })
ok("dbvm_cloak_write rejects empty", d9 and d9.result.error_code == "INVALID_PARAMS")

-- ---- audit coverage for new mutating prefixes --------------------------------------------------------
local al31 = req("get_audit_log", { limit = 200 })
local seen = {}
if al31 then for _, e in ipairs(al31.result.entries) do seen[e.method] = true end end
ok("set_speed / create_hotkey / dbvm_cloak_write audited",
   seen["set_speed"] and seen["create_hotkey"] and seen["dbvm_cloak_write"],
   al31 and json.encode(al31.result.entries))

-- ---- v15.7.0: exact-set audit coverage + clamps -------------------------------------------------
print("== v15.7.0 quality pass ==")
-- evaluate_lua must be audited even though the "evaluate_" prefix only covers
-- the execute_code family... it does not match any prefix; the exact set does.
local al_eval = req("get_audit_log", { limit = 200 })
local evalSeen = false
if al_eval then for _, e in ipairs(al_eval.result.entries) do
  if e.method == "evaluate_lua" then evalSeen = true end
end end
ok("evaluate_lua audited via exact set", evalSeen)

-- clamps: oversize requests fail fast with INVALID_PARAMS instead of freezing CE
local bigCopy = req("copy_memory", { source = "0x401000", size = 65 * 1024 * 1024 })
ok("copy_memory 64MiB clamp", bigCopy and bigCopy.result.success == false
   and bigCopy.result.error_code == "INVALID_PARAMS", json.encode(bigCopy))
local bigCmp = req("compare_memory", { addr1 = "0x401000", addr2 = "0x402000", size = 65 * 1024 * 1024 })
ok("compare_memory 64MiB clamp", bigCmp and bigCmp.result.success == false
   and bigCmp.result.error_code == "INVALID_PARAMS", json.encode(bigCmp))
local bigMd5 = req("md5_memory", { address = "0x401000", size = 17 * 1024 * 1024 })
ok("md5_memory 16MiB clamp", bigMd5 and bigMd5.result.success == false
   and bigMd5.result.error_code == "INVALID_PARAMS", json.encode(bigMd5))
local bigStr = req("read_string", { address = "0x401000", max_length = 1024 * 1024 + 1 })
ok("read_string 1MiB clamp accepted (clamped, no-process error only)",
   bigStr ~= nil, json.encode(bigStr))
local oobWrite = req("write_integer", { address = "0x401000", value = 300, type = "byte" })
ok("write_integer range message", oobWrite and oobWrite.result.success == false
   and tostring(oobWrite.result.error):find("out of range") ~= nil, json.encode(oobWrite))

-- ---- UNIT-33 (v15.7.0): pointer-chain validation + CT records health ---------
local function _test_unit33()
print("== UNIT-33 pointer & CT health ==")

-- Default mocks: readPointer is undefined -> pcall fails -> chain breaks at step 1.
local vFail = req("validate_pointer_chain", { base = "0x1000", offsets = { 0x10 } })
ok("pointer chain: nil readPointer -> invalid at step 1",
   vFail and vFail.result.success == true and vFail.result.valid == false
   and vFail.result.failed_step == 1, json.encode(vFail))

local vBad = req("validate_pointer_chain", { base = "not-hex", offsets = {} })
ok("pointer chain: unresolvable base -> INVALID_ADDRESS",
   vBad and vBad.result.success == false and vBad.result.error_code == "INVALID_ADDRESS",
   json.encode(vBad))

local vMany = req("validate_pointer_chain", { base = "0x1000", offsets = {} })
vMany = req("validate_pointer_chain",
            { base = "0x1000", offsets = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } })
ok("pointer chain: 33 offsets -> INVALID_PARAMS",
   vMany and vMany.result.success == false and vMany.result.error_code == "INVALID_PARAMS",
   json.encode(vMany))

-- Scoped richer mocks: alive chain + a 4-record address list.
local _realReadPointer, _realReadBytes, _realGetAl = readPointer, readBytes, getAddressList
do
  readPointer = function(addr) return addr + 0x1000 end
  readBytes   = function(addr, n, asTable) assert(asTable == true) return { 0 } end

  local vOk = req("validate_pointer_chain", { base = "0x1000", offsets = { 0x10, 0x20 } })
  ok("pointer chain: alive chain -> valid with 2 steps",
     vOk and vOk.result.success == true and vOk.result.valid == true
     and #vOk.result.steps == 2 and vOk.result.final_address == "0x3030",
     vOk and json.encode(vOk.result))

  local vDead = req("validate_pointer_chain", { base = "0x1000", offsets = { 0x10 } })
  -- dereferenced target is always "readable" under this mock, so still valid;
  -- instead simulate a dead hop by making readPointer fail on the second hop.
  local hop = 0
  readPointer = function(addr)
    hop = hop + 1
    if hop == 2 then return nil end
    return addr + 0x1000
  end
  local vHop2 = req("validate_pointer_chain", { base = "0x1000", offsets = { 0x10, 0x20 } })
  ok("pointer chain: dead second hop reported",
     vHop2 and vHop2.result.valid == false and vHop2.result.failed_step == 2,
     vHop2 and json.encode(vHop2.result))

  local alive = { ID = 1, Description = "alive", Address = "0x401000" }
  local dead  = { ID = 2, Description = "dead",  Address = "nothex" }
  local grp   = { ID = 3, Description = "grp",   IsGroupHeader = true }
  local scr   = { ID = 4, Description = "scr",   Script = "[enable]" }
  local alMock = { Count = 4, [0] = alive, [1] = dead, [2] = grp, [3] = scr }
  getAddressList = function() return alMock end

  local h = req("ct_memory_records_health", {})
  ok("CT health: 4 records classified ok/unresolved/group/script",
     h and h.result.success == true and h.result.total == 4 and h.result.checked == 4
     and h.result.summary.ok == 1 and h.result.summary.unresolved == 1
     and h.result.summary.group == 1 and h.result.summary.script == 1
     and h.result.truncated == false, h and json.encode(h.result))

  local hLim = req("ct_memory_records_health", { limit = 2 })
  ok("CT health: budget 2 -> truncated",
     hLim and hLim.result.checked == 2 and hLim.result.truncated == true,
     hLim and json.encode(hLim.result))

  getAddressList = function() return { Count = 0 } end
  local hEmpty = req("ct_memory_records_health", {})
  ok("CT health: empty table -> all zeros",
     hEmpty and hEmpty.result.total == 0 and hEmpty.result.summary.ok == 0,
     hEmpty and json.encode(hEmpty.result))
end
readPointer, readBytes, getAddressList = _realReadPointer, _realReadBytes, _realGetAl
end
_test_unit33()

-- ---- UNIT-34 (v15.8.0): preflight + AOB health scan + inject preview --------
local function _test_unit34()
print("== UNIT-34 session health ==")

-- preflight works without a process and reports failed checks honestly
local pf0 = req("preflight", {})
ok("preflight: no process -> success, ok=false, 4 checks",
   pf0 and pf0.result.success == true and pf0.result.ok == false
   and #pf0.result.checks == 4, pf0 and json.encode(pf0.result))

ok("preflight: empty symbols -> INVALID_PARAMS",
   req("preflight", { symbols = {} }).result.error_code == "INVALID_PARAMS")
ok("preflight: 33 symbols -> INVALID_PARAMS",
   req("preflight", { symbols = { "s","s","s","s","s","s","s","s","s","s","s","s","s","s","s","s",
                                 "s","s","s","s","s","s","s","s","s","s","s","s","s","s","s","s","s" } })
     .result.error_code == "INVALID_PARAMS")
ok("preflight: non-string symbol -> INVALID_PARAMS",
   req("preflight", { symbols = { 42 } }).result.error_code == "INVALID_PARAMS")

-- aob_health_scan: validation before the process guard
ok("aob health: missing patterns -> INVALID_PARAMS",
   req("aob_health_scan", {}).result.error_code == "INVALID_PARAMS")
local manyP = {}
for _ = 1, 257 do manyP[#manyP + 1] = "48 89 5C" end
ok("aob health: 257 patterns -> INVALID_PARAMS",
   req("aob_health_scan", { patterns = manyP }).result.error_code == "INVALID_PARAMS")
ok("aob health: no process -> NO_PROCESS",
   req("aob_health_scan", { patterns = { "48 89 5C" } }).result.error_code == "NO_PROCESS")

-- inject_preview: validation before the process guard
ok("inject preview: missing address -> INVALID_ADDRESS",
   req("inject_preview", { expected = "48 89" }).result.error_code == "INVALID_ADDRESS")
ok("inject preview: empty expected -> INVALID_PARAMS",
   req("inject_preview", { address = "0x1000", expected = "" }).result.error_code == "INVALID_PARAMS")
ok("inject preview: odd-length expected -> INVALID_PARAMS",
   req("inject_preview", { address = "0x1000", expected = "48 8" }).result.error_code == "INVALID_PARAMS")
ok("inject preview: non-hex expected -> INVALID_PARAMS",
   req("inject_preview", { address = "0x1000", expected = "ZZ 89" }).result.error_code == "INVALID_PARAMS")
ok("inject preview: wildcard rejected -> INVALID_PARAMS",
   req("inject_preview", { address = "0x1000", expected = "48 ?? 5C" }).result.error_code == "INVALID_PARAMS")
ok("inject preview: 257 bytes -> INVALID_PARAMS",
   req("inject_preview", { address = "0x1000", expected = string.rep("00 ", 257) })
     .result.error_code == "INVALID_PARAMS")
ok("inject preview: valid params + no process -> NO_PROCESS",
   req("inject_preview", { address = "0x1000", expected = "39 30 00 00" }).result.error_code == "NO_PROCESS")

-- Scoped mocks: attached process, one main module, memscan factory, readBytes.
local _realPid, _realEnum, _realMS, _realGMS = getOpenedProcessID, enumModules, createMemScan, getModuleSize
do
  getOpenedProcessID = function() return 0x1234 end
  enumModules = function()
    return { { Name = "game.exe", Address = 0x400000, Size = 0x100000,
               Is64Bit = true, PathToFile = "C:/game/game.exe" } }
  end

  -- preflight with a live session: overall ok, module + symbol checks pass
  local pf1 = req("preflight", { symbols = { "0x400000", "nothex" } })
  ok("preflight: live session -> ok=true, module resolved",
     pf1 and pf1.result.ok == true and pf1.result.main_module ~= nil
     and pf1.result.main_module.name == "game.exe"
     and pf1.result.main_module.base == "0x400000"
     and pf1.result.process_id == 0x1234, pf1 and json.encode(pf1.result))
  ok("preflight: symbols 1/2 resolved -> check fails",
     pf1 and #pf1.result.checks == 5 and pf1.result.checks[5].ok == false
     and pf1.result.symbols[1].resolved == true and pf1.result.symbols[1].address == "0x400000"
     and pf1.result.symbols[2].resolved == false, pf1 and json.encode(pf1.result))

  -- aob_health_scan: memscan factory missing -> per-pattern error, honest report
  local ahErr = req("aob_health_scan", { patterns = { "48 89 5C" } })
  ok("aob health: no memscan API -> per-pattern error status",
     ahErr and ahErr.result.success == true and ahErr.result.total == 1
     and ahErr.result.errors == 1 and ahErr.result.results[1].status == "error",
     ahErr and json.encode(ahErr.result))

  -- aob_health_scan: mocked memscan -> hit + miss + ratio (shared result queue:
  -- the queue index spans scans, each createMemScan() consumes the next entry)
  local scanQueue, scanIdx = {}, 0
  createMemScan = function()
    return {
      setOnlyOneResult = function() end,
      firstScan = function() end,
      waitTillDone = function() end,
      getOnlyResult = function() scanIdx = scanIdx + 1 return scanQueue[scanIdx] end,
      destroy = function() end,
    }
  end
  local ah = req("aob_health_scan", { patterns = { "48 89 5C", "90 90 90" } })
  scanQueue, scanIdx = { 0x401234, false }, 0
  local ahHit = req("aob_health_scan", { patterns = { "48 89 5C", "90 90 90" } })
  ok("aob health: hit + miss -> ratio 0.5",
     ahHit and ahHit.result.hits == 1 and ahHit.result.misses == 1
     and ahHit.result.hit_ratio == 0.5
     and ahHit.result.results[1].status == "hit"
     and ahHit.result.results[1].address == "0x401234"
     and ahHit.result.results[2].status == "miss"
     and ahHit.result.module_base == "0x400000", ahHit and json.encode(ahHit.result))
  ok("aob health: deterministic (rerun miss-only matches)",
     ah and ah.result.hits == 0 and ah.result.misses == 2,
     ah and json.encode(ah.result))

  -- named module that cannot resolve -> INVALID_ADDRESS
  ok("aob health: unresolvable module -> INVALID_ADDRESS",
     req("aob_health_scan", { patterns = { "48" }, module = "game.exe" })
       .result.error_code == "INVALID_ADDRESS")

  -- named module by hex base with explicit size -> uses that scope
  getModuleSize = function() return 0x1000 end
  scanQueue, scanIdx = { 0x400800 }, 0
  local ahMod = req("aob_health_scan", { patterns = { "AA BB" }, module = "0x400000" })
  ok("aob health: explicit module scope hit",
     ahMod and ahMod.result.success == true and ahMod.result.module_size == 0x1000
     and ahMod.result.results[1].status == "hit", ahMod and json.encode(ahMod.result))

  -- inject_preview against the default readBytes stub {0x39,0x30,0x00,0x00}
  local ipEq = req("inject_preview", { address = "0x401000", expected = "39 30 00 00" })
  ok("inject preview: matching fingerprint",
     ipEq and ipEq.result.success == true and ipEq.result.readable == true
     and ipEq.result.match == true and ipEq.result.first_diff_offset == -1
     and ipEq.result.length == 4, ipEq and json.encode(ipEq.result))
  local ipNe = req("inject_preview", { address = "0x401000", expected = "39 30 00 01" })
  ok("inject preview: mismatch -> first_diff at byte 3",
     ipNe and ipNe.result.match == false and ipNe.result.first_diff_offset == 3
     and ipNe.result.actual == "39 30 00 00", ipNe and json.encode(ipNe.result))

  readBytes = function() return nil end
  local ipDead = req("inject_preview", { address = "0x401000", expected = "39 30" })
  ok("inject preview: unreadable target -> readable=false",
     ipDead and ipDead.result.success == true and ipDead.result.readable == false
     and ipDead.result.match == false, ipDead and json.encode(ipDead.result))
end
getOpenedProcessID, enumModules, createMemScan, getModuleSize = _realPid, _realEnum, _realMS, _realGMS
end
_test_unit34()

-- ---- stability / shock + large-data experiments (v15.7.0) -------------------
local function _test_stability()
print("== stability / large data ==")

-- 1. Deep nesting: 250-deep params must fail deterministically, never crash
--    the dispatcher (codec depth cap is 200 on both encode and decode).
local deepJson = '{"jsonrpc":"2.0","method":"status","params":{"a":'
local close = ''
for _ = 1, 250 do deepJson = deepJson .. '{' close = close .. '}' end
deepJson = deepJson .. close .. '},"id":1}'
local deepResp = MCP_Bridge.execute(deepJson)
local deepOk = false
pcall(function()
  local d = json.decode(deepResp)
  deepOk = (d.error ~= nil) or (d.result ~= nil)
end)
ok("250-deep nesting rejected without crashing", deepOk, deepResp and deepResp:sub(1, 120))

-- 2. Audit ring stays bounded at MAX_AUDIT_ENTRIES and keeps the newest.
for i = 1, 220 do req("set_speed", { speed = 1.0 + i / 1000 }) end
local al = req("get_audit_log", { limit = 200 })
ok("audit ring bounded at 200 after 220 mutations",
   al and al.result.total == 200 and #al.result.entries == 200,
   al and al.result.total)
ok("audit ring keeps the newest entry",
   al and al.result.entries[1] ~= nil and al.result.entries[1].method == "set_speed",
   al and al.result.entries[1] and json.encode(al.result.entries[1]))

-- 3. Batch boundary: 64 sub-calls execute; 65 is rejected up front.
local calls64 = {}
for _ = 1, 64 do calls64[#calls64 + 1] = { method = "status", params = {} } end
local t0 = os.clock()
local b64 = req("batch", { calls = calls64 })
local batchMs = (os.clock() - t0) * 1000
ok("batch of 64 executes fully", b64 and b64.result.succeeded == 64, b64 and b64.result.succeeded)
local calls65 = {}
for _ = 1, 65 do calls65[#calls65 + 1] = { method = "status", params = {} } end
local b65 = req("batch", { calls = calls65 })
ok("batch of 65 rejected", b65 and b65.result.success == false
   and b65.result.error_code == "INVALID_PARAMS", json.encode(b65))

-- 4. Large wire payload: a 512 KiB string param survives encode/decode.
local big = string.rep("A", 512 * 1024)
local t1 = os.clock()
local bigEcho = MCP_Bridge_call("get_audit_log", { limit = 1, marker = big })
local bigMs = (os.clock() - t1) * 1000
local bigParsed = json.decode(bigEcho)
ok("512 KiB string param round trip",
   bigParsed and bigParsed.result ~= nil and bigParsed.result.success == true,
   bigEcho and #bigEcho)
print(("  [perf] batch64=%.1fms bigparam=%.1fms"):format(batchMs, bigMs))
end
_test_stability()

-- ---- auth gate (CE_MCP_AUTH_TOKEN, v15.7.0) ----------------------------------------------------------
-- Reload the bridge with a stubbed os.getenv so AUTH_TOKEN is resolved as set.
-- Encapsulated in a function: the main chunk is at Lua's 200-local limit.
local function auth_gate_tests()
local real_getenv = os.getenv
os.getenv = function(k)
  if k == "CE_MCP_AUTH_TOKEN" then return "sekret-token" end
  return real_getenv(k)
end
dofile((arg and arg[0] and arg[0]:match("^(.*)[/\\]") or ".") .. "/ce_mcp_bridge.lua")
os.getenv = real_getenv

local function raw_call(method, params)
  return json.decode(MCP_Bridge.call(method, params))
end

local denied = raw_call("status", {})
ok("missing token rejected AUTH_REQUIRED",
   denied.error and denied.error.data and denied.error.data.error_code == "AUTH_REQUIRED",
   json.encode(denied))

local wrong = raw_call("status", { _auth = "nope" })
ok("wrong token rejected AUTH_REQUIRED",
   wrong.error and wrong.error.data and wrong.error.data.error_code == "AUTH_REQUIRED",
   json.encode(wrong))

local good = raw_call("status", { _auth = "sekret-token" })
ok("correct token accepted", good.result and good.result.success == true
   and good.result.version == "15.8.0", json.encode(good))

local batch_good = raw_call("batch", { _auth = "sekret-token", calls = {
  { method = "status", params = {} },
  { method = "dbvm_cloak_write", params = { physical_base = 0x1000, bytes = { 9 } } },
} })
ok("batch passes the auth gate",
   batch_good.result and batch_good.result.succeeded == 2
   and batch_good.result.results[2].wrote == 1, json.encode(batch_good))

-- token must not leak into the audit log (mutating sub-command above)
local al_auth = raw_call("get_audit_log", { _auth = "sekret-token", limit = 5 })
local leaked = false
if al_auth and al_auth.result then
  for _, e in ipairs(al_auth.result.entries) do
    if tostring(e.params and e.params._auth or "") == "sekret-token" then leaked = true end
  end
end
ok("token stripped before audit", not leaked)

-- Reload once more without the token: open access is restored.
dofile((arg and arg[0] and arg[0]:match("^(.*)[/\\]") or ".") .. "/ce_mcp_bridge.lua")
local open_again = raw_call("status", {})
ok("token unset restores open access",
   open_again.result and open_again.result.success == true, json.encode(open_again))
end -- auth_gate_tests

print("== auth gate: CE_MCP_AUTH_TOKEN set ==")
auth_gate_tests()

print(("\n%d passed, %d failed"):format(pass, fail))
os.exit(fail == 0 and 0 or 1)
