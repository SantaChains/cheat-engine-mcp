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
ok("version is 15.4.2", MCP_Bridge.version == "15.4.2", MCP_Bridge.version)
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
ok("status ok", st and st.result.success == true and st.result.version == "15.4.2")
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
ok("prefix filter", lmp and lmp.result.total == 4 and lmp.result.methods[1] == "dbk_get_cr0",
   lmp and lmp.result.total)
ok("status alias bridge_status", req("bridge_status").result.version == "15.4.2")
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

print(("\n%d passed, %d failed"):format(pass, fail))
os.exit(fail == 0 and 0 or 1)
