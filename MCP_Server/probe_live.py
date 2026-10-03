import json
import mcp_cheatengine as ce

def show(name, d):
    if isinstance(d, (str, bytes)):
        try:
            d = json.loads(d)
        except Exception:
            print(f"  {name}: NON-JSON -> {str(d)[:120]}")
            return None
    print(f"  {name}: {json.dumps(d, ensure_ascii=False)[:260]}")
    return d

print("== 0) fastpath existence (needs new DLL in CE plugins) ==")
for m in ("dll_ping", "dll_status", "dll_enum_dialogs"):
    r = ce.call(m)
    ok = not (isinstance(r, dict) and r.get("error_code") == "METHOD_NOT_FOUND")
    print(f"  {m}: {'PRESENT (fastpath)' if ok else 'MISSING (old DLL)'}")

print("== 1) preflight detail ==")
pf = ce.call("preflight", {"symbols": ["Baba Is You.exe+0", "\"Baba Is You.exe\"+0", "no-such-sym"]})
show("preflight", pf)
if pf:
    print(f"  ok={pf.get('ok')}  game_version={pf.get('game_version')}  table={pf.get('table_path')}")
    print(f"  symbols: {json.dumps(pf.get('symbols'), ensure_ascii=False)}")

base = (pf or {}).get("main_module", {}).get("base")
print(f"== 2) inject_preview @ {base} ==")
exp = "4D 5A 90 00"
ip  = show("expect==actual", ce.call("inject_preview", {"address": base, "expected": exp}))
ip2 = show("expect!=actual", ce.call("inject_preview", {"address": base, "expected": "90 90 90 90"}))
ip3 = show("wildcard", ce.call("inject_preview", {"address": base, "expected": "4D ?? 90 00"}))

print("== 3) aob_health_scan (protection +W covers PE header) ==")
ah = show("MZ+garbage @+W", ce.call("aob_health_scan", {"patterns": ["4D 5A 90 00", "DE AD BE EF 12 34"], "protection": "-W"}))

print("== 4) validate_pointer_chain (numeric base) ==")
vc = show("chain", ce.call("validate_pointer_chain", {"base": base, "offsets": [16, 0]}))

print("== summary ==")
verdicts = {
    "preflight ok": pf and pf.get("ok") is True,
    "preflight game_version": bool(pf and pf.get("game_version")),
    "preflight symbol resolved (quoted or plain)": bool(pf and any(s.get("resolved") for s in pf.get("symbols", []))),
    "inject match": ip and ip.get("match") is True,
    "inject mismatch": ip2 and ip2.get("match") is False and ip2.get("first_diff_offset") == 0,
    "inject wildcard rejected": ip3 and ip3.get("success") is False,
    "aob MZ hit(-W) + garbage miss": ah and ah.get("hits") == 1 and ah.get("misses") == 1,
    "pointer chain honest semantics": vc and vc.get("success") is True and isinstance(vc.get("valid"), bool),
    "NEW_DLL_FASTPATH": all(not (isinstance(ce.call(m), dict) and ce.call(m).get("error_code") == "METHOD_NOT_FOUND")
                            for m in ("dll_ping",)),
}
for k, v in verdicts.items():
    print(f"  [{'PASS' if v else 'FAIL'}] {k}")
