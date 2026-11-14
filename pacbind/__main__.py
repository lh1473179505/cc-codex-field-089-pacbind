"""CLI. inspect already works; admit is the piece to implement."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from pacbind.load import LoadError, load_json
def build_parser():
    p=argparse.ArgumentParser(prog="pacbind")
    sub=p.add_subparsers(dest="cmd", required=True)
    ins=sub.add_parser("inspect"); ins.add_argument("--bundle", required=True)
    adm=sub.add_parser("admit")
    adm.add_argument("--bundle", required=True); adm.add_argument("--policy", required=True)
    adm.add_argument("--keys", required=True); adm.add_argument("--report", required=True)
    return p
def main(argv=None)->int:
    args=build_parser().parse_args(argv)
    try: bundle=load_json(args.bundle)
    except (LoadError, OSError) as exc:
        print(f"failed to load bundle: {exc}", file=sys.stderr); return 2
    if args.cmd=="inspect":
        t=bundle.get("ticket") or {}
        print(json.dumps({"cname":t.get("cname"),"sname":t.get("sname"),"groups":(bundle.get("pac") or {}).get("groups")}, indent=2)); return 0
    try:
        policy=load_json(args.policy); keys=load_json(args.keys)
    except (LoadError, OSError) as exc:
        print(f"failed to load policy or keys: {exc}", file=sys.stderr); return 2
    from pacbind.engine import admit
    try: report=admit(bundle, policy, keys)
    except NotImplementedError as exc:
        print(str(exc), file=sys.stderr); return 2
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    d=str(report.get("decision","")).lower()
    if d=="allow": return 0
    if d=="deny": return 1
    print("report is missing a decision of allow or deny", file=sys.stderr); return 2
if __name__=="__main__":
    raise SystemExit(main())
