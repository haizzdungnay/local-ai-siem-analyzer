"""
eval/demo_lite.py — trang demo tĩnh "trước/sau playbook" + kết quả smoke LoRA, KHÔNG cần bật lab.

Đọc kết quả có sẵn và xuất một file HTML tự chứa (không CDN, mở offline bằng trình duyệt):
  - A/B playbook: eval/raw_exports/smoke/playbook-ab.json (do eval/playbook_ab_smoke.py tạo)
  - Smoke LoRA (tùy chọn): research/training/outputs/<run>-smoke/run_manifest.json

    python eval/demo_lite.py
    python eval/demo_lite.py --ab eval/raw_exports/smoke/playbook-ab.json \
        --manifest research/training/outputs/qwen35-9b-pentest-soc-qlora-v1-smoke/run_manifest.json
    # muốn chạy lại A/B trước (chỉ cần Ollama, không cần Wazuh/VM):
    python eval/playbook_ab_smoke.py && python eval/demo_lite.py

IPv4 được thay bằng nhãn (IP-1, IP-2…) trước khi ghi HTML. Output mặc định nằm trong
eval/raw_exports/demo/ (gitignored). Đây là minh họa N=1, không phải kết quả đánh giá.
"""
import argparse
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AB = ROOT / "eval" / "raw_exports" / "smoke" / "playbook-ab.json"
DEFAULT_OUT = ROOT / "eval" / "raw_exports" / "demo" / "demo-lite.html"
DEFAULT_MANIFEST = (ROOT / "research" / "training" / "outputs"
                    / "qwen35-9b-pentest-soc-qlora-v1-smoke" / "run_manifest.json")

IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
RULE_ID = re.compile(r"\b(?:rule\s*)?(5\d{3}|40\d{3}|31\d{3}|55[0-4]|50[0-9]|510)\b", re.I)


class Masker:
    """Thay IPv4 bằng nhãn ổn định trong toàn trang (cùng IP -> cùng nhãn)."""

    def __init__(self):
        self.map: dict[str, str] = {}

    def __call__(self, text) -> str:
        if not isinstance(text, str):
            text = json.dumps(text, ensure_ascii=False) if text is not None else ""
        return IPV4.sub(self._label, text)

    def _label(self, m: re.Match) -> str:
        return self.map.setdefault(m.group(0), f"IP-{len(self.map) + 1}")


def evidence(step: str, masked: str) -> dict:
    """Bước có bám bằng chứng không: có rule ID / có giá trị cụ thể (IP, user, agent) từ alert."""
    return {"rule": bool(RULE_ID.search(step)), "value": "IP-" in masked or "agent" in step.lower()}


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def column(label: str, tag: str, res: dict, mask: Masker) -> tuple[str, dict]:
    an = res.get("analysis") or {}
    steps = an.get("next_steps") or []
    rows, n_rule, n_val = [], 0, 0
    for s in steps:
        m = mask(s)
        ev = evidence(s, m)
        n_rule += ev["rule"]
        n_val += ev["value"]
        badges = "".join(f'<span class="tag {"ok" if ok else "no"}">{name}</span>'
                         for name, ok in (("rule ID", ev["rule"]), ("giá trị alert", ev["value"])))
        rows.append(f"<li><div>{esc(m)}</div><div class='badges'>{badges}</div></li>")
    mitre = ", ".join(an.get("mitre") or []) or "—"
    stats = {"steps": len(steps), "rule": n_rule, "value": n_val}
    body = f"""
    <section class="col {tag}">
      <header><span class="pill">{esc(label)}</span>
        <span class="meta">severity <b>{esc(str(an.get('severity', '—')))}</b> · MITRE {esc(mitre)}
        · confidence {esc(str(an.get('confidence', '—')))}</span></header>
      <p class="summary">{esc(mask(an.get('summary', '')))}</p>
      <h4>next_steps ({len(steps)})</h4>
      <ol>{''.join(rows) or '<li><i>không có</i></li>'}</ol>
      <p class="foot">{n_rule}/{len(steps)} bước có rule ID · {n_val}/{len(steps)} bước có giá trị từ alert</p>
    </section>"""
    return body, stats


def loss_svg(history: list[dict]) -> str:
    pts = [(h["step"], h["loss"]) for h in history if "loss" in h and "step" in h]
    if len(pts) < 2:
        return ""
    w, h, pad = 320, 120, 24
    xs, ys = [p[0] for p in pts], [p[1] for p in pts]
    x0, x1, y1 = min(xs), max(xs), max(ys) * 1.1
    def px(x): return pad + (x - x0) / ((x1 - x0) or 1) * (w - 2 * pad)
    def py(y): return h - pad - y / y1 * (h - 2 * pad)
    line = " ".join(f"{px(x):.1f},{py(y):.1f}" for x, y in pts)
    dots = "".join(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="3"/>' for x, y in pts)
    return (f'<svg viewBox="0 0 {w} {h}" class="loss" role="img" aria-label="loss theo step">'
            f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" class="axis"/>'
            f'<polyline points="{line}"/>{dots}'
            f'<text x="{pad}" y="14">loss {ys[0]:.2f} → {ys[-1]:.2f}</text>'
            f'<text x="{w-pad}" y="{h-6}" text-anchor="end">step {x0}–{x1}</text></svg>')


def manifest_card(path: Path) -> str:
    m = json.loads(path.read_text(encoding="utf-8"))
    cfg = m.get("config") or {}
    hist = m.get("log_history") or []
    steps = max((h.get("step", 0) for h in hist), default=0) or 5
    wall = float(m.get("wall_seconds") or 0)
    init = cfg.get("init_adapter") or {}
    rows = [
        ("Base model", cfg.get("base_model", "—")),
        ("Adapter khởi đầu", f"{init.get('repo', '—')} @ {str(init.get('revision', ''))[:7]}" if init else "—"),
        ("Mẫu train (smoke)", f"{m.get('train_examples')} mẫu giả"),
        ("VRAM đỉnh", f"{m.get('peak_vram_gb')} GB"),
        ("Thời gian", f"{wall:.0f} s · ~{wall / steps:.1f} s/step"),
        ("GPU / torch", f"{m.get('gpu')} · {m.get('torch')}"),
    ]
    tr = "".join(f"<tr><th>{esc(k)}</th><td>{esc(str(v))}</td></tr>" for k, v in rows)
    return f"""
    <section class="card">
      <h2>2. LoRA trên Qwen3.5-9B-Pentest — chạy thử pipeline</h2>
      <div class="grid2"><table>{tr}</table>{loss_svg(hist)}</div>
      <p class="note">Smoke test trên dữ liệu giả: chứng minh nạp model 4-bit + adapter pentest và train tiếp
      được (loss giảm). Chưa train trên dữ liệu SOC, chưa đo chất lượng.</p>
    </section>"""


CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e2dd;--a:#b4532a;--b:#2a6f5b;
--ok:#2a6f5b;--no:#a33;--okbg:#e4f1ec;--nobg:#f7e3e3}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#171716;--fg:#ecebe6;--mut:#a3a29c;
--card:#21211f;--line:#34332f;--a:#e08a5f;--b:#6cc2a6;--ok:#6cc2a6;--no:#e88;--okbg:#1d332c;--nobg:#3a2222}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:0 0 12px}h4{margin:14px 0 6px;font-size:13px;
text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
.sub{color:var(--mut);margin:0 0 22px}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:18px;margin-bottom:18px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;
font-size:12.5px;margin:0}
.ab{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:820px){.ab,.grid2{grid-template-columns:1fr}}
.col{border:1px solid var(--line);border-radius:10px;padding:14px;border-top:4px solid var(--a)}
.col.b{border-top-color:var(--b)}.col header{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.pill{font-weight:700}.col.a .pill{color:var(--a)}.col.b .pill{color:var(--b)}
.meta{color:var(--mut);font-size:13px}.summary{margin:10px 0 0}
ol{padding-left:20px;margin:0}li{margin:0 0 10px}.badges{margin-top:3px}
.tag{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;margin-right:4px}
.tag.ok{background:var(--okbg);color:var(--ok)}.tag.no{background:var(--nobg);color:var(--no)}
.foot{color:var(--mut);font-size:13px;border-top:1px solid var(--line);padding-top:8px;margin:8px 0 0}
details{margin-top:12px}summary{cursor:pointer;color:var(--mut)}
.grid2{display:grid;grid-template-columns:1fr 340px;gap:16px;align-items:center}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);
font-size:14px;vertical-align:top}th{color:var(--mut);font-weight:500;width:38%}
svg.loss{width:100%;height:auto}svg.loss polyline{fill:none;stroke:var(--b);stroke-width:2}
svg.loss circle{fill:var(--b)}svg.loss .axis{stroke:var(--line)}svg.loss text{fill:var(--mut);font-size:11px}
.note{color:var(--mut);font-size:13.5px;margin:12px 0 0}
"""


def build(ab: dict, manifest: Path | None) -> str:
    mask = Masker()
    alert_path = Path(ab.get("alert", ""))
    alert_txt = ""
    if ab.get("alert") and alert_path.is_file():
        alert_txt = mask(json.dumps(json.loads(alert_path.read_text(encoding="utf-8")),
                                    ensure_ascii=False, indent=2))
    col_a, st_a = column("A — KHÔNG playbook", "a", ab.get("A_no_playbook") or {}, mask)
    col_b, st_b = column("B — CÓ playbook", "b", ab.get("B_playbook") or {}, mask)
    lora = manifest_card(manifest) if manifest and manifest.exists() else ""
    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Demo playbook IR</title>
<style>{CSS}</style></head><body><main>
<h1>Playbook IR: next_steps trước và sau</h1>
<p class="sub">Model {esc(ab.get('model', '—'))} · rule {esc(str(ab.get('rule_id', '—')))} ·
cùng alert, cùng prompt, chỉ khác có/không playbook · minh họa N=1, chưa phải kết quả đánh giá</p>
<section class="card"><h2>1. Cùng một alert, hai câu trả lời</h2>
<div class="ab">{col_a}{col_b}</div>
<p class="note">A: {st_a['rule']}/{st_a['steps']} bước có rule ID, {st_a['value']}/{st_a['steps']} có giá trị alert ·
B: {st_b['rule']}/{st_b['steps']} và {st_b['value']}/{st_b['steps']}. Nhãn đỏ là việc tiếp theo:
khối PLAYBOOK tin cậy riêng + bắt buộc trích rule ID và giá trị từ alert.</p>
<details><summary>Alert đầu vào</summary><pre>{esc(alert_txt) or 'không tìm thấy file alert'}</pre></details>
<details><summary>Playbook đưa vào context (rule {esc(str(ab.get('rule_id', '')))})</summary>
<pre>{esc(mask(ab.get('playbook_context', '')))}</pre></details>
</section>{lora}
</main></body></html>
"""


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Trang demo tĩnh A/B playbook + smoke LoRA")
    ap.add_argument("--ab", default=str(DEFAULT_AB))
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                    help="run_manifest.json của smoke LoRA; bỏ qua nếu không có")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    ab_path = Path(args.ab)
    if not ab_path.exists():
        sys.exit(f"!! Không thấy {ab_path}. Chạy trước: python eval/playbook_ab_smoke.py (chỉ cần Ollama)")
    ab = json.loads(ab_path.read_text(encoding="utf-8"))
    manifest = Path(args.manifest)
    if not manifest.exists():
        print(f"[!] Không thấy {manifest} — trang sẽ không có phần LoRA")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(ab, manifest), encoding="utf-8", newline="\n")
    print(f"[OK] {out}  (mở bằng trình duyệt, không cần mạng)")


if __name__ == "__main__":
    main()
