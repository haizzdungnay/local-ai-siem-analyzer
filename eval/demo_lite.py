"""
eval/demo_lite.py — trang demo tĩnh next_steps "trước/sau playbook", KHÔNG cần bật lab.

Đọc eval/raw_exports/smoke/playbook-ab.json (do eval/playbook_ab_smoke.py tạo) và xuất một
file HTML tự chứa (không CDN, mở offline bằng trình duyệt):

    python eval/demo_lite.py
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

IPV4 = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
VERIFY = re.compile(r"^\s*(kiểm tra|xác minh|xác định|đếm|tra cứu|truy vấn|tìm|check|verify|confirm)", re.I)
BRANCH = re.compile(r"^\s*(nếu|if)\b", re.I)
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
    return {"verify": bool(VERIFY.search(step)), "branch": bool(BRANCH.search(step)),
            "rule": bool(RULE_ID.search(step)), "value": "IP-" in masked or "agent" in step.lower()}


def esc(s: str) -> str:
    return html.escape(s, quote=True)


def column(label: str, tag: str, res: dict, mask: Masker) -> tuple[str, dict]:
    an = res.get("analysis") or {}
    steps = an.get("next_steps") or []
    rows, n = [], {"verify": 0, "branch": 0, "rule": 0, "value": 0}
    for s in steps:
        m = mask(s)
        ev = evidence(s, m)
        for k in n:
            n[k] += ev[k]
        # 2 nhãn đầu: cấu trúc điều tra (playbook cải thiện); 2 nhãn sau: bám bằng chứng (việc tiếp theo)
        badges = "".join(f'<span class="tag {cls}">{name}</span>'
                         for name, cls in (("bước xác minh", "ok" if ev["verify"] else "off"),
                                           ("nhánh điều kiện", "ok" if ev["branch"] else "off"),
                                           ("rule ID", "ok" if ev["rule"] else "no"),
                                           ("giá trị alert", "ok" if ev["value"] else "no")))
        rows.append(f"<li><div>{esc(m)}</div><div class='badges'>{badges}</div></li>")
    mitre = an.get("mitre") or "—"
    if isinstance(mitre, list):  # analyze_alert trả chuỗi, analyze_window trả list
        mitre = ", ".join(mitre) or "—"
    stats = {"steps": len(steps), **n}
    body = f"""
    <section class="col {tag}">
      <header><span class="pill">{esc(label)}</span>
        <span class="meta">severity <b>{esc(str(an.get('severity', '—')))}</b> · MITRE {esc(mitre)}</span></header>
      <p class="summary">{esc(mask(an.get('summary', '')))}</p>
      <h4>next_steps ({len(steps)})</h4>
      <ol>{''.join(rows) or '<li><i>không có</i></li>'}</ol>
      <p class="foot">{n['verify']}/{len(steps)} bước xác minh · {n['branch']} nhánh điều kiện ·
      {n['rule']}/{len(steps)} có rule ID · {n['value']}/{len(steps)} có giá trị từ alert</p>
    </section>"""
    return body, stats


CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--card:#fff;--line:#e3e2dd;--a:#b4532a;--b:#7a6a2a;--c:#2a6f5b;
--ok:#2a6f5b;--no:#a33;--okbg:#e4f1ec;--nobg:#f7e3e3}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#171716;--fg:#ecebe6;--mut:#a3a29c;
--card:#21211f;--line:#34332f;--a:#e08a5f;--b:#d4bc6a;--c:#6cc2a6;--ok:#6cc2a6;--no:#e88;--okbg:#1d332c;--nobg:#3a2222}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 48px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:0 0 12px}h4{margin:14px 0 6px;font-size:13px;
text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}
.sub{color:var(--mut);margin:0 0 22px}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:18px;margin-bottom:18px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;
font-size:12.5px;margin:0}
.ab{display:grid;grid-template-columns:repeat(var(--n),1fr);gap:14px}@media(max-width:900px){.ab{grid-template-columns:1fr}}
.col{border:1px solid var(--line);border-radius:10px;padding:14px;border-top:4px solid var(--a)}
.col.b{border-top-color:var(--b)}.col.c{border-top-color:var(--c)}.col header{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.pill{font-weight:700}.col.a .pill{color:var(--a)}.col.b .pill{color:var(--b)}.col.c .pill{color:var(--c)}
.meta{color:var(--mut);font-size:13px}.summary{margin:10px 0 0}
ol{padding-left:20px;margin:0}li{margin:0 0 10px}.badges{margin-top:3px}
.tag{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:999px;margin-right:4px}
.tag.ok{background:var(--okbg);color:var(--ok)}.tag.no{background:var(--nobg);color:var(--no)}
.tag.off{background:transparent;color:var(--mut);border:1px dashed var(--line)}
.foot{color:var(--mut);font-size:13px;border-top:1px solid var(--line);padding-top:8px;margin:8px 0 0}
details{margin-top:12px}summary{cursor:pointer;color:var(--mut)}
.note{color:var(--mut);font-size:13.5px;margin:12px 0 0}
"""


def build(ab: dict) -> str:
    mask = Masker()
    alert_path = Path(ab.get("alert", ""))
    alert_txt = ""
    if ab.get("alert") and alert_path.is_file():
        alert_txt = mask(json.dumps(json.loads(alert_path.read_text(encoding="utf-8")),
                                    ensure_ascii=False, indent=2))
    arms = [("A_no_playbook", "A — KHÔNG playbook", "a"),
            ("B_playbook", "B — playbook qua RAG (untrusted)", "b"),
            ("C_trusted_playbook", "C — playbook TRUSTED", "c")]
    cols, stats = [], []
    for key, label, tag in arms:
        if key in ab:
            body, st = column(label, tag, ab[key] or {}, mask)
            cols.append(body)
            stats.append((label.split(" ")[0], st))

    def line(field: str) -> str:
        return " → ".join(f"{name} {st[field]}/{st['steps']}" for name, st in stats)

    return f"""<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Demo playbook IR</title>
<style>{CSS}</style></head><body><main>
<h1>Playbook IR: next_steps trước và sau</h1>
<p class="sub">Model {esc(ab.get('model', '—'))} · rule {esc(str(ab.get('rule_id', '—')))} ·
cùng alert, cùng prompt; B và C cùng playbook, chỉ khác chỗ đặt và nhãn tin cậy · minh họa N=1, chưa phải kết quả đánh giá</p>
<section class="card"><h2>Cùng một alert, {len(cols)} câu trả lời</h2>
<div class="ab" style="--n:{len(cols)}">{''.join(cols)}</div>
<p class="note"><b>Cấu trúc điều tra</b> (bước xác minh): {line('verify')}.
<b>Bám bằng chứng</b> (bước có rule ID): {line('rule')}; bước có giá trị từ alert: {line('value')}.
Nhãn đỏ là phần chưa đạt.</p>
<details><summary>Alert đầu vào</summary><pre>{esc(alert_txt) or 'không tìm thấy file alert'}</pre></details>
<details><summary>Playbook đưa vào context (rule {esc(str(ab.get('rule_id', '')))})</summary>
<pre>{esc(mask(ab.get('playbook_context', '')))}</pre></details>
</section>
</main></body></html>
"""


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Trang demo tĩnh A/B playbook")
    ap.add_argument("--ab", default=str(DEFAULT_AB))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    ab_path = Path(args.ab)
    if not ab_path.exists():
        sys.exit(f"!! Không thấy {ab_path}. Chạy trước: python eval/playbook_ab_smoke.py (chỉ cần Ollama)")
    ab = json.loads(ab_path.read_text(encoding="utf-8"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(ab), encoding="utf-8", newline="\n")
    print(f"[OK] {out}  (mở bằng trình duyệt, không cần mạng)")


if __name__ == "__main__":
    main()
