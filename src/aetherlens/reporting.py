"""Human-readable offline evidence report; no external assets or network calls."""

from html import escape
from pathlib import Path


_CSS = """
:root{color-scheme:dark;font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:#090e16;color:#dbe4f0}
main{max-width:1160px;margin:0 auto;padding:60px 32px 90px}
header{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;border-bottom:1px solid #273044;padding-bottom:30px}
.eyebrow{color:#6fe2bd;font-size:11px;font-weight:800;letter-spacing:.2em;text-transform:uppercase}
h1{color:#fff;font-size:clamp(28px,5vw,52px);margin:13px 0 6px;letter-spacing:-.05em;line-height:1.1}
.sub{color:#94a3b8;max-width:700px}
.chip{border:1px solid #33514d;background:#132720;color:#8be1b8;padding:8px 13px;border-radius:99px;white-space:nowrap;font-size:12px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:32px 0 50px}
.metric,.sensor,.finding{border:1px solid #263347;background:#111927;border-radius:16px}
.metric{padding:20px}.metric strong{display:block;color:white;font-size:30px;margin:6px 0;font-variant-numeric:tabular-nums}
.metric span{color:#91a1b8;font-size:12px;letter-spacing:.07em;text-transform:uppercase}
h2{font-size:20px;margin:33px 0 16px;color:white;letter-spacing:-.025em}
section{margin-bottom:32px}
.sensors{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}
.sensor{padding:20px}.sensor b{color:#fff;display:block;font-size:16px;overflow-wrap:anywhere}
.sensor p,.finding p{color:#94a3b8;margin:8px 0 0}
.faint{color:#73829b;font-size:12px}
.finding{margin:12px 0;padding:22px;border-left:4px solid #efad52}
.finding.high{border-left-color:#ff777e}.finding.medium{border-left-color:#efad52}
.finding b{color:#fff;display:block;margin-bottom:8px;font-size:17px}
.severity{color:#ff9298;font-size:11px;text-transform:uppercase;font-weight:bold;letter-spacing:.13em}
.finding.medium .severity{color:#ffc97d}
code{font-size:13px;color:#cbd5e1;overflow-wrap:anywhere}
.evidence{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.evidence span{background:#1d293a;border:1px solid #334258;padding:5px 10px;border-radius:7px;font-size:12px}
footer{margin-top:40px;border-top:1px solid #273044;padding-top:22px;color:#91a1b8;font-size:13px}
@media(max-width:690px){main{padding:32px 15px}header{flex-direction:column}.metrics{grid-template-columns:repeat(2,1fr)}}
"""


def render_fusion(report: dict) -> str:
    """Render untrusted strings as escaped text and keep the report self-contained."""
    def e(value) -> str:
        return escape(str(value), quote=True)

    metrics = (
        ("Observers", report["sensor_count"]),
        ("Unique BSSIDs", report["observed_bssids"]),
        ("Shared BSSIDs", report["shared_bssids"]),
        ("Identity conflicts", len(report["findings"])),
    )
    cards = "".join(
        f'<div class="metric"><span>{e(label)}</span><strong>{e(value)}</strong></div>'
        for label, value in metrics
    )
    sensors = "".join(
        f'<article class="sensor"><span class="eyebrow">Sensor</span><b>{e(s["id"])}</b>'
        f'<p>{e(s["site"])} · {e(s["observations"])} transmitters</p>'
        f'<span class="faint">{e(s["timestamp"])}</span></article>'
        for s in report["sensors"]
    )
    findings = "".join(
        f'<article class="finding {e(f["severity"])}">'
        f'<span class="severity">{e(f["severity"])} · {e(f["kind"]).replace("_", " ")}</span>'
        f'<b>{e(" vs ".join(f["sensors"]))}</b>'
        f'<code>{e(f["bssid"])}</code><div class="evidence">'
        + "".join(f"<span>{e(item)}</span>" for item in f["evidence"])
        + "</div></article>"
        for f in report["findings"]
    )
    if not findings:
        findings = '<p class="sub">No identity conflicts in comparable observations. This does not establish network safety.</p>'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>AetherLens | Wireless investigation</title><style>'
        + _CSS + '</style></head><body><main><header><div>'
        '<span class="eyebrow">AetherLens / cooperative wireless intelligence</span>'
        '<h1>Wireless identity investigation</h1>'
        '<p class="sub">Compare observations from independent sensors without transmitting '
        'packets or uploading data to a server.</p></div>'
        '<span class="chip">● Offline evidence</span></header>'
        '<div class="metrics">' + cards + '</div>'
        '<section><h2>Observer network</h2><div class="sensors">' + sensors + '</div></section>'
        '<section><h2>Conflicting evidence</h2>' + findings + '</section>'
        '<footer>' + e(report["note"])
        + f' Timestamp tolerance: {e(report["max_skew_seconds"])} seconds.'
        + ' Claims should be confirmed against authorized infrastructure records.</footer>'
        '</main></body></html>'
    )


def save_fusion(path: str | Path, report: dict) -> None:
    Path(path).write_text(render_fusion(report), encoding="utf-8")
