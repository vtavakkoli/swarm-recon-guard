from __future__ import annotations

import csv, html, json, math
from collections import defaultdict
from pathlib import Path
from swarmguard.reporting.stats import auroc, average_precision, describe, hedges_g, wilson_interval
from swarmguard.reporting.distributional import evaluate_distributional

METRICS=("detected","detector_score_peak","detection_delay_ms","exposure_before_detection","semantic_coverage","vulnerability_discovery_rate","requests_per_second","latency_p95_ms","latency_p99_ms","transport_error_rate","sla_p95_delta_pct","throughput_delta_pct","per_identity_rule_triggered")

def _num(v):
    if v is None: return None
    if isinstance(v,bool): return 1.0 if v else 0.0
    try: x=float(v)
    except (TypeError,ValueError): return None
    return None if math.isnan(x) else x

def _fmt(s):
    if s.n==0 or math.isnan(s.mean): return "—"
    return f"{s.mean:.4g} ± {s.std:.3g} [{s.ci95_low:.4g}, {s.ci95_high:.4g}]"

def build_report(runs:list[dict[str,object]], manifest:dict[str,object], out:Path)->None:
    if not runs: raise ValueError("cannot build report without runs")
    baseline={(int(r["agent_count"]),int(r["repeat"])):r for r in runs if r["scenario"]=="benign_flash"}
    for r in runs:
        b=baseline.get((int(r["agent_count"]),int(r["repeat"])))
        if b:
            bp95=float(b["latency_p95_ms"]); brps=float(b["requests_per_second"])
            r["sla_p95_delta_pct"]=100*(float(r["latency_p95_ms"])-bp95)/bp95 if bp95 else 0.0
            r["throughput_delta_pct"]=100*(float(r["requests_per_second"])-brps)/brps if brps else 0.0
    stat_cfg=manifest.get("suite",{}).get("statistical",{}) if isinstance(manifest.get("suite",{}),dict) else {}
    distributional={"summary":[],"diagnostics":{}}
    if stat_cfg.get("enabled",True):
        distributional=evaluate_distributional(
            runs,
            out,
            alpha=float(stat_cfg.get("alpha",0.01)),
            shrinkage=float(stat_cfg.get("shrinkage",0.10)),
            hybrid_weight=float(stat_cfg.get("hybrid_weight",0.50)),
            validation_modes=tuple(stat_cfg.get("validation_modes",["leave_repeat_out","leave_scale_out"])),
        )

    fields=sorted({k for r in runs for k in r})
    with (out/"raw_metrics.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(runs)
    groups=defaultdict(list)
    for r in runs: groups[(str(r["scenario"]),int(r["agent_count"]))].append(r)
    summaries={}; flat=[]
    for key in sorted(groups,key=lambda x:(x[1],x[0])):
        stats={}; row={"scenario":key[0],"agent_count":key[1],"repeats":len(groups[key])}
        for metric in METRICS:
            values=[x for r in groups[key] if (x:=_num(r.get(metric))) is not None]
            s=describe(values); stats[metric]=s
            row.update({f"{metric}_n":s.n,f"{metric}_mean":s.mean,f"{metric}_std":s.std,f"{metric}_ci95_low":s.ci95_low,f"{metric}_ci95_high":s.ci95_high})
        summaries[key]=stats; flat.append(row)
    with (out/"summary.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(flat[0])); w.writeheader(); w.writerows(flat)
    labels=[int(r["label"]) for r in runs]; scores=[float(r["detector_score_peak"]) for r in runs]
    auc=auroc(labels,scores); ap=average_precision(labels,scores)
    neg=[r for r in runs if r["scenario"]=="benign_flash"]; pos=[r for r in runs if r["scenario"]!="benign_flash"]
    fpr=sum(bool(r["detected"]) for r in neg)/len(neg) if neg else float("nan"); tpr=sum(bool(r["detected"]) for r in pos)/len(pos) if pos else float("nan")
    (out/"classification.json").write_text(json.dumps({"auroc":auc,"average_precision":ap,"false_positive_rate":fpr,"positive_detection_rate":tpr},indent=2))
    scale_rows=[]
    for n in sorted({int(r["agent_count"]) for r in runs}):
        sub=[r for r in runs if int(r["agent_count"])==n]; bn=[r for r in sub if r["scenario"]=="benign_flash"]; ps=[r for r in sub if r["scenario"]!="benign_flash"]
        fp=sum(bool(r["detected"]) for r in bn); tp=sum(bool(r["detected"]) for r in ps); fpl,fph=wilson_interval(fp,len(bn)); tpl,tph=wilson_interval(tp,len(ps))
        scale_rows.append({"agent_count":n,"auroc":auroc([int(r["label"]) for r in sub],[float(r["detector_score_peak"]) for r in sub]),"average_precision":average_precision([int(r["label"]) for r in sub],[float(r["detector_score_peak"]) for r in sub]),"false_positive_rate":fp/len(bn) if bn else float("nan"),"false_positive_wilson_low":fpl,"false_positive_wilson_high":fph,"positive_detection_rate":tp/len(ps) if ps else float("nan"),"positive_detection_wilson_low":tpl,"positive_detection_wilson_high":tph})
    with (out/"classification_by_agents.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(scale_rows[0])); w.writeheader(); w.writerows(scale_rows)
    effects=[]
    for n in sorted({int(r["agent_count"]) for r in runs}):
        bn=[r for r in runs if int(r["agent_count"])==n and r["scenario"]=="benign_flash"]
        for sc in ("independent_recon","coordinated_swarm"):
            ar=[r for r in runs if int(r["agent_count"])==n and r["scenario"]==sc]
            for m in ("detector_score_peak","semantic_coverage","vulnerability_discovery_rate"):
                effects.append({"agent_count":n,"contrast":f"{sc} vs benign_flash","metric":m,"hedges_g":hedges_g([float(r[m]) for r in ar],[float(r[m]) for r in bn])})
    with (out/"effect_sizes.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(effects[0])); w.writeheader(); w.writerows(effects)
    with (out/"runs.jsonl").open("w",encoding="utf-8") as f:
        for r in runs: f.write(json.dumps(r,sort_keys=True)+"\n")
    trs=[]
    for (sc,n),s in sorted(summaries.items(),key=lambda x:(x[0][1],x[0][0])):
        cells=[html.escape(sc),f"{n:,}",_fmt(s["detected"]),_fmt(s["detector_score_peak"]),_fmt(s["semantic_coverage"]),_fmt(s["exposure_before_detection"]),_fmt(s["vulnerability_discovery_rate"]),_fmt(s["latency_p95_ms"]),_fmt(s["sla_p95_delta_pct"]),_fmt(s["requests_per_second"])]
        trs.append("<tr>"+"".join(f"<td>{c}</td>" for c in cells)+"</tr>")
    dist_rows=[]
    for row in distributional.get("summary",[]):
        dist_rows.append(
            "<tr>"
            + f"<td>{html.escape(str(row['validation']))}</td>"
            + f"<td>{html.escape(str(row['detector']))}</td>"
            + f"<td>{float(row['macro_auroc_mean']):.3f}</td>"
            + f"<td>{float(row['macro_ap_mean']):.3f}</td>"
            + f"<td>{float(row['detection_rate']):.1%}</td>"
            + f"<td>{float(row['false_positive_rate']):.1%}</td>"
            + "</tr>"
        )
    diagnostics=distributional.get("diagnostics",{})
    mardia=diagnostics.get("mardia_skewness",{}) if isinstance(diagnostics,dict) else {}
    if mardia:
        gaussian_note=f"Mardia skewness p={float(mardia.get('p_value',float('nan'))):.3g}. A small p-value means the single-Gaussian model is an approximation and should be compared with richer models."
    else:
        gaussian_note="Gaussian diagnostics unavailable."
    distributional_html=(
        '<div class="panel"><h2>Distributional detector comparison</h2>'
        '<table><tr><th>Validation</th><th>Detector</th><th>Macro AUROC</th><th>Macro AP</th><th>Detection</th><th>FPR</th></tr>'
        + "".join(dist_rows)
        + '</table><p><small>' + html.escape(gaussian_note) + '</small></p>'
        + '<p><small>Gaussian OOD models the benign distribution. Gaussian LLR compares benign likelihood against a scenario-conditioned attack mixture. Hybrid fuses the original transparent score with the LLR using training-fold statistics only.</small></p></div>'
    )
    suite=html.escape(json.dumps(manifest.get("suite",{}),indent=2,sort_keys=True))
    page=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SwarmReconGuard report</title><style>body{{font-family:system-ui;margin:0;background:#f8fafc;color:#0f172a}}main{{max-width:1180px;margin:auto;padding:32px}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card,.panel{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px;margin-top:14px}}.v{{font-size:28px;font-weight:700}}.k{{font-size:12px;color:#64748b;text-transform:uppercase}}table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{padding:8px;border-bottom:1px solid #e2e8f0;text-align:right;white-space:nowrap}}th:first-child,td:first-child{{text-align:left}}.panel{{overflow:auto}}pre{{background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow:auto}}</style></head><body><main><h1>SwarmReconGuard</h1><p>Repeated black-box collective-behavior benchmark.</p><div class="cards"><div class="card"><div class="k">AUROC</div><div class="v">{auc:.3f}</div></div><div class="card"><div class="k">Average precision</div><div class="v">{ap:.3f}</div></div><div class="card"><div class="k">Positive detection</div><div class="v">{tpr:.1%}</div></div><div class="card"><div class="k">Benign FPR</div><div class="v">{fpr:.1%}</div></div></div><div class="panel"><h2>Repeated-trial summary</h2><table><tr><th>Scenario</th><th>Agents</th><th>Detection</th><th>Peak score</th><th>Coverage</th><th>Exposure at alarm</th><th>Discovery</th><th>p95 ms</th><th>SLA Δ%</th><th>req/s</th></tr>{''.join(trs)}</table><p><small>mean ± sample SD [95% Student-t CI]. Scale-specific Wilson intervals are in classification_by_agents.csv.</small></p></div>{distributional_html}<div class="panel"><h2>Experiment design</h2><pre>{suite}</pre></div><div class="panel"><h2>Artifacts</h2><p>raw_metrics.csv · summary.csv · runs.jsonl · classification.json · classification_by_agents.csv · effect_sizes.csv · distributional_scores.csv · distributional_folds.csv · distributional_summary.csv · gaussian_diagnostics.json · manifest.json</p></div></main></body></html>'''
    (out/"report.html").write_text(page,encoding="utf-8")
