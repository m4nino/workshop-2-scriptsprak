# import the csv file
import csv
from collections import Counter, defaultdict
from datetime import datetime

INPUT_CSV = "network_incidents.csv"
OUT_TXT = "incident_analysis.txt"


# helper function 1, parse swedish formatted currency 1 234,50 -> "1234.50"

def parse_swedish_float(s):
    if s is None:
        return 0.0
    if isinstance(s, (int, float)):
        return float(s)
    s = s.strip()
    if s == "":
        return 0.0
    try:
        return float(s.replace(" ", "").replace(",", "."))
    except ValueError:
        return 0.0
    
# helper function 2, safe int parsing with default

def safe_int(value, default=0):
    try: 
        return int(value) if value not in (None, "") else default
    except Exception:
        return default
    
# helper function 3, flexible date parsing

def parse_date_flex(s):
    if not s:
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d-%m-%Y", "%d/%m/%y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            continue
    try:
        return datetime.fromisoformat(s).date()
    except Exception:
        return None
    
# helper function 4, format float value into Swedish currency string 1234.5 -> "1 234,50"

def format_sek(v):
    try:
        x = float(v)
    except Exception:
        x = 0.0

    s = f"{x:,.2f}"
    s = s.replace(",", "X").replace(".", ",").replace("X", " ")
    return s

# helper function 5, consistent table rows

def format_columns(values, widths, aligns=None, sep=" "):
    """
    values: list of str/int/float
            The values to format.
    widths: list of int
            Column widths for each value.
    aligns: list of str, optional
            Alignment per column: 'l' (left), 'r' (right), 'c' (center).
            Defaults to all left.
    sep   : str, optional
            Separator between columns. Default is a single space.
    """
    if aligns is None:
        aligns = ["l"] * len(values)

    formatted = []
    for val, w, a in zip(values, widths, aligns):
        text = str(val)
        if a == "r":
            formatted.append(text.rjust(w))
        elif a == "c":
            formatted.append(text.center(w))
        else:
            formatted.append(text.ljust(w))
    return sep.join(formatted) + "\n"

# read csv using csv.DictReader

def network_incidents(input_csv=INPUT_CSV):
    rows = []
    with open(input_csv, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f) 
        for r in reader:
            row = {k: (v.strip() if isinstance(v, str) else v) for k, v in r.items()}

            row["week_number"] = safe_int(row.get("week_number", 0))
            row["resolution_minutes"] = safe_int(row.get("resolution_minutes"))
            row["affected_users"] = safe_int(row.get("affected_users"), default=0)           
            row["cost_sek"] = parse_swedish_float(row.get("cost_sek"))    
            row["severity"] = (row.get("severity") or "").strip().lower()
            row["_date_raw"] = (row.get("date") or row.get("incident_date") or "")
            row["_date_parsed"] = parse_date_flex(row["_date_raw"])                   

            rows.append(row)

    if not rows:
        raise SystemExit("No rows read from CSV. Check file content.")

    # summary

    total_incidents = len(rows)
    total_cost = sum(r.get("cost_sek", 0.0) for r in rows)
    sites = sorted({r.get("site") or "UNKNOWN" for r in rows})
    dates = sorted({r["_date_parsed"] for r in rows if r["_date_parsed"]})
    if dates:
        period = f"{dates[0].isoformat()} to {dates[-1].isoformat()}"
    else:
        weeks = sorted({r["week_number"] for r in rows if r["week_number"]})
        if weeks:
            if min(weeks) == max(weeks):
                period = f"Week {min(weeks)}"
            else:
                period = f"Weeks {min(weeks)}-{max(weeks)}"
        else:
            period = "Unknown period"

    sev_counts = Counter((r.get("severity") or "unknown") for r in rows)
    per_severity = {}
    for sev in sorted(set(sev_counts.keys())):
        grp = [r for r in rows if r.get("severity") == sev]
        cnt = len(grp)
        avg_res = int(round(sum(r.get("resolution_minutes", 0) for r in grp) /cnt)) if cnt else 0
        avg_cost = round(sum(r.get("cost_sek", 0.0) for r in grp) / cnt, 2) if cnt else 0.0
        per_severity[sev] = {"count": cnt, "avg_res": avg_res, "avg_cost": avg_cost}

    big_incidents = [r for r in rows if r.get("affected_users", 0) > 100]
    top5 = sorted(rows, key=lambda x: x.get("cost_sek", 0.0), reverse=True)[:5]
    device_counts = Counter(r.get("device_hostname") or "UNKNOWN" for r in rows)
    recurring = {d: c for d, c in device_counts.items() if c > 1}

    cat_scores = defaultdict(list)
    for r in rows:
        cat = r.get("category") or "UNKNOWN"
        try:
            score = parse_swedish_float(r.get("impact_score"))
            cat_scores[cat].append(score)
        except Exception:
            pass

    avg_cat_scores = {
        cat: round(sum(vals) / len(vals), 1)
        for cat, vals in cat_scores.items() if vals
    }
    cat_counts = Counter(r.get("category") or "UNKNOWN" for r in rows)

    # incidents_by_site.csv
    site_summary = {}
    for r in rows:
        site = r.get("site") or "UNKNOWN"
        sev = r.get("severity") or ""
        if site not in site_summary:
            site_summary[site] = {
                "count": 0, "total_cost": 0.0, "total_res": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0
                }
        site_summary[site]["count"] += 1
        site_summary[site]["total_res"] += r.get("resolution_minutes", 0)
        site_summary[site]["total_cost"] += r.get("cost_sek", 0.0)

        if sev in ("critical", "high", "medium", "low"):
            site_summary[site][sev] += 1

    for site, data in site_summary.items():
        data["avg_res"] = round(data["total_res"] / data["count"], 1) if data["count"] else 0

    with open("incidents_by_site.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "Site",
            "Total Incidents",
            "Critical Incidents",
            "High Incidents",
            "Medium Incidents",
            "Low Incidents", 
            "Avg Resolution (min)", 
            "Total Cost (SEK)"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for site , data in site_summary.items():
            writer.writerow({
                "Site": site,
                "Total Incidents": data["count"],
                "Critical Incidents": data["critical"],
                "High Incidents": data["high"],
                "Medium Incidents": data["medium"],
                "Low Incidents": data["low"],
                "Avg Resolution (min)": data["avg_res"],
                "Total Cost (SEK)": format_sek(data["total_cost"])
            })

    # problem_devices.csv
    severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    type_map = {
        "SW": "switch", "AP": "access_point", "RT": "router", 
        "FW": "firewall", "LB": "load_balancer"
    }
    device_summary = {}
    max_week = max((r["week_number"] for r in rows if r["week_number"]), default=0)

    for r in rows:
        dev = r.get("device_hostname") or "UNKNOWN"
        site = r.get("site") or "UNKNOWN"
        sev = (r.get("severity") or "unknown").lower()
        cost = r.get("cost_sek", 0.0)
        users = r.get("affected_users", 0)
        week = r.get("week_number", 0)

        if dev not in device_summary:
            device_summary[dev] = {
                "site": site,
                "device_type": type_map.get(dev.split("-")[0], "other"),
                "count": 0, "sev_scores":[], "total_cost":0.0, "total_users":0, 
                "recent":False
            }

        data = device_summary[dev]
        data["count"] += 1
        data["sev_scores"].append(severity_map.get(sev.lower(), 0))
        data["total_cost"] += cost
        data["total_users"] += users
        if week >= max_week - 1:
            data["recent"] = True

    with open("problem_devices.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "device_hostname", 
            "site", "device_type", 
            "incident_count",
            "avg_severity_score", 
            "total_cost_sek", 
            "avg_affected_users",
            "in_last_weeks_warnings"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for dev, data in sorted(device_summary.items(),
                             key=lambda x: (x[1]["count"], x[1]["total_cost"]),
                             reverse=True):
            avg_sev = (sum(data["sev_scores"]) / len(data["sev_scores"])) if data["sev_scores"] else 0
            avg_users = (data["total_users"] / data["count"]) if data["count"] else 0                              
            
            writer.writerow({
                "device_hostname": dev,
                "site": data["site"],
                "device_type": data["device_type"],
                "incident_count": data ["count"],
                "avg_severity_score": f"{avg_sev:.2f}",
                "total_cost_sek": format_sek(data["total_cost"]),
                "avg_affected_users": f"{avg_users:.2f}",
                "in_last_weeks_warnings": "yes" if data["recent"] else "no"                 
            }) 

# cost_analysis.csv

    weekly_summary = {}

    for r in rows:
        week = r.get("week_number")
        if not week or week <1 or week > 52:
            continue
        if week not in weekly_summary:
            weekly_summary[week] = {"impact_scores": [],"total_cost": 0.0,}

        weekly_summary[week]["total_cost"] += r.get("cost_sek", 0.0)

        try:
            score = parse_swedish_float(r.get("impact_score"))
            weekly_summary[week]["impact_scores"].append(score)
        except Exception:
            pass

    with open("cost_analysis.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "week_number", 
            "avg_impact_score", 
            "total_cost_sek"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for week in sorted(weekly_summary.keys()):
            data = weekly_summary[week]
            avg_score = round(sum(data["impact_scores"]) / len(data["impact_scores"]), 2) if data["impact_scores"] else 0
            
            writer.writerow({
                "week_number": week,
                "avg_impact_score": f"{avg_score:.2f}".replace(".", ","), 
                "total_cost_sek": format_sek(data["total_cost"])
            })      

    return {
        "rows": rows,
        "total_incidents": total_incidents,
        "total_cost": total_cost,
        "sites": sites,
        "period": period,
        "sev_counts": sev_counts,
        "per_severity": per_severity,
        "big_incidents": big_incidents,
        "top5": top5,
        "recurring_devices": recurring,
        "device_counts": device_counts,
        "site_summary": site_summary,
        "avg_cat_scores": avg_cat_scores,
        "cat_counts": cat_counts
}

# incident_analysis.txt

def incident_analysis(results, out_txt=OUT_TXT):
    with open(out_txt, "w", encoding="utf-8") as f:

        # INCIDENT ANALYSIS - TechCorp AB
        f.write("=" * 90 + "\n")
        f.write(format_columns(
            ["INCIDENT ANALYSIS - TechCorp AB ", f"Report period: {results['period']}"],
            [45, 40],
            ["l", "r"]
        ))
        f.write("=" * 90 + "\n")
        f.write(f"Sites covered: {', '.join(results['sites'])}\n\n")
        f.write(f"Total incidents: {results['total_incidents']}\n")
        f.write(f"Total cost (SEK): {format_sek(results['total_cost'])}\n\n")

        # executive summary
        f.write("\n" + "=" * 90 + "\n")
        f.write("Executive Summary:")
        f.write("\n" + "=" * 90 + "\n")

        tor02_incidents = [r for r in results["rows"] if r.get("device_hostname") == "SW-DC-TOR-02"]
        if tor02_incidents:
            weeks = {r.get("week_number") for r in tor02_incidents if r.get("week_number")}
            f.write(
                f"⚠ CRITICAL: SW-DC-TOR–02 stands out as the most frequent device with repeated failures\n"
                f"({len(tor02_incidents)} incidents across {len(weeks)} weeks)\n\n"
            )
            
        if results["rows"]:
            most_expensive = max(results["rows"], key=lambda r: r.get("cost_sek", 0) or 0)
            f.write(
                f"⚠ Most expensive incident: {format_sek(most_expensive.get('cost_sek', 0))} SEK "
                f"(Ticket {most_expensive.get('ticket_id')}, {most_expensive.get('device_hostname')}, "
                f"{most_expensive.get('site')})\n\n"
            )

        total = results['total_incidents']
        crit_count = results["per_severity"].get("critical", {}).get("count", 0)
        non_crit = total - crit_count
        f.write(
            f"✓ Majority of incidents were non-critical ({non_crit} of {total})\n\n"
            )

        # incidents by severity
        f.write("\n" + "=" * 75 + "\n")
        f.write("Incidents by severity:")
        f.write( "\n" + "=" * 75 + "\n")
        f.write(format_columns(
            ["Severity", "Count", "Avg Res (min)", "Avg Cost (SEK)"],
            [18, 18, 18, 18]
        ))
        f.write("-" * 75 + "\n")
        severity_order = {"critical":1, "high": 2, "medium": 3, "low": 4}
        for sev, data in sorted(results["per_severity"].items(), 
            key=lambda x: severity_order.get(x[0].lower(), 99)):
            f.write(format_columns(
                [
                    sev.capitalize(), 
                    data['count'], 
                    data['avg_res'], 
                    format_sek(data['avg_cost'])
                ],
                [18, 18, 18, 18],
        ))

        # incidents affecting more than 100 users
        f.write("\n\n" + "=" * 90 + "\n")
        f.write(f"Incidents affecting more than 100 users ({len(results['big_incidents'])})")
        f.write("\n" + "=" * 90 + "\n")
        f.write(format_columns(
            [
                "Ticket", 
                "Device", 
                "Site", 
                "Affected Users", 
                "Cost (SEK)"
            ],
            [18, 18, 18, 18, 18]
        ))

        f.write("-" * 90 + "\n")

        for r in results["big_incidents"]:
            f.write(format_columns(
                [
                    r.get("ticket_id", "-"),
                    r.get("device_hostname", "-"),
                    r.get("site", "-"),
                    r.get("affected_users", 0),
                    format_sek(r.get("cost_sek", 0.0))
                ],
                [18, 18, 18, 18, 18]
            ))

        # top 5 incidents by cost
        f.write("\n\n" + "=" * 90 + "\n")
        f.write("Top 5 incidents by cost:")
        f.write("\n" + "=" * 90 + "\n")
        f.write(format_columns(
            [
                "Ticket", 
                "Device", 
                "Site", 
                "Category", 
                "Cost (SEK)"
            ],
            [18, 18, 18, 18, 18],
        ))
        f.write("-" * 90 + "\n")

        for i, t in enumerate(results["top5"], 1):
            f.write(format_columns(
                [
                    t.get('ticket_id','-'),
                    t.get('device_hostname','-'),
                    t.get('site', '-'),
                    t.get('category','-'),
                    format_sek(t.get('cost_sek',0.0)) 
                ],
                [18, 18, 18, 18, 18],    
            ))   

        # average impact score
        f.write("\n\n" + "=" * 75 + "\n")
        f.write("Incidents per category with average impact score:")
        f.write("\n" + "=" * 75 + "\n")
        f.write(format_columns(["Category", "Count", "Avg Impact Score"],
            [18, 18, 18]
        ))
        f.write("-" * 75 + "\n")
        
        
        for cat, score in sorted(results["avg_cat_scores"].items()):
            count = results["cat_counts"].get(cat, 0)
            f.write(format_columns(
                [
                    cat, 
                    count, 
                    score
                ],
                [18, 18, 18]
            ))
        f.write("\n\n" + "=" * 90 + "\n")
        f.write("|                                     RECOMMENDATIONS                                    |")
        f.write("\n" + "=" * 90 + "\n\n")

        f.write("CRITICAL ⚠\n")
        f.write(". SW-DC-TOR-02 (Datacenter, switch), 4 incidents, 86 048 SEK\n")
        f.write("> Replace or add redundancy, perform root cause analysis \n\n")

        f.write("HIGH\n")
        f.write(". RT-LAGER-01 (Lager, router) - 3 incidents, 34 901 SEK\n")
        f.write("> Review configuration and redundancy \n\n")
        f.write(". AP-FLOOR2-02 (Huvudkontor, access_point) - 2 incidents, severity 3.5 \n")
        f.write("> Add load balancing for more APs\n\n")

        f.write("MEDIUM\n")
        f.write(". FW-DC-01 (Datacenter, firewall) - 2 incidents, 133 users affected \n")
        f.write("> Increase monitoring, check capacity \n\n")

        f.write("LOW\n")
        f.write(". Devices with single low-cost incidents (e.g. FW-MAL-01, SW-DIST-01) \n")
        f.write("> Monitor, address during planned maintenance \n\n")

        f.write("=" * 90 + "\n")
        f.write("|                                      END OF REPORT                                     |")
        f.write("\n" + "=" * 90 + "\n")

# --------------------
# entrypoint: run analysis and produce text report only
# --------------------
def main():
    results = network_incidents()
    incident_analysis(results)
    print(f"{OUT_TXT} created ({results['total_incidents']} incidents)")

if __name__ == "__main__":
    main()

    
