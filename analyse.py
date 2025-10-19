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
            return datetime.strptime(s, fmt). date()
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
    with open(INPUT_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f) 
        for r in reader:
            row = {k: (v.strip() if isinstance(v, str) else v) for k, v in r.items()}

            row["week_number"] = safe_int(row.get("week_number"))
            row["resolution_minutes"] = safe_int(row.get("resolution_minutes"))
            row["affected_users"] = safe_int(row.get("affected_users"), default=0)           
            row["cost_sek"] = parse_swedish_float(row.get("cost_sek", "0"))    
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
        period = f"Weeks {min(weeks)} to {max(weeks)}" if weeks else "Unknown period"

    sev_counts = Counter((r.get("severity") or "unknown") for r in rows)
    per_severity = {}
    for sev in sorted(set(sev_counts.keys())):
        grp = [r for r in rows if (r.get("severity") or "").strip().lower() == sev]
        cnt = len(grp)
        avg_res = int(round(sum(r.get("resolution_minutes", 0) for r in grp) /cnt)) if cnt else 0
        avg_cost = round(sum(r.get("cost_sek", 0.0) for r in grp) / cnt, 2) if cnt else 0.0
        per_severity[sev] = {"count": cnt, "avg_res": avg_res, "avg_cost": avg_cost}

    big_incidents = [r for r in rows if r.get("affected_users", 0) > 100]
    top5 = sorted(rows, key=lambda x: x.get("cost_sek", 0.0), reverse=True)[:5]
    device_counts = Counter(r.get("device_hostname") or "UNKNOWN" for r in rows)
    recurring = {d: c for d, c in device_counts.items() if c > 1}

    # incidents by site (csv)
    site_summary = {}
    for r in rows:
        site = r.get("site") or "UNKNOWN"
        sev = (r.get("severity") or "").lower()
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

    cat_scores = defaultdict(list)
    for r in rows:
        score = r.get("affected_users", 0) * r.get("resolution_minutes", 0)
        cat = r.get("category") or "UNKNOWN"
        cat_scores[cat].append(score)

    avg_cat_scores = {
        cat : round (sum(vals)/len(vals), 1)
        for cat, vals in cat_scores.items() if vals
    }

    with open ("incidents_by_site.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Site", 
            "Total Incidents",
            "Critical Incidents",
            "High Incidents",
            "Medium Incidents",
            "Low Incidents", 
            "Avg Resolution (min)", 
            "Total Cost (SEK)"
        ])

        for site , data in site_summary.items():
            writer.writerow([
                site,
                data["count"],
                data["critical"],
                data["high"],
                data["medium"],
                data["low"],
                data["avg_res"],
                f"{data['total_cost']:.2f}".replace(".", ",")
            ])

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
    }

# generate text report

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

        # key highlights
        f.write("\n" + "=" * 66)
        f.write("\nKey highlights:")
        f.write("\n" + "=" * 66 + "\n")
        if results["device_counts"]:
            most, cnt = max(results["device_counts"].items(), key=lambda x: x[1])
            f.write(f"- Most frequent device: {most} ({cnt} incidents)\n")
        if results["top5"]:
            t = results["top5"][0]
            f.write(f"- Most expensive incident: {format_sek(t.get('cost_sek',0.0))} SEK; ticket: {t.get('ticket_id','N/A')}\n")
        f.write(f"- Incidents affecting >100 users: {len(results['big_incidents'])}\n")
        f.write(f"- Recurring devices count: {len(results['recurring_devices'])}\n\n")

        # incidents by severity
        f.write("\n" + "=" * 75)
        f.write("\nIncidents by severity:")
        f.write("\n" + "=" * 75 + "\n")
        f.write(format_columns(
            ["Severity", "Count", "Avg Res (min)", "Avg Cost (SEK)"],
            [18, 18, 18, 18],
        ))
        f.write("-" * 75 + "\n")
        for sev, data in sorted(results["per_severity"].items(), key=lambda x: x[0]):
            f.write(format_columns(
                [sev.capitalize(), data['count'], data['avg_res'], format_sek(data['avg_cost'])],
                [18, 18, 18, 18],
         ))

        # incidents affecting more than 100 users
        f.write("\n\n" + "=" * 90 + "\n")
        f.write("Incidents affecting more than 100 users:\n")
        f.write("=" * 90 + "\n")
        f.write(format_columns(
            ["Ticket", "Device", "Site", "Affected Users", "Cost (SEK)"],
            [18, 18, 18, 18, 18],
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
        f.write("\n\n" + "=" * 90)
        f.write("\nTop 5 incidents by cost:\n")
        f.write("=" * 90 + "\n")
        f.write(format_columns(
            ["Ticket", "Device", "Site", "Category", "Cost (SEK)"],
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

# --------------------
# entrypoint: run analysis and produce text report only
# --------------------
def main():
    results = network_incidents()
    incident_analysis(results)
    print(f"{OUT_TXT} created ({results['total_incidents']} incidents)")

if __name__ == "__main__":
    main()

    
