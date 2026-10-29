"""Offline, bounded, reproducible statistics over explicitly selected evidence."""
from __future__ import annotations

import copy
import csv
import hashlib
import html
import io
import json
import math
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import numpy as np

from . import evidence_graph

MAX_ROWS = 5000
MAX_BYTES = 40 * 1024 * 1024
SEED = 42
LIMITATIONS = [
    "Exploratory statistics describe this bounded sample, not the entire population.",
    "Correlation, text similarity and graph communities do not prove coordination, bots, identity or ownership.",
    "Event times are distinct from collection times. Undated observations are excluded from time analysis.",
    "Empty activity bins mean no observed events, not verified inactivity; source coverage may be incomplete.",
    "Numeric correlation p-values assume independent observations; BH correction does not remove sampling bias or autocorrelation.",
    "Coordinates are reported observations, not independently verified geolocation. Forecasts are scenarios, not threat predictions.",
]


def number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (TypeError, ValueError, OverflowError):
        return None


def event_time(value):
    if not value:
        return None
    try:
        text = str(value)
        if len(text) == 14 and text.isdigit():
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
        # Naive event dates have an explicit UTC assumption in the report.
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def load(path):
    path = Path(path).resolve()
    if path.suffix.lower() not in {".csv", ".tsv", ".json", ".jsonl"}:
        raise ValueError("Choose CSV, TSV, JSON, JSONL or a saved dossier.json")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Analysis input exceeds 40 MB")
    text = raw.decode("utf-8-sig")
    if path.suffix.lower() in {".csv", ".tsv"}:
        reader = csv.DictReader(io.StringIO(text), delimiter="\t" if path.suffix.lower() == ".tsv" else ",")
        data = []
        for row in reader:
            data.append(row)
            if len(data) > MAX_ROWS:
                break
    elif path.suffix.lower() == ".jsonl":
        data = [json.loads(line) for line in text.splitlines() if line.strip()][:MAX_ROWS + 1]
    else:
        data = json.loads(text)
    if not isinstance(data, (dict, list)):
        raise ValueError("Input must contain records or dossier evidence sections")
    if isinstance(data, dict) and not (isinstance(data.get("sections"), dict) or
                                           isinstance(data.get("records"), list)):
        raise ValueError("JSON must contain sections or a records array")
    if isinstance(data, dict) and isinstance(data.get("sections"), dict):
        if any(not isinstance(data.get(key, []), list) for key in ("artifacts", "source_checks", "source_events", "errors")):
            raise ValueError("Dossier artifacts, source checks and errors must be arrays")
        if any(not isinstance(data["sections"].get(key, []), list) for key in ("web", "profiles", "emails")):
            raise ValueError("Dossier web, profiles and emails must be arrays")
    return data, {"kind": "analysis_input", "path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def normalize(data):
    rows, seen, counts = [], set(), Counter()
    ignored = {"source_checks", "source_events", "artifacts", "statistics", "analytics", "status", "settings", "errors"}
    timestamp_keys = ("timestamp", "published_at", "created_at", "posted", "date", "snapshot_at", "event_time")
    measurement_keys = ("observer_latitude", "observer_longitude", "bearing_deg", "bearing_error_deg", "range_m", "range_error_m")

    def visit(item, section="import", depth=0):
        if depth > 6 or counts["visited"] > 50000:
            counts["structure_limit"] += 1
            return
        if isinstance(item, list):
            for child in item:
                visit(child, section, depth + 1)
            return
        if not isinstance(item, dict):
            return
        counts["visited"] += 1
        if str(item.get("state") or item.get("status", "")).lower() in {
                "error", "failed", "blocked", "timeout", "skipped", "unavailable", "running", "attempted"}:
            counts["failed_records"] += 1
            return
        scalars = {str(k)[:80]: v for k, v in item.items() if isinstance(v, (str, int, float)) and not isinstance(v, bool)}
        if scalars:
            if len(rows) >= MAX_ROWS:
                counts["truncated"] += 1
                return
            stamp = next((item[k] for k in timestamp_keys if item.get(k)), None)
            # Wireless timestamps originate in telemetry; generic observed_at is a collection timestamp.
            if stamp is None and section == "wireless":
                stamp = item.get("observed_at")
            time = event_time(stamp)
            if stamp and time is None:
                counts["invalid_times"] += 1
            metrics = {}
            for key, value in scalars.items():
                if key not in {*timestamp_keys, *measurement_keys, "target_id", "id", "ref", "event_id", "actor", "username", "source", "target", "label", "latitude", "longitude", "lat", "lon", "lng"}:
                    num = number(value)
                    if num is not None:
                        metrics[key] = num
            if isinstance(item.get("metrics"), dict):
                metrics.update({str(k)[:80]: n for k, v in item["metrics"].items() if (n := number(v)) is not None})
            metrics = dict(sorted(metrics.items())[:24])
            lat = number(item.get("latitude", item.get("lat")))
            lon = number(item.get("longitude", item.get("lon", item.get("lng"))))
            if lat is not None and lon is not None and not (-90 <= lat <= 90 and -180 <= lon <= 180):
                lat = lon = None
                counts["invalid_coordinates"] += 1
            measurement = item.get("measurement") if isinstance(item.get("measurement"), dict) else {}
            row = {"id": str(item.get("event_id") or item.get("id") or "")[:160], "section": section,
                   "target_id": str(item.get("target_id") or "")[:160],
                   "measurement": {k: number(measurement.get(k, item.get(k))) for k in measurement_keys}
                                  if any(k in item or k in measurement for k in measurement_keys) else {},
                   "actor": str(item.get("actor") or item.get("username") or item.get("author") or "")[:160],
                   "timestamp": time.isoformat() if time else "", "source": str(item.get("source") or "Imported evidence")[:200],
                   "source_url": evidence_graph._url(item.get("source_url") or item.get("url")),
                   "text": str(item.get("text") or item.get("snippet") or item.get("description") or "")[:4000],
                   "latitude": lat, "longitude": lon, "metrics": metrics,
                   "relation_source": str(item.get("relation_source") or (item.get("source") if item.get("target") else "") or "")[:160],
                   "relation_target": str(item.get("relation_target") or item.get("target") or "")[:160],
                   "label": str(item.get("label") or "")[:80]}
            key = json.dumps(row, sort_keys=True, ensure_ascii=False)
            if (row["id"] or row["source_url"]) and key in seen:
                counts["duplicates"] += 1
            else:
                seen.add(key)
                row["ref"] = len(rows)
                rows.append(row)
        for key, child in item.items():
            if key not in ignored and key not in {"metrics", "measurement", "relationship_graph", "history", "quality_report", "ai_analysis"} and isinstance(child, (list, dict)):
                visit(child, section, depth + 1)

    if isinstance(data, dict) and isinstance(data.get("sections"), dict) and isinstance(data["sections"].get("analysis_observations"), list):
        visit(data["sections"]["analysis_observations"], "analysis_observations")
    elif isinstance(data, dict) and isinstance(data.get("sections"), dict):
        for section, value in data["sections"].items():
            if section not in ignored:
                visit(value, section)
    else:
        visit(data.get("records", []) if isinstance(data, dict) else data)
    return rows, dict(counts)


def describe(rows):
    fields = sorted({key for row in rows for key in row["metrics"]})[:24]
    result = {}
    for key in fields:
        values = [r["metrics"][key] for r in rows if key in r["metrics"]]
        q1, q2, q3 = np.quantile(values, [.25, .5, .75])
        freq = Counter(values)
        positive = np.array([x for x in values if x > 0])
        tail = {"status": "insufficient_data"}
        if len(positive) >= 20 and np.std(positive):
            xmin = float(min(positive))
            alpha = 1 + len(positive) / float(np.log(positive/xmin).sum())
            tail = {"status": "ok", "positive_n": len(positive), "xmin": xmin, "pareto_density_alpha_mle": alpha,
                    "meaning": "Exploratory continuous Pareto fit over positive values; no power-law goodness-of-fit claim"}
        result[key] = {"n": len(values), "missing": len(rows) - len(values), "pareto_tail": tail,
                       "mean": float(np.mean(values)), "median": float(q2),
                       "modes": sorted(x for x, n in freq.items() if n == max(freq.values()))[:10],
                       "variance_sample": float(np.var(values, ddof=1)) if len(values) > 1 else None,
                       "std_sample": float(np.std(values, ddof=1)) if len(values) > 1 else None,
                       "q1": float(q1), "q3": float(q3), "min": min(values), "max": max(values),
                       "iqr_outlier_refs": [r["ref"] for r in rows if key in r["metrics"] and
                                            (r["metrics"][key] < q1 - 1.5*(q3-q1) or r["metrics"][key] > q3 + 1.5*(q3-q1))][:100]}
    activity = sorted(Counter(r["actor"] for r in rows if r["actor"]).values(), reverse=True)
    zipf = {"status": "insufficient_data"}
    if len(activity) >= 5 and len(set(activity)) > 1:
        fit = np.polyfit(np.log(np.arange(1, len(activity)+1)), np.log(activity), 1)
        zipf = {"status": "ok", "rank_log_slope": float(fit[0]), "counts": activity,
                "meaning": "Rank-frequency diagnostic; not evidence that a Zipf law holds"}
    return {"status": "ok" if result else "insufficient_data", "fields": result, "zipf_activity": zipf,
            "sources": dict(Counter(r["source"] for r in rows)),
            "actors": dict(Counter(r["actor"] for r in rows if r["actor"]))}


def correlations(rows):
    from scipy.stats import pearsonr, spearmanr
    fields = sorted({key for row in rows for key in row["metrics"]})[:24]
    pairs = []
    for a, b in combinations(fields, 2):
        values = [(r["metrics"][a], r["metrics"][b]) for r in rows if a in r["metrics"] and b in r["metrics"]]
        if len(values) < 8:
            continue
        x, y = np.array(values).T
        if np.std(x) == 0 or np.std(y) == 0:
            continue
        r, p = pearsonr(x, y)
        rho, _ = spearmanr(x, y)
        pairs.append({"a": a, "b": b, "n": len(values), "pearson": float(r), "spearman": float(rho), "p": float(p)})
    adjusted = 1.0
    for rank, row in reversed(list(enumerate(sorted(pairs, key=lambda r: r["p"]), 1))):
        adjusted = min(adjusted, row["p"] * len(pairs) / rank)
        row["q_bh"] = adjusted
    return {"status": "ok" if pairs else "insufficient_data", "minimum_pairs": 8,
            "pairs": sorted(pairs, key=lambda r: -abs(r["pearson"]))}


def temporal(rows, period):
    dated = [(r, event_time(r["timestamp"])) for r in rows if r["timestamp"]]
    if len(dated) < 8:
        return {"status": "insufficient_data", "detail": "At least eight explicitly dated events are required"}
    stamps = np.array([time.timestamp() for _, time in dated])
    width = max(3600, math.ceil((max(stamps) - min(stamps)) / (511 * 3600)) * 3600)
    start = math.floor(min(stamps) / width) * width
    bins = int((max(stamps) - start) // width) + 1
    total = np.zeros(bins, dtype=int)
    series = {}
    actors = [a for a, _ in Counter(r["actor"] for r, _ in dated if r["actor"]).most_common(40)]
    for a in actors:
        series[a] = np.zeros(bins, dtype=int)
    for r, time in dated:
        index = int((time.timestamp() - start) // width)
        total[index] += 1
        if r["actor"] in series:
            series[r["actor"]][index] += 1
    pairs = []
    for a, b in combinations(actors, 2):
        x, y = series[a], series[b]
        if bins >= 8 and np.count_nonzero(x) >= 3 and np.count_nonzero(y) >= 3 and np.std(x) and np.std(y):
            pairs.append({"a": a, "b": b, "pearson": float(np.corrcoef(x, y)[0, 1]), "bins": bins})
    baseline_n = max(4, bins // 4)
    alarms, upper, lower = [], 0.0, 0.0
    if bins >= 16:
        mean = float(np.mean(total[:baseline_n]))
        scale = max(1.0, float(np.std(total[:baseline_n], ddof=1)))
        for i, value in enumerate(total[baseline_n:], baseline_n):
            z = (value - mean) / scale
            upper, lower = max(0, upper + z - .5), min(0, lower + z + .5)
            if upper > 5 or lower < -5:
                alarms.append({"bin": i, "direction": "increase" if upper > 5 else "decrease", "count": int(value)})
                upper = lower = 0.0
    rhythm = []
    for a in actors:
        times = sorted(time.timestamp() for r, time in dated if r["actor"] == a)
        gaps = np.diff(times)
        if len(gaps) >= 4 and np.mean(gaps) > 0:
            rhythm.append({"actor": a, "events": len(times), "mean_interval_seconds": float(np.mean(gaps)),
                           "interval_cv": float(np.std(gaps) / np.mean(gaps))})
    result = {"status": "ok", "bin_seconds": width, "timezone": "UTC; naive dates interpreted as UTC",
              "start": datetime.fromtimestamp(start, timezone.utc).isoformat(), "counts": total.tolist(),
              "dated": len(dated), "undated": len(rows)-len(dated), "actor_limit": 40,
              "actor_correlations": sorted(pairs, key=lambda r: -abs(r["pearson"]))[:100],
              "rhythms": rhythm, "utc_hour_counts": dict(sorted(Counter(time.hour for _, time in dated).items())),
              "cusum": {"baseline_bins": baseline_n, "k": .5, "h": 5, "alarms": alarms},
              "forecast": {"status": "insufficient_data", "detail": "At least 24 bins with varying counts required"},
              "stl": {"status": "insufficient_data", "detail": "At least two explicit seasonal periods required"}}
    if bins >= 24 and np.std(total):
        from statsmodels.tsa.arima.model import ARIMA
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            fit = ARIMA(total, order=(1, 0, 0)).fit(method_kwargs={"maxiter": 50})
        if fit.mle_retvals.get("converged", False):
            forecast = fit.get_forecast(steps=5)
            result["forecast"] = {"status": "ok", "model": "ARIMA(1,0,0)",
                                  "mean": forecast.predicted_mean.tolist(), "interval_95": forecast.conf_int().tolist(),
                                  "meaning": "Exploratory next-bin counts; no validated predictive accuracy"}
        else:
            result["forecast"] = {"status": "error", "detail": "ARIMA did not converge"}
    if bins >= period * 2:
        from statsmodels.tsa.seasonal import STL
        fit = STL(total, period=period, robust=True).fit()
        result["stl"] = {"status": "ok", "period_bins": period, "trend": fit.trend.tolist(),
                         "seasonal": fit.seasonal.tolist(), "residual": fit.resid.tolist()}
    return result


def networks(rows, graph):
    import networkx as nx
    g = nx.Graph()
    for row in (graph or {}).get("nodes", [])[:600]:
        g.add_node(str(row["id"]), label=str(row.get("label", row["id"])))
    for edge in (graph or {}).get("edges", [])[:1500]:
        a, b = str(edge.get("source", "")), str(edge.get("target", ""))
        if a in g and b in g and a != b:
            g.add_edge(a, b)
    omitted = 0
    for row in rows:
        a, b = row["relation_source"], row["relation_target"]
        if not a or not b or a == b:
            continue
        if len(set((a, b)) - set(g)) + len(g) > 600 or g.number_of_edges() >= 1500:
            omitted += 1
            continue
        g.add_edge(a, b)
    if not g.number_of_edges():
        return {"status": "insufficient_data", "detail": "Explicit source/target relationships or dossier graph required"}
    groups = nx.community.louvain_communities(g, seed=SEED)
    communities = [sorted(c) for c in sorted(groups, key=lambda c: (-len(c), min(c)))]
    degree = nx.degree_centrality(g)
    between = nx.betweenness_centrality(g, k=min(64, len(g)), seed=SEED)
    pagerank = nx.pagerank(g, max_iter=200)
    hubs = [{"id": node, "label": g.nodes[node].get("label", node), "degree": degree[node],
             "betweenness": between[node], "pagerank": pagerank[node]} for node in g]
    # shortcut: Girvan-Newman is limited to 80 nodes/200 edges; use Louvain for larger graphs.
    gn = ({"status": "ok", "communities": [sorted(c) for c in next(nx.community.girvan_newman(g))]}
          if len(g) <= 80 and g.number_of_edges() <= 200 else {"status": "skipped", "detail": "Girvan-Newman limit: 80 nodes / 200 edges"})
    return {"status": "ok", "nodes": len(g), "edges": g.number_of_edges(), "omitted_relations": omitted,
            "meaning": "Undirected topology of supplied candidate evidence, not a social identity graph",
            "louvain": communities, "modularity": float(nx.community.modularity(g, groups)),
            "girvan_newman": gn, "hubs": sorted(hubs, key=lambda r: -r["pagerank"])[:100]}


def texts(rows):
    from sklearn.feature_extraction.text import TfidfVectorizer
    docs = [r for r in rows if len(r["text"].strip()) >= 10][:500]
    if len(docs) < 2:
        return {"status": "insufficient_data", "detail": "At least two texts of ten characters required"}
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2), sublinear_tf=True)
    try:
        matrix = vectorizer.fit_transform(r["text"] for r in docs)
    except ValueError:
        return {"status": "insufficient_data", "detail": "No usable text vocabulary"}
    similarity = (matrix @ matrix.T).toarray()
    pairs = [{"a": docs[i]["ref"], "b": docs[j]["ref"], "cosine": float(similarity[i, j])}
             for i, j in combinations(range(len(docs)), 2) if similarity[i, j] >= .8]
    ranks = sorted(zip(vectorizer.get_feature_names_out(), np.asarray(matrix.sum(axis=0)).ravel()), key=lambda p: -p[1])
    return {"status": "ok", "documents": len(docs), "omitted_texts": sum(bool(r["text"]) for r in rows)-len(docs),
            "vocabulary": matrix.shape[1], "threshold": .8, "pairs_total": len(pairs),
            "similar_pairs": sorted(pairs, key=lambda r: -r["cosine"])[:100],
            "top_terms": [{"term": term, "weight": float(weight)} for term, weight in ranks[:30]],
            "meaning": "Lexical similarity, not authorship or synthetic-text detection"}


def spatial(rows, radius):
    from sklearn.cluster import DBSCAN
    from sklearn.neighbors import KernelDensity, NearestNeighbors
    located = [r for r in rows if r["latitude"] is not None and r["longitude"] is not None][:1000]
    if len(located) < 3:
        return {"status": "insufficient_data", "detail": "At least three valid WGS84 points required"}
    coords = np.radians([[r["latitude"], r["longitude"]] for r in located])
    eps = radius / 6371.0088
    labels = DBSCAN(eps=eps, min_samples=3, metric="haversine", algorithm="ball_tree").fit_predict(coords)
    kde = KernelDensity(bandwidth=eps, metric="haversine", kernel="gaussian", algorithm="ball_tree").fit(coords)
    density = kde.score_samples(coords)
    result = {"status": "ok", "radius_km": radius, "min_samples": 3, "located": len(located),
              "omitted_points": sum(r["latitude"] is not None and r["longitude"] is not None for r in rows)-len(located),
              "clusters": len(set(labels)-{-1}), "noise": int(np.sum(labels == -1)),
              "points": [{"ref": r["ref"], "latitude": r["latitude"], "longitude": r["longitude"],
                          "cluster": int(c), "kde_log_score": float(d)} for r, c, d in zip(located, labels, density)],
              "kde_meaning": "Relative spherical-kernel scores at observed points; not calibrated probability density per square kilometre",
              "moran": {"status": "insufficient_data", "detail": "Eight located measured numeric value records required"}}
    measured = [i for i, r in enumerate(located) if "value" in r["metrics"]]
    if len(measured) >= 8:
        values = np.array([located[i]["metrics"]["value"] for i in measured])
        if np.std(values):
            positions = coords[measured]
            indices = NearestNeighbors(n_neighbors=min(6, len(measured)), metric="haversine", algorithm="ball_tree").fit(positions).kneighbors(positions, return_distance=False)
            weights = np.zeros((len(measured), len(measured)))
            for i, near in enumerate(indices):
                weights[i, near[near != i][:5]] = 1
            weights = np.maximum(weights, weights.T)
            z = values-values.mean()
            def statistic(v):
                return float(len(v)/weights.sum() * (v @ weights @ v)/(v @ v))
            observed = statistic(z)
            rng = np.random.default_rng(SEED)
            trials = [statistic(rng.permutation(z)) for _ in range(99)]
            expected = -1/(len(z)-1)
            result["moran"] = {"status": "ok", "n": len(z), "i": observed,
                               "permutation_p_two_sided": (1+sum(abs(v-expected) >= abs(observed-expected) for v in trials))/100,
                               "permutations": 99, "weights": "symmetric five nearest neighbours"}
    return result


def multivariate(rows):
    from sklearn.decomposition import PCA
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
    from sklearn.manifold import TSNE
    from sklearn.metrics import balanced_accuracy_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    fields = [key for key, n in Counter(k for r in rows for k in r["metrics"]).most_common(12) if n >= max(8, len(rows)//2)]
    complete = [r for r in rows if fields and all(k in r["metrics"] for k in fields)][:1000]
    if len(complete) < 8 or not fields:
        return {"status": "insufficient_data", "detail": "Eight complete numeric records required; missing values are not imputed"}
    x = np.array([[r["metrics"][k] for k in fields] for r in complete])
    varying = np.std(x, axis=0) > 0
    if not np.any(varying):
        return {"status": "insufficient_data", "detail": "All numeric fields are constant"}
    x = StandardScaler().fit_transform(x[:, varying])
    fields = [k for k, keep in zip(fields, varying) if keep]
    pca = PCA(n_components=min(2, len(fields)), random_state=SEED)
    projection = pca.fit_transform(x)
    iso = IsolationForest(n_estimators=100, contamination="auto", random_state=SEED, n_jobs=1).fit(x)
    result = {"status": "ok", "fields": fields, "n": len(complete), "complete_case_only": True,
              "isolation_forest": [{"ref": r["ref"], "score": float(score), "candidate_anomaly": bool(label == -1)}
                                   for r, score, label in zip(complete, iso.decision_function(x), iso.predict(x))],
              "pca_variance_ratio": pca.explained_variance_ratio_.tolist(),
              "pca": [{"ref": r["ref"], "point": p.tolist()} for r, p in zip(complete, projection)],
              "tsne": {"status": "insufficient_data"}, "classification": {"status": "insufficient_data", "detail": "At least forty labelled records and ten examples per class required"}}
    if len(complete) >= 12 and len(fields) >= 2:
        sample = x[:300]
        projection = TSNE(n_components=2, perplexity=min(30, (len(sample)-1)/3), init="pca", learning_rate="auto", random_state=SEED).fit_transform(sample)
        result["tsne"] = {"status": "ok", "points": [{"ref": r["ref"], "point": p.tolist()} for r, p in zip(complete[:300], projection)]}
    labelled = [r for r in complete if r["label"]]
    labels = Counter(r["label"] for r in labelled)
    if len(labelled) >= 40 and 2 <= len(labels) <= 10 and min(labels.values()) >= 10:
        x = np.array([[r["metrics"][k] for k in fields] for r in labelled])
        y = [r["label"] for r in labelled]
        train, test = train_test_split(np.arange(len(y)), test_size=.3, stratify=y, random_state=SEED)
        models = {}
        for name, model in (("random_forest", RandomForestClassifier(n_estimators=100, max_depth=6, random_state=SEED, n_jobs=1)),
                            ("gradient_boosting", GradientBoostingClassifier(n_estimators=50, max_depth=2, random_state=SEED))):
            model.fit(x[train], np.array(y)[train])
            models[name] = {"balanced_accuracy": float(balanced_accuracy_score(np.array(y)[test], model.predict(x[test]))),
                            "feature_importance": dict(zip(fields, model.feature_importances_.tolist()))}
        result["classification"] = {"status": "ok", "train": len(train), "test": len(test), "models": models,
                                    "meaning": "Stratified holdout on supplied labels, not an independently validated identity/bot/AI detector"}
    return result


def analyze(data, *, radius_km=5.0, period=24, model_output=None):
    if not .1 <= radius_km <= 100 or not 2 <= period <= 168:
        raise ValueError("Radius must be 0.1–100 km and seasonal period 2–168 bins")
    rows, coverage = normalize(data)
    graph = data.get("relationship_graph") if isinstance(data, dict) else None
    if isinstance(data, dict) and isinstance(data.get("sections"), dict) and not graph:
        graph = evidence_graph.build_graph(data)
    result = {"schema_version": 1, "seed": SEED, "rows": rows, "coverage": {**coverage, "retained": len(rows)},
              "parameters": {"radius_km": radius_km, "seasonal_period_bins": period}, "limitations": LIMITATIONS,
              "methods": {}, "versions": {"numpy": np.__version__}}
    import importlib.metadata
    for package in ("scipy", "scikit-learn", "statsmodels", "networkx", "torch", "transformers", "umap-learn", "pykrige"):
        try:
            result["versions"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result["versions"][package] = "not installed"
    from . import analytics_models as models
    for name, fn in (("descriptive", lambda: describe(rows)), ("correlations", lambda: correlations(rows)),
                     ("temporal", lambda: temporal(rows, period)), ("network", lambda: networks(rows, graph)),
                     ("text", lambda: texts(rows)), ("spatial", lambda: spatial(rows, radius_km)),
                     ("multivariate", lambda: multivariate(rows)), ("bert", lambda: models.bert(rows)),
                     ("lstm", lambda: models.lstm_autoencoder(result["methods"].get("temporal", {}), model_output)),
                     ("umap", lambda: models.umap_projection(rows, result["methods"].get("bert", {}))),
                     ("kriging", lambda: models.kriging(rows)), ("triangulation", lambda: models.triangulation(rows))):
        try:
            with warnings.catch_warnings(), np.errstate(over="raise", divide="raise", invalid="raise"):
                warnings.simplefilter("ignore", RuntimeWarning)
                result["methods"][name] = fn()
        except ImportError:
            result["methods"][name] = {"status": "unavailable", "detail": "Install setup-analysis.bat dependencies"}
        except (ValueError, RuntimeError, OSError, ArithmeticError, np.linalg.LinAlgError) as exc:
            result["methods"][name] = {"status": "error", "detail": type(exc).__name__ + "; calculation failed on this sample"}
    result["status"] = "partial" if coverage.get("truncated") or coverage.get("structure_limit") or any(
        m["status"] in {"error", "unavailable", "partial"} for m in result["methods"].values()) else "ok" if rows else "empty"
    return result


def summary(result):
    from .markdown_export import _text
    lines = ["# Statistical analysis", "", "Status: " + result["status"],
             "Retained observations: " + str(result["coverage"]["retained"]), "",
             "Seed: 42. Versions: " + json.dumps(result["versions"], sort_keys=True), "",
             "Parameters: " + json.dumps(result["parameters"], sort_keys=True), "",
             "## Methods", "", "| Method | Status | Detail |", "| --- | --- | --- |"]
    for name, part in result["methods"].items():
        lines.append(f"| {name} | {part['status']} | {part.get('detail', '')} |")
    lines += ["", "## Numeric distributions", "", "| Field | N | Missing | Mean | Median | Sample SD | Q1 | Q3 |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for key, row in result["methods"].get("descriptive", {}).get("fields", {}).items():
        safe = _text(key)
        lines.append("| " + " | ".join(str(x) for x in [safe, row["n"], row["missing"], row["mean"], row["median"], row["std_sample"], row["q1"], row["q3"]]) + " |")
    methods = result["methods"]
    for name in ("bert", "lstm", "umap", "kriging", "triangulation"):
        part = methods.get(name, {})
        if not part:
            continue
        lines += ["", "### " + name.upper(), "", "Status: " + _text(part.get("status")), ""]
        if name == "bert" and part.get("status") == "ok":
            lines += ["Model: " + _text(part["model"]) + "; dimensions: " + str(part["dimensions"]), "",
                      "| Record A | Record B | Semantic cosine |", "| --- | --- | --- |"]
            lines += [f"| {r['a']} | {r['b']} | {r['cosine']:.4f} |" for r in part.get("similar_pairs", [])[:20]]
        elif name == "lstm" and part.get("status") == "ok":
            lines += [f"Window: {part['window_bins']} bins; epochs: {part['epochs']}; calibration threshold: {part['threshold']:.6f}; holdout MSE: {part['test_mse']:.6f}.", "",
                      "Train / calibration / test bins: " + _text(str([part['training_bins'], part['calibration_bins'], part['test_bins']])), ""]
        elif name == "umap":
            for label, space in part.get("spaces", {}).items():
                lines += ["- " + _text(label) + ": " + _text(space["status"]) + "; " + str(space.get("n", 0)) + " projected records."]
        elif name == "kriging" and part.get("status") == "ok":
            lines += ["| Estimated latitude | Longitude | Interpolated value | Model variance |", "| --- | --- | --- | --- |"]
            lines += [f"| {p['latitude']:.6f} | {p['longitude']:.6f} | {p['value']:.4f} | {p['variance']:.4f} |" for p in part["points"][:20]]
        elif name == "triangulation":
            for target in part.get("targets", []):
                lines += ["- " + _text(target["target_id"]) + ": " + _text(target["status"])]
                if "latitude" in target:
                    lines += [f"  - Estimated coordinates: {target['latitude']:.6f}, {target['longitude']:.6f}",
                              "  - Conditional 95% ellipse axes (metres): " + _text(str(target["ellipse_95_semi_axes_m"]))]
                lines += ["  - " + _text(target.get("detail", ""))]
        if part.get("detail"):
            lines += ["", _text(part["detail"])]
    lines += ["", "## Limits", "", *["- " + value for value in LIMITATIONS], "",
              "Full calculations and record references: analytics.json. Original input SHA-256 is retained in dossier artifacts.", ""]
    return "\n".join(lines)


def html_report(analysis):
    def table(headers, rows):
        return "<table><thead><tr>" + "".join("<th>"+html.escape(str(x))+"</th>" for x in headers) + "</tr></thead><tbody>" + "".join(
            "<tr>" + "".join("<td>"+html.escape(str(round(x, 4) if isinstance(x, float) else x))+"</td>" for x in row) + "</tr>" for row in rows) + "</tbody></table>"
    methods = analysis["methods"]
    body = "<h1>FindAll statistical report</h1><p>" + str(analysis["coverage"]["retained"]) + " retained observations · " + analysis["status"] + "</p>"
    body += "<p>Exploratory sample analysis. Signals require source review and independent verification.</p>"
    body += "<h2>Coverage</h2>" + table(["Method", "Status", "Detail"], [(k, v["status"], v.get("detail", "")) for k, v in methods.items()])
    body += "<h2>Numeric distributions</h2>" + table(["Field", "N", "Missing", "Mean", "Median", "SD", "Q1", "Q3"],
        [(k, *[v[x] for x in ("n", "missing", "mean", "median", "std_sample", "q1", "q3")]) for k, v in methods["descriptive"].get("fields", {}).items()])
    body += "<h2>Numeric correlations</h2>" + table(["Field A", "Field B", "N", "Pearson", "Spearman", "BH q"],
        [tuple(r[k] for k in ("a", "b", "n", "pearson", "spearman", "q_bh")) for r in methods["correlations"].get("pairs", [])[:30]])
    time = methods["temporal"]
    series = time.get("counts", [])
    if series:
        peak = max(series) or 1
        body += '<h2>Observed activity</h2><p>Start: ' + html.escape(time["start"]) + '; bin width: ' + str(time["bin_seconds"]) + ' seconds (UTC).</p><svg role="img" aria-label="Observed event counts" viewBox="0 0 900 180">'
        for i, n in enumerate(series):
            body += f'<rect x="{i*900/len(series):.2f}" y="{180-n/peak*170:.2f}" width="{max(.5,900/len(series)-1):.2f}" height="{n/peak*170:.2f}" fill="#209b92"><title>Bin {i}: {n} events</title></rect>'
        body += "</svg>"
        body += table(["Actor A", "Actor B", "Pearson", "Bins"], [tuple(r[k] for k in ("a", "b", "pearson", "bins")) for r in time.get("actor_correlations", [])[:20]])
        body += "<p>CUSUM review signals: " + str(len(time["cusum"]["alarms"])) + ". ARIMA: " + html.escape(time["forecast"]["status"]) + ". STL: " + html.escape(time["stl"]["status"]) + ".</p>"
    network = methods["network"]
    body += "<h2>Graph topology</h2><p>" + str(len(network.get("louvain", []))) + " Louvain communities; candidate evidence topology, not proof of affiliation.</p>"
    body += table(["Node", "Degree", "Betweenness (sampled)", "PageRank"], [tuple(r[k] for k in ("label", "degree", "betweenness", "pagerank")) for r in network.get("hubs", [])[:20]])
    body += "<h2>Lexical similarity</h2>" + table(["Record A", "Record B", "TF-IDF cosine"], [tuple(r[k] for k in ("a", "b", "cosine")) for r in methods["text"].get("similar_pairs", [])[:20]])
    geo = methods["spatial"]
    body += "<h2>Geographic observations</h2><p>DBSCAN clusters: " + str(geo.get("clusters", 0)) + "; noise points: " + str(geo.get("noise", 0)) + ". Coordinates remain externally unverified.</p>"
    body += table(["Record", "Latitude", "Longitude", "Cluster", "Relative KDE log score"], [tuple(r[k] for k in ("ref", "latitude", "longitude", "cluster", "kde_log_score")) for r in geo.get("points", [])[:30]])
    bert = methods.get("bert", {})
    body += "<h2>BERT semantic similarity</h2><p>" + html.escape(str(bert.get("model", bert.get("detail", "")))) + "</p>"
    body += table(["Record A", "Record B", "Embedding cosine"], [tuple(r[k] for k in ("a", "b", "cosine")) for r in bert.get("similar_pairs", [])[:30]])
    lstm = methods.get("lstm", {})
    body += "<h2>LSTM activity reconstruction</h2><p>" + html.escape(str(lstm.get("detail", lstm.get("meaning", "")))) + "</p>"
    body += table(["Window end bin", "Partition", "Reconstruction MSE", "Review signal"], [tuple(r[k] for k in ("end_bin", "partition", "mse", "candidate_anomaly")) for r in lstm.get("scores", []) if r["partition"] == "test"][:50])
    for space, values in methods.get("umap", {}).get("spaces", {}).items():
        body += "<h2>UMAP " + html.escape(space) + "</h2>" + table(["Source record", "UMAP 1", "UMAP 2"], [(r["ref"], *r["point"]) for r in values.get("points", [])[:30]])
    body += "<h2>Kriging field estimates</h2>" + table(["Latitude", "Longitude", "Interpolated value", "Model variance"],
        [tuple(r[k] for k in ("latitude", "longitude", "value", "variance")) for r in methods.get("kriging", {}).get("points", [])[:50]])
    body += "<h2>Triangulation and multilateration</h2>" + table(["Target label", "Status", "Latitude", "Longitude", "Conditional 95% ellipse axes (m)", "Source records"],
        [(r["target_id"], r["status"], r.get("latitude", ""), r.get("longitude", ""), r.get("ellipse_95_semi_axes_m", ""), r.get("input_refs", "")) for r in methods.get("triangulation", {}).get("targets", [])])
    body += "<h2>Record references</h2>" + table(["Ref", "Source", "URL", "Event time", "Actor label"],
        [(r["ref"], r["source"], r["source_url"], r["timestamp"], r["actor"]) for r in analysis["rows"][:100]])
    body += "<p>First 100 references displayed. Full record mapping, numeric outputs and parameters are in analytics.json.</p>"
    body += "<h2>Reproducibility and limits</h2><p>Seed: 42; parameters " + html.escape(json.dumps(analysis["parameters"])) + ". Versions: " + html.escape(json.dumps(analysis["versions"])) + "</p><ul>" + "".join("<li>"+html.escape(x)+"</li>" for x in LIMITATIONS) + "</ul>"
    for name in methods:
        body += "<details><summary>" + name.title() + " full calculations</summary><pre>" + html.escape(json.dumps(methods[name], ensure_ascii=False, indent=2)) + "</pre></details>"
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>FindAll statistics</title><style>body{max-width:1100px;margin:32px auto;padding:16px;background:#0e141c;color:#ebf2f7;font:16px system-ui}table{border-collapse:collapse;width:100%;display:block;overflow:auto}td,th{padding:9px;border:1px solid #30404d;text-align:left;overflow-wrap:anywhere}th{background:#17202a}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer;padding:12px}svg{width:100%;background:#17202a}</style>' + body + '</html>'


def run(path, output, *, radius_km=5.0, period=24):
    from . import dossier
    data, artifact = load(path)
    query = str(data.get("query") or Path(path).stem) if isinstance(data, dict) else Path(path).stem
    folder = dossier._folder(Path(output) / "dossiers", query + " statistics")
    analysis = analyze(data, radius_km=radius_km, period=period, model_output=folder)
    report = copy.deepcopy(data) if isinstance(data, dict) and isinstance(data.get("sections"), dict) else {
        "query": query, "kind": "dataset", "scope": "offline", "sections": {"web": [], "profiles": [], "emails": [], "domain": {}},
        "source_checks": [], "errors": [], "artifacts": []}
    # Source dossiers stay untouched; analysis is always a new version.
    report.pop("ai_analysis", None)
    report.pop("exported_paths", None)
    report.pop("analytics", None)
    for key in ("web", "profiles", "emails"):
        report["sections"].setdefault(key, [])
    report["sections"].setdefault("domain", {})
    for key in ("artifacts", "source_checks", "errors"):
        report.setdefault(key, [])
    report["observed_at"] = datetime.now(timezone.utc).isoformat()
    report["report_json"], report["report_csv"] = str(folder / "dossier.json"), str(folder / "dossier.csv")
    report.setdefault("artifacts", []).append(artifact)
    weights = analysis["methods"].get("lstm", {}).get("weights")
    if weights:
        report["artifacts"].append(weights)
    report["analytics"] = analysis
    for row in analysis["rows"]:
        row["sha256"] = artifact["sha256"]
        row["attribution"] = "imported observation; externally unverified"
    report["sections"]["analysis_observations"] = analysis["rows"]
    analysis_path = folder / "analytics.json"
    analysis_path.write_text(json.dumps(analysis, ensure_ascii=False, indent=2, allow_nan=False), encoding="utf-8")
    sha = hashlib.sha256(analysis_path.read_bytes()).hexdigest()
    report["artifacts"].append({"kind": "statistical_calculations", "path": str(analysis_path), "sha256": sha})
    report["sections"]["statistics"] = [{"title": name + " statistical calculation", "sha256": sha,
        "source": "FindAll offline statistics", "status": part["status"], "attribution": "interpretation; exploratory sample statistics",
        "text": json.dumps({k: v for k, v in part.items() if k not in {"points", "pca", "tsne", "isolation_forest", "embeddings", "scores", "spaces"}}, ensure_ascii=False)[:3500],
        "observed_at": report["observed_at"]} for name, part in analysis["methods"].items()]
    for name, part in analysis["methods"].items():
        dossier._record_check(report, {"source": "Statistics: " + name, "state": "empty" if part["status"] == "insufficient_data" else part["status"],
                                       "count": len(analysis["rows"]), "detail": part.get("detail", "Exploratory calculation; see analytics.json")})
    (folder / "dossier.csv").touch()
    (folder / "analytics.md").write_text(summary(analysis), encoding="utf-8")
    (folder / "analytics.html").write_text(html_report(analysis), encoding="utf-8")
    report["exported_paths"] = {"analytics_json": str(analysis_path), "analytics_markdown": str(folder / "analytics.md"), "analytics_html": str(folder / "analytics.html")}
    return dossier.save_relationship_graph(report)
