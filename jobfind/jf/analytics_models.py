"""Local numerical/learned analysis; no dataset is uploaded or executed."""
from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import numpy as np

SEED = 42
EARTH_M = 6371008.8
BERT_REPO = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
BERT_REVISION = "e8f8c211226b894fcb81acc59f3b34ba3efd5f42"
BERT_DIR = Path(__file__).resolve().parents[1] / "third_party" / "models" / "multilingual-minilm"


def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_bert():
    from huggingface_hub import snapshot_download
    snapshot_download(BERT_REPO, revision=BERT_REVISION, token=False, local_dir=BERT_DIR,
                      allow_patterns=["config.json", "tokenizer.json", "tokenizer_config.json",
                                      "special_tokens_map.json", "model.safetensors", "README.md",
                                      "sentence_bert_config.json"], max_workers=2)
    files = {p.name: checksum(p) for p in BERT_DIR.iterdir() if p.is_file() and p.name != "findall-model.json"}
    if not {"config.json", "tokenizer.json", "model.safetensors"} <= files.keys():
        raise ValueError("BERT model download is incomplete")
    manifest = {"repository": BERT_REPO, "revision": BERT_REVISION, "files": files}
    (BERT_DIR / "findall-model.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"status": "ok", "repository": BERT_REPO, "revision": BERT_REVISION, "path": str(BERT_DIR), "files": files}


@lru_cache(maxsize=1)
def _bert_components(folder):
    manifest_path = folder / "findall-model.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("revision") != BERT_REVISION or manifest.get("repository") != BERT_REPO:
        raise ValueError("Unexpected BERT model manifest")
    required = {"config.json", "tokenizer.json", "model.safetensors"}
    if not isinstance(manifest.get("files"), dict) or not required <= manifest["files"].keys():
        raise ValueError("Incomplete BERT model manifest")
    for filename, expected in manifest["files"].items():
        if Path(filename).name != filename or checksum(folder / filename) != expected:
            raise ValueError("BERT file integrity check failed; install the pinned model again")
    import torch
    from transformers import AutoModel, AutoTokenizer
    torch.set_num_threads(2)
    tokenizer = AutoTokenizer.from_pretrained(folder, local_files_only=True, trust_remote_code=False)
    model = AutoModel.from_pretrained(folder, local_files_only=True, trust_remote_code=False, use_safetensors=True).eval()
    if model.config.model_type != "bert":
        raise ValueError("Expected a BERT architecture")
    return tokenizer, model, manifest


def embed_texts(texts):
    import torch
    tokenizer, model, _manifest = _bert_components(BERT_DIR)
    vectors = []
    with torch.inference_mode():
        for start in range(0, len(texts), 16):
            encoded = tokenizer(texts[start:start+16], padding=True, truncation=True,
                                max_length=128, return_tensors="pt")
            hidden = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1)
            pooled = (hidden*mask).sum(1)/mask.sum(1).clamp(min=1)
            vectors.extend(torch.nn.functional.normalize(pooled, dim=1).cpu().numpy())
    return np.array(vectors, dtype=np.float32)


def bert(rows):
    docs = [r for r in rows if len(r["text"].strip()) >= 10][:300]
    if len(docs) < 2:
        return {"status": "insufficient_data", "detail": "BERT requires two texts of at least ten characters"}
    if not (BERT_DIR / "findall-model.json").is_file():
        return {"status": "unavailable", "detail": "Choose Install BERT model once; analysis then runs offline"}
    matrix = embed_texts([r["text"] for r in docs])
    manifest = _bert_components(BERT_DIR)[2]
    similarity = matrix @ matrix.T
    pairs = [{"a": docs[i]["ref"], "b": docs[j]["ref"], "cosine": float(np.clip(similarity[i, j], -1, 1))}
             for i in range(len(docs)) for j in range(i+1, len(docs)) if similarity[i, j] >= .8]
    return {"status": "ok", "model": BERT_REPO, "revision": BERT_REVISION, "architecture": "BertModel",
            "weight_sha256": manifest["files"]["model.safetensors"], "documents": len(docs), "dimensions": matrix.shape[1],
            "max_tokens": 128, "omitted_texts": sum(len(r["text"].strip()) >= 10 for r in rows)-len(docs),
            "embeddings": [{"ref": r["ref"], "vector": v.tolist()} for r, v in zip(docs, matrix)],
            "similar_pairs_total": len(pairs), "similar_pairs": sorted(pairs, key=lambda p: -p["cosine"])[:100],
            "meaning": "Pretrained multilingual sentence-BERT cosine similarity; not authorship or identity proof"}


def umap_projection(rows, bert_result):
    from umap import UMAP
    from sklearn.preprocessing import StandardScaler
    spaces = {}
    fields = sorted({key for row in rows for key in row["metrics"]})[:12]
    complete = [r for r in rows if fields and all(k in r["metrics"] for k in fields)][:500]
    matrices = []
    if len(complete) >= 8:
        raw = np.array([[r["metrics"][key] for key in fields] for r in complete])
        varying = np.std(raw, axis=0) > 0
        if np.any(varying):
            matrices.append(("numeric", StandardScaler().fit_transform(raw[:, varying]), [r["ref"] for r in complete]))
    embeddings = bert_result.get("embeddings", [])
    if len(embeddings) >= 8:
        matrices.append(("bert_semantic", np.array([r["vector"] for r in embeddings]), [r["ref"] for r in embeddings]))
    for name, matrix, refs in matrices:
        if len(np.unique(np.round(matrix, 6), axis=0)) < 3:
            spaces[name] = {"status": "insufficient_data", "detail": "At least three distinct feature vectors required"}
            continue
        n = min(15, len(matrix)-1)
        projected = UMAP(n_neighbors=n, n_components=2, n_epochs=200, random_state=SEED, n_jobs=1,
                         init="random", metric="cosine" if name == "bert_semantic" else "euclidean").fit_transform(matrix)
        if not np.isfinite(projected).all():
            raise ValueError("UMAP returned nonfinite coordinates")
        spaces[name] = {"status": "ok", "n_neighbors": n, "n": len(refs),
                        "points": [{"ref": ref, "point": point.tolist()} for ref, point in zip(refs, projected)]}
    return {"status": "ok" if any(s["status"] == "ok" for s in spaces.values()) else "insufficient_data",
            "detail": "UMAP projections preserve approximate neighbourhoods; chart distance is not calibrated evidence strength",
            "seed": SEED, "n_epochs": 200, "min_dist": .1, "numeric_fields": fields,
            "numeric_omitted": max(0, sum(bool(fields) and all(k in r["metrics"] for k in fields) for r in rows)-500), "spaces": spaces}


def lstm_autoencoder(temporal, output=None):
    values = np.asarray(temporal.get("counts", []), dtype=np.float32)
    if len(values) < 120:
        return {"status": "insufficient_data", "detail": "LSTM requires 120 dated activity bins; uses observed counts, not collection timestamps"}
    if not np.isfinite(values).all() or np.any(values < 0):
        raise ValueError("LSTM counts must be finite and nonnegative")
    import torch
    from torch import nn
    window, epochs = 12, 40
    train_end, cal_end = int(len(values)*.6), int(len(values)*.8)
    raw = np.log1p(values)
    mean, scale = float(raw[:train_end].mean()), float(raw[:train_end].std())
    if scale < 1e-5:
        return {"status": "insufficient_data", "detail": "LSTM training prefix has constant activity"}
    scaled = (raw-mean)/scale
    def windows(begin, end):
        return np.stack([scaled[i:i+window] for i in range(begin, end-window+1)])[:, :, None]
    train, calibration, test = windows(0, train_end), windows(train_end, cal_end), windows(cal_end, len(values))

    class Autoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.LSTM(1, 8, batch_first=True)
            self.decoder = nn.LSTM(8, 8, batch_first=True)
            self.reconstruct = nn.Linear(8, 1)

        def forward(self, x):
            _, (hidden, _) = self.encoder(x)
            latent = hidden[-1].unsqueeze(1).repeat(1, window, 1)
            decoded, _ = self.decoder(latent)
            return self.reconstruct(decoded)

    torch.set_num_threads(2)
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(SEED)
        model = Autoencoder()
        optimizer = torch.optim.Adam(model.parameters(), lr=.01)
        training = torch.from_numpy(train)
        model.train()
        for _ in range(epochs):
            optimizer.zero_grad()
            loss = nn.functional.mse_loss(model(training), training)
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.inference_mode():
            def errors(x):
                tensor = torch.from_numpy(x)
                return ((model(tensor)-tensor)**2).mean(dim=(1, 2)).numpy()
            calibration_errors = errors(calibration)
            test_errors = errors(test)
            all_windows = windows(0, len(values))
            scores = errors(all_windows)
        threshold = max(1e-6, float(np.quantile(calibration_errors, .99)))
        state = {k: v.detach().cpu().contiguous() for k, v in model.state_dict().items()}
    digest = hashlib.sha256(b"".join(k.encode()+v.numpy().tobytes() for k, v in sorted(state.items()))).hexdigest()
    result = {"status": "ok", "model": "LSTM encoder-decoder autoencoder", "hidden_size": 8, "window_bins": window,
              "epochs": epochs, "seed": SEED, "training_bins": [0, train_end], "calibration_bins": [train_end, cal_end],
              "test_bins": [cal_end, len(values)], "normalization": {"transform": "log1p", "mean": mean, "scale": scale},
              "threshold": threshold, "threshold_quantile": .99, "test_mse": float(test_errors.mean()),
              "state_sha256": digest, "scores": [{"end_bin": i+window-1, "mse": float(score),
                  "partition": "train" if i+window <= train_end else "calibration" if i >= train_end and i+window <= cal_end else "test" if i >= cal_end else "boundary",
                  "candidate_anomaly": bool(score > threshold)} for i, score in enumerate(scores)],
              "meaning": "Reconstruction-error candidates, calibrated on a later prefix; no validated bot or threat detector"}
    if output is not None:
        from safetensors.torch import save_file
        path = Path(output) / "lstm-autoencoder.safetensors"
        save_file(state, str(path))
        result["weights"] = {"kind": "lstm_weights", "path": str(path), "sha256": checksum(path)}
    return result


def _basis(latitude, longitude):
    lat, lon = math.radians(latitude), math.radians(longitude)
    return (np.array([math.cos(lat)*math.cos(lon), math.cos(lat)*math.sin(lon), math.sin(lat)]),
            np.array([-math.sin(lon), math.cos(lon), 0]),
            np.array([-math.sin(lat)*math.cos(lon), -math.sin(lat)*math.sin(lon), math.cos(lat)]))


def project(coordinates, latitude, longitude):
    center, east, north = _basis(latitude, longitude)
    result = []
    for lat, lon in coordinates:
        unit = _basis(lat, lon)[0]
        angle = math.acos(float(np.clip(unit @ center, -1, 1)))
        k = angle/math.sin(angle) if angle > 1e-10 else 1.0
        result.append([EARTH_M*k*float(unit@east), EARTH_M*k*float(unit@north)])
    return np.array(result)


def unproject(points, latitude, longitude):
    center, east, north = _basis(latitude, longitude)
    output = []
    for x, y in points:
        distance = math.hypot(x, y)
        angle = distance/EARTH_M
        unit = math.cos(angle)*center + (math.sin(angle)/distance if distance else 0)*(x*east+y*north)
        output.append([math.degrees(math.asin(float(np.clip(unit[2], -1, 1)))), math.degrees(math.atan2(unit[1], unit[0]))])
    return np.array(output)


def kriging(rows):
    from pykrige.ok import OrdinaryKriging
    from scipy.spatial import ConvexHull, Delaunay
    groups = defaultdict(list)
    for row in rows:
        if row["latitude"] is not None and row["longitude"] is not None and "value" in row["metrics"]:
            groups[(row["latitude"], row["longitude"])].append(row)
    if len(groups) < 6:
        return {"status": "insufficient_data", "detail": "Kriging requires six distinct located numeric value measurements"}
    groups = dict(list(groups.items())[:200])
    coords = np.array(list(groups))
    values = np.array([np.mean([r["metrics"]["value"] for r in group]) for group in groups.values()])
    latitude = float(np.mean(coords[:, 0]))
    longitude = math.degrees(math.atan2(np.sin(np.radians(coords[:, 1])).mean(), np.cos(np.radians(coords[:, 1])).mean()))
    points = project(coords, latitude, longitude)
    if np.max(np.linalg.norm(points, axis=1)) > 250000:
        return {"status": "insufficient_data", "detail": "Kriging local field must fit within 250 km of its centre"}
    if np.linalg.matrix_rank(points-points.mean(axis=0), tol=1e-3) < 2 or np.std(values) < 1e-12:
        return {"status": "insufficient_data", "detail": "Kriging needs non-collinear locations and varying measurements"}
    model = OrdinaryKriging(points[:, 0], points[:, 1], values, variogram_model="spherical", nlags=6,
                            verbose=False, enable_plotting=False, pseudo_inv=True)
    grid_x, grid_y = np.meshgrid(np.linspace(points[:, 0].min(), points[:, 0].max(), 16),
                                 np.linspace(points[:, 1].min(), points[:, 1].max(), 16))
    grid = np.column_stack([grid_x.ravel(), grid_y.ravel()])
    grid = grid[Delaunay(points[ConvexHull(points).vertices]).find_simplex(grid) >= 0]
    predictions, variance = model.execute("points", grid[:, 0], grid[:, 1])
    locations = unproject(grid, latitude, longitude)
    return {"status": "ok", "model": "OrdinaryKriging / spherical variogram", "coordinate_model": "spherical azimuthal equidistant; metres",
            "centre": [latitude, longitude], "variogram_parameters": model.variogram_model_parameters.tolist(),
            "distinct_locations": len(groups), "duplicate_location_policy": "arithmetic mean at the same coordinate",
            "omitted_locations": max(0, len({(r['latitude'], r['longitude']) for r in rows if r['latitude'] is not None and r['longitude'] is not None and 'value' in r['metrics']})-200),
            "input_refs": [r["ref"] for group in groups.values() for r in group],
            "points": [{"latitude": float(lat), "longitude": float(lon), "value": float(value), "variance": max(0.0, float(var))}
                       for (lat, lon), value, var in zip(locations, predictions, variance)],
            "meaning": "Interpolation inside the measured convex hull only; variogram variance is model uncertainty, not independent verification"}


def triangulation(rows):
    from scipy.optimize import least_squares
    groups, invalid, omitted = defaultdict(list), 0, 0
    for row in rows:
        m = row.get("measurement") or {}
        if not m:
            continue
        lat, lon = m.get("observer_latitude"), m.get("observer_longitude")
        if not row.get("target_id") or lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            invalid += 1
            continue
        valid_bearing = m.get("bearing_deg") is not None and 0 <= m["bearing_deg"] < 360 and .01 <= (m.get("bearing_error_deg") or 0) <= 90
        valid_range = m.get("range_m") is not None and 0 < m["range_m"] <= 100000 and 0 < (m.get("range_error_m") or 0) <= 100000
        if not valid_bearing and not valid_range:
            invalid += 1
            continue
        if len(groups) >= 50 and row["target_id"] not in groups:
            omitted += 1
            continue
        groups[row["target_id"]].append((row, m, valid_bearing, valid_range))
    targets = []
    for target, records in groups.items():
        omitted += max(0, len(records)-100)
        records = records[:100]
        coords = np.array([[m["observer_latitude"], m["observer_longitude"]] for _, m, _, _ in records])
        if len(np.unique(coords, axis=0)) < 3:
            targets.append({"target_id": target, "status": "insufficient_data", "detail": "Three distinct observer locations required"})
            continue
        lat0 = float(coords[:, 0].mean())
        lon0 = math.degrees(math.atan2(np.sin(np.radians(coords[:, 1])).mean(), np.cos(np.radians(coords[:, 1])).mean()))
        xy = project(coords, lat0, lon0)
        if np.max(np.linalg.norm(xy, axis=1)) > 50000:
            targets.append({"target_id": target, "status": "insufficient_data", "detail": "Observer geometry must fit within 50 km of its centre"})
            continue
        normals = np.array([[math.cos(math.radians(m["bearing_deg"])), -math.sin(math.radians(m["bearing_deg"]))]
                            for _, m, b, _ in records if b])
        if all(b and not r for _, _, b, r in records) and np.linalg.matrix_rank(normals, tol=1e-5) < 2:
            targets.append({"target_id": target, "status": "insufficient_data", "detail": "Parallel bearings do not determine a location"})
            continue

        def residuals(candidate):
            lat, lon = np.radians(unproject([candidate], lat0, lon0)[0])
            result = []
            for _, m, has_bearing, has_range in records:
                observer_lat, observer_lon = math.radians(m["observer_latitude"]), math.radians(m["observer_longitude"])
                dl = lon-observer_lon
                if has_bearing:
                    bearing = math.atan2(math.sin(dl)*math.cos(lat), math.cos(observer_lat)*math.sin(lat)-math.sin(observer_lat)*math.cos(lat)*math.cos(dl))
                    delta = bearing-math.radians(m["bearing_deg"])
                    result.append(math.atan2(math.sin(delta), math.cos(delta))/math.radians(m["bearing_error_deg"]))
                if has_range:
                    a = math.sin((lat-observer_lat)/2)**2+math.cos(lat)*math.cos(observer_lat)*math.sin(dl/2)**2
                    distance = 2*EARTH_M*math.asin(math.sqrt(float(np.clip(a, 0, 1))))
                    result.append((distance-m["range_m"])/m["range_error_m"])
            return np.array(result)

        seeds = [xy.mean(axis=0)+[1, 1], *[np.array([x, y], dtype=float) for x, y in ((10000, 10000), (-10000, 10000), (10000, -10000), (-10000, -10000))]]
        if len(normals) >= 2 and np.linalg.matrix_rank(normals) == 2:
            observer_xy = np.array([position for position, (_, _, b, _) in zip(xy, records) if b])
            seeds.append(np.linalg.lstsq(normals, (normals*observer_xy).sum(axis=1), rcond=None)[0].clip(-99999, 99999))
        def jacobian(candidate):
            # Absolute metre steps stay resolvable when the solution is at the projection origin.
            return np.column_stack([(residuals(candidate+step)-residuals(candidate-step))/.2
                                    for step in (np.array([.1, 0]), np.array([0, .1]))])
        fits = [least_squares(residuals, seed.clip(-99999, 99999), jac=jacobian, bounds=(-100000, 100000), max_nfev=150) for seed in seeds]
        fit = min(fits, key=lambda f: float(f.fun @ f.fun))
        if not fit.success or np.linalg.matrix_rank(fit.jac, tol=1e-8) < 2 or np.linalg.norm(fit.x) > 100000:
            targets.append({"target_id": target, "status": "error", "detail": "Geometry did not yield a converged identifiable solution"})
            continue
        alternatives = [f for f in fits if np.linalg.norm(f.x-fit.x) > 100 and float(f.fun@f.fun) <= float(fit.fun@fit.fun)+1]
        if alternatives:
            targets.append({"target_id": target, "status": "insufficient_data", "detail": "Multiple locations fit; add another independent bearing or range"})
            continue
        covariance = np.linalg.inv(fit.jac.T @ fit.jac)
        eigenvalues, eigenvectors = np.linalg.eigh(covariance)
        location = unproject([fit.x], lat0, lon0)[0]
        dof = max(1, len(fit.fun)-2)
        inconsistent = float(fit.fun@fit.fun)/dof > 9
        targets.append({"target_id": target, "status": "partial" if inconsistent else "ok", "latitude": float(location[0]), "longitude": float(location[1]),
                        "input_refs": [r["ref"] for r, _, _, _ in records], "weighted_residuals": fit.fun.tolist(),
                        "reduced_chi_square": float(fit.fun@fit.fun)/dof, "covariance_metres2": covariance.tolist(),
                        "ellipse_95_semi_axes_m": np.sqrt(np.maximum(eigenvalues, 0)*5.991).tolist(),
                        "ellipse_major_bearing_deg": float(math.degrees(math.atan2(eigenvectors[0, -1], eigenvectors[1, -1])) % 180),
                        "detail": "Measurements conflict with their supplied errors; review before using the estimate" if inconsistent else "Weighted bearing/range solution",
                        "meaning": "Spherical-Earth estimate; ellipse is conditional on supplied independent Gaussian measurement errors, not a validated real-world accuracy guarantee"})
    return {"status": "partial" if invalid or omitted or any(t["status"] in {"error", "partial"} for t in targets) else "ok" if any(t["status"] == "ok" for t in targets) else "insufficient_data",
            "detail": "Bearing triangulation / range multilateration; explicit observer coordinates and calibrated errors required",
            "invalid_measurements": invalid, "omitted_measurements": omitted, "targets": targets}
