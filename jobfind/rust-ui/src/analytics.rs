use eframe::egui;
use serde_json::Value;

#[derive(Default)]
pub struct Workspace {
    pub path: String,
    pub result: Option<Value>,
    pub error: String,
    pub open_requested: bool,
    pub setup_requested: bool,
    pub model_status: String,
}

pub fn arguments(path: &str) -> Vec<String> {
    vec!["statistics".into(), "--path".into(), path.into()]
}

impl Workspace {
    pub fn show(&mut self, ui: &mut egui::Ui, busy: bool, examples: &std::path::Path) -> bool {
        crate::workspace_hero(
            ui,
            "📊",
            "Statistical intelligence",
            "Analyze saved evidence locally. Source files remain unchanged.",
            Some(("OFFLINE ENGINE", crate::theme::COLOR_INFO)),
        );
        let mut run = false;
        crate::card(ui, |ui| {
            ui.label(egui::RichText::new("Saved dossier or dataset").strong());
            let input = ui.horizontal(|ui| {
                let clear_needed = !self.path.is_empty();
                let width = if clear_needed {
                    (ui.available_width() - 44.0).max(100.0)
                } else {
                    ui.available_width()
                };
                let f = ui.add_sized(
                    [width, 36.0],
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("dossier.json · CSV · TSV · JSON · JSONL"),
                );
                if clear_needed {
                    if ui
                        .add_sized(
                            [36.0, 36.0],
                            egui::Button::new(
                                egui::RichText::new("✖")
                                    .size(13.0)
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .fill(egui::Color32::from_rgb(20, 26, 38))
                            .stroke(egui::Stroke::new(1.0, crate::theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(6)),
                        )
                        .on_hover_text("Clear dataset path")
                        .clicked()
                    {
                        self.path.clear();
                    }
                }
                f
            }).inner;
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Choose file…"))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Evidence data", &["json", "jsonl", "csv", "tsv"])
                        .pick_file()
                    {
                        self.path = path.to_string_lossy().into_owned();
                    }
                }
                let selection = ui.visuals().selection;
                let enabled = !busy && !self.path.trim().is_empty();
                run = ui
                    .add_enabled(
                        enabled,
                        egui::Button::new(
                            egui::RichText::new("Analyze data").color(selection.stroke.color).strong(),
                        )
                        .fill(selection.bg_fill),
                    )
                    .clicked()
                    || (enabled
                        && input.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                crate::kbd_badge(ui, "↵ Enter");
                if busy {
                    ui.spinner();
                    ui.label("Calculating…");
                }
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Up to 5,000 observations. Analysis stays local; model download is a separate action.").small().color(ui.visuals().weak_text_color()));
            ui.add_space(8.0);
            egui::CollapsingHeader::new("Models and input guide").show(ui, |ui| {
                ui.label("BERT: text. UMAP: numeric features or BERT vectors. LSTM: at least 120 dated activity bins.");
                ui.label("Kriging: six located numeric value measurements. Triangulation: target_id, three observer locations, bearings or ranges and their measurement errors.");
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(!busy, egui::Button::new("Install / repair BERT model")).clicked() {
                        self.setup_requested = true;
                    }
                    if ui.button("Open example datasets").clicked() { crate::open_url(&examples.to_string_lossy()); }
                });
                ui.label(egui::RichText::new("Model installation downloads public weights once. Dataset texts stay local.").small().color(ui.visuals().weak_text_color()));
                if !self.model_status.is_empty() { ui.label(&self.model_status); }
            });
        });
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        if let Some(report) = &self.result {
            let analysis = &report["analytics"];
            ui.add_space(16.0);
            crate::card(ui, |ui| {
                let retained = analysis["coverage"]["retained"].as_u64().unwrap_or(0);
                let status = analysis["status"].as_str().unwrap_or("unknown");
                let status_color = if status == "ok" || status == "complete" {
                    crate::theme::COLOR_SUCCESS
                } else {
                    crate::theme::COLOR_WARN
                };
                ui.horizontal_wrapped(|ui| {
                    crate::bento_chip(ui, "📈", "OBSERVATIONS", &format!("{retained}"), crate::theme::COLOR_INFO);
                    crate::bento_chip(ui, "⚡", "ENGINE STATUS", status, status_color);
                    let sources_cnt = analysis["coverage"]["sources"].as_array().map_or(0, Vec::len);
                    crate::bento_chip(ui, "🎯", "SOURCES", &format!("{sources_cnt} sources"), crate::theme::COLOR_ACCENT);
                });
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    for (label, key) in [
                        ("📄 Open report", "analytics_html"),
                        ("📝 Markdown", "analytics_markdown"),
                        ("📊 Calculations JSON", "analytics_json"),
                    ] {
                        if let Some(path) = report["exported_paths"][key].as_str() {
                            if ui.button(label).clicked() {
                                crate::open_url(path);
                            }
                        }
                    }
                    if let Some(path) = report["report_json"].as_str() {
                        if ui
                            .add_enabled(
                                !busy && !path.is_empty(),
                                egui::Button::new("🔍 View dossier / AI / diagram"),
                            )
                            .clicked()
                        {
                            self.open_requested = true;
                        }
                    }
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Correlations and clusters are review signals. They do not prove bots, identity or ownership.").small().color(ui.visuals().warn_fg_color));
            });
            ui.add_space(10.0);
            if let Some(methods) = analysis["methods"].as_object() {
                for (name, part) in methods {
                    egui::CollapsingHeader::new(format!(
                        "{} · {}",
                        name,
                        part["status"].as_str().unwrap_or("unknown")
                    ))
                        .default_open(name == "descriptive" || name == "bert" || name == "umap")
                    .show(ui, |ui| {
                        if let Some(detail) = part["detail"].as_str() {
                            ui.label(detail);
                        }
                        if name == "descriptive" {
                            if let Some(fields) = part["fields"].as_object() {
                                for (field, values) in fields {
                                    ui.label(format!(
                                        "{} · N={} · mean {:.3} · median {:.3} · missing {}",
                                        field,
                                        values["n"],
                                        values["mean"].as_f64().unwrap_or(0.0),
                                        values["median"].as_f64().unwrap_or(0.0),
                                        values["missing"]
                                    ));
                                }
                                if fields.is_empty() {
                                    ui.label("No numeric measurements in this sample.");
                                }
                            }
                        } else {
                            match name.as_str() {
                                "bert" => {
                                    if part["status"] == "ok" {
                                        ui.label(format!("{} texts · {} dimensions · local BertModel", part["documents"], part["dimensions"]));
                                        ui.label(part["model"].as_str().unwrap_or(""));
                                        if let Some(pairs) = part["similar_pairs"].as_array() {
                                            for pair in pairs.iter().take(5) { ui.label(format!("Records {} ↔ {} · semantic cosine {:.3}", pair["a"], pair["b"], pair["cosine"].as_f64().unwrap_or(0.0))); }
                                        }
                                    }
                                }
                                "lstm" => {
                                    if part["status"] == "ok" {
                                        let count = part["scores"].as_array().map_or(0, |rows| rows.iter().filter(|r| r["candidate_anomaly"] == true && r["partition"] == "test").count());
                                        ui.label(format!("LSTM autoencoder · {} epochs · {}-bin windows · {} holdout review signals", part["epochs"], part["window_bins"], count));
                                        ui.label(format!("Calibration threshold {:.4} · holdout MSE {:.4}", part["threshold"].as_f64().unwrap_or(0.0), part["test_mse"].as_f64().unwrap_or(0.0)));
                                    }
                                }
                                "umap" => {
                                    if let Some(spaces) = part["spaces"].as_object() {
                                        for (label, space) in spaces {
                                            ui.label(format!("{} · {}", label, space["status"].as_str().unwrap_or("unknown")));
                                            if let Some(points) = space["points"].as_array() { scatter(ui, points); }
                                        }
                                    }
                                }
                                "kriging" => {
                                    if part["status"] == "ok" { ui.label(format!("{} measured locations · {} interpolated grid points · spherical variogram", part["distinct_locations"], part["points"].as_array().map_or(0, Vec::len))); }
                                }
                                "triangulation" => {
                                    if let Some(targets) = part["targets"].as_array() {
                                        for target in targets.iter().take(10) {
                                            ui.label(format!("{} · {}", target["target_id"].as_str().unwrap_or(""), target["status"].as_str().unwrap_or("unknown")));
                                            if let (Some(lat), Some(lon)) = (target["latitude"].as_f64(), target["longitude"].as_f64()) {
                                                ui.label(format!("Estimate {:.6}, {:.6} · conditional 95% ellipse axes {} m", lat, lon, target["ellipse_95_semi_axes_m"]));
                                            }
                                            if let Some(detail) = target["detail"].as_str() { ui.label(detail); }
                                        }
                                    }
                                }
                                "correlations" => {
                                    if let Some(pairs) = part["pairs"].as_array() {
                                        for p in pairs.iter().take(12) {
                                            ui.label(format!(
                                                "{} ↔ {} · Pearson {:.3} · N={}",
                                                p["a"].as_str().unwrap_or(""),
                                                p["b"].as_str().unwrap_or(""),
                                                p["pearson"].as_f64().unwrap_or(0.0),
                                                p["n"]
                                            ));
                                        }
                                    }
                                }
                                "network" => {
                                    ui.label(format!(
                                        "{} nodes · {} edges · {} Louvain communities",
                                        part["nodes"],
                                        part["edges"],
                                        part["louvain"].as_array().map_or(0, Vec::len)
                                    ));
                                    if let Some(hubs) = part["hubs"].as_array() {
                                        for hub in hubs.iter().take(8) {
                                            ui.label(format!(
                                                "{} · PageRank {:.4}",
                                                hub["label"].as_str().unwrap_or(""),
                                                hub["pagerank"].as_f64().unwrap_or(0.0)
                                            ));
                                        }
                                    }
                                }
                                "temporal" => {
                                    ui.label(format!(
                                        "{} dated · {} undated · bins {} seconds",
                                        part["dated"], part["undated"], part["bin_seconds"]
                                    ));
                                    ui.label(format!(
                                        "CUSUM review signals: {} · ARIMA: {} · STL: {}",
                                        part["cusum"]["alarms"].as_array().map_or(0, Vec::len),
                                        part["forecast"]["status"]
                                            .as_str()
                                            .unwrap_or("unavailable"),
                                        part["stl"]["status"].as_str().unwrap_or("unavailable")
                                    ));
                                }
                                "spatial" => {
                                    ui.label(format!(
                                        "{} located points · {} clusters · {} noise points",
                                        part["located"], part["clusters"], part["noise"]
                                    ));
                                }
                                "text" => {
                                    ui.label(format!(
                                        "{} documents · {} similar pairs · cosine threshold {}",
                                        part["documents"], part["pairs_total"], part["threshold"]
                                    ));
                                }
                                "multivariate" => {
                                    ui.label(format!(
                                        "{} complete records · PCA and Isolation Forest",
                                        part["n"]
                                    ));
                                    ui.label(format!(
                                        "t-SNE: {} · labelled classification: {}",
                                        part["tsne"]["status"].as_str().unwrap_or("unavailable"),
                                        part["classification"]["status"]
                                            .as_str()
                                            .unwrap_or("unavailable")
                                    ));
                                }
                                _ => {}
                            }
                            egui::CollapsingHeader::new("Calculation details")
                                .id_salt(("statistics-details", name))
                                .show(ui, |ui| {
                                    let text: String = serde_json::to_string_pretty(part).unwrap_or_default().chars().take(12000).collect();
                                    ui.small("Preview up to 12,000 characters. Full results are in Calculations JSON.");
                                    egui::ScrollArea::vertical()
                                        .id_salt(("statistics-method", name))
                                        .max_height(240.0)
                                        .show(ui, |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(text).monospace(),
                                                )
                                                .wrap(),
                                            );
                                        });
                                });
                        }
                    });
                }
            }
            egui::CollapsingHeader::new("Coverage and reproducibility").show(ui, |ui| {
                ui.label(format!(
                    "Seed {} · {}",
                    analysis["seed"], analysis["versions"]
                ));
                ui.label(analysis["coverage"].to_string());
                if let Some(limits) = analysis["limitations"].as_array() {
                    for limit in limits {
                        ui.label(limit.as_str().unwrap_or(""));
                    }
                }
            });
        }
        run
    }
}

fn scatter(ui: &mut egui::Ui, points: &[Value]) {
    let pairs: Vec<_> = points
        .iter()
        .filter_map(|p| {
            Some((
                p["point"][0].as_f64()? as f32,
                p["point"][1].as_f64()? as f32,
                p["ref"].as_u64()?,
            ))
        })
        .collect();
    if pairs.is_empty() {
        return;
    }
    let min_x = pairs.iter().map(|p| p.0).fold(f32::INFINITY, f32::min);
    let max_x = pairs.iter().map(|p| p.0).fold(f32::NEG_INFINITY, f32::max);
    let min_y = pairs.iter().map(|p| p.1).fold(f32::INFINITY, f32::min);
    let max_y = pairs.iter().map(|p| p.1).fold(f32::NEG_INFINITY, f32::max);
    let (response, painter) = ui.allocate_painter(
        egui::vec2(ui.available_width(), 190.0),
        egui::Sense::hover(),
    );
    let area = response.rect.shrink(12.0);
    painter.rect_filled(response.rect, 4.0, ui.visuals().extreme_bg_color);
    for (x, y, id) in pairs {
        let pos = egui::pos2(
            area.left() + (x - min_x) / (max_x - min_x).max(1e-6) * area.width(),
            area.bottom() - (y - min_y) / (max_y - min_y).max(1e-6) * area.height(),
        );
        painter.circle_filled(pos, 3.5, ui.visuals().hyperlink_color);
        if response
            .hover_pos()
            .is_some_and(|cursor| cursor.distance(pos) < 7.0)
        {
            response
                .clone()
                .on_hover_text(format!("Source record {}", id));
        }
    }
    ui.small("UMAP coordinates have arbitrary scale and orientation; hover points for source record numbers.");
}

#[cfg(test)]
mod tests {
    #[test]
    fn analysis_dossier_uses_the_existing_research_result() {
        let result: crate::DossierResult = serde_json::from_value(serde_json::json!({
            "query":"synthetic survey", "kind":"dataset", "report_json":"C:/Cases/dossier.json",
            "sections":{"statistics":[{"attribution":"interpretation"}]}
        }))
        .unwrap();
        assert_eq!(result.report_json, "C:/Cases/dossier.json");
        assert_eq!(
            result.sections["statistics"][0]["attribution"],
            "interpretation"
        );
    }
    #[test]
    fn input_is_one_argument_even_with_spaces() {
        assert_eq!(
            super::arguments("C:\\Cases\\sample data.csv"),
            vec!["statistics", "--path", "C:\\Cases\\sample data.csv"]
        );
    }
}
