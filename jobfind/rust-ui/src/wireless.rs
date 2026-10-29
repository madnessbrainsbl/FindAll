use eframe::egui;
use serde_json::Value;
use std::path::PathBuf;

pub enum Action {
    Collect(Vec<String>),
    Research,
    Open(String),
}

pub struct Workspace {
    pub files: String,
    pub result: Option<Value>,
    query: String,
    latitude: String,
    longitude: String,
    radius: f64,
    mapping: String,
    seconds: u32,
    providers: [bool; 4],
    wifi: bool,
    ble: bool,
    sdr: bool,
    filter: String,
    selected: Option<usize>,
    pub error: String,
    edit_inputs: bool,
}

impl Default for Workspace {
    fn default() -> Self {
        Self {
            files: String::new(),
            result: None,
            query: "Wireless survey".into(),
            latitude: String::new(),
            longitude: String::new(),
            radius: 1.0,
            mapping: String::new(),
            seconds: 8,
            providers: [false; 4],
            wifi: false,
            ble: false,
            sdr: false,
            filter: String::new(),
            selected: None,
            error: String::new(),
            edit_inputs: false,
        }
    }
}

pub fn append_files(text: &mut String, paths: impl IntoIterator<Item = PathBuf>) {
    let mut existing: Vec<String> = text
        .lines()
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for path in paths {
        let name = path.to_string_lossy().into_owned();
        if !existing.iter().any(|s| s == &name) {
            existing.push(name);
        }
    }
    *text = existing.join("\n");
}

pub fn pick_files() -> Option<Vec<PathBuf>> {
    rfd::FileDialog::new()
        .set_title("Select field telemetry")
        .add_filter(
            "Telemetry",
            &[
                "csv", "tsv", "json", "geojson", "kml", "db", "sqlite", "sqlite3", "xlsx",
            ],
        )
        .pick_files()
}

fn coordinates(row: &Value) -> Option<(f64, f64)> {
    let (lat, lon) = (row["latitude"].as_f64()?, row["longitude"].as_f64()?);
    (lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon))
    .then_some((lat, lon))
}

impl Workspace {
    pub fn args(&self) -> Result<Vec<String>, String> {
        if !(2..=200).contains(&self.query.trim().chars().count()) {
            return Err("Enter a survey name of 2–200 characters.".into());
        }
        let paths: Vec<_> = self
            .files
            .lines()
            .map(|s| s.trim().trim_matches('"'))
            .filter(|s| !s.is_empty())
            .collect();
        if paths.len() > 10 {
            return Err("Select at most ten telemetry files.".into());
        }
        if paths.is_empty()
            && !self.providers.iter().any(|x| *x)
            && !self.wifi
            && !self.ble
            && !self.sdr
        {
            return Err("Select telemetry files or a collection source.".into());
        }
        for path in &paths {
            if !std::path::Path::new(path).is_file() {
                return Err(
                    "A selected telemetry file is unavailable. Choose an existing file.".into(),
                );
            }
        }
        if !self.radius.is_finite()
            || !(0.1..=10.0).contains(&self.radius)
            || !(1..=30).contains(&self.seconds)
        {
            return Err("Use a radius of 0.1–10 km and discovery duration of 1–30 seconds.".into());
        }
        let mut args = vec![
            "wireless".into(),
            "--query".into(),
            self.query.trim().into(),
            "--radius".into(),
            self.radius.to_string(),
            "--seconds".into(),
            self.seconds.to_string(),
        ];
        for path in paths {
            args.extend(["--file".into(), path.into()]);
        }
        let names = ["wigle", "opencellid", "shodan", "censys"];
        args.extend([
            "--providers".into(),
            names
                .iter()
                .zip(self.providers)
                .filter(|(_, enabled)| *enabled)
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(","),
        ]);
        if self.providers[..3].iter().any(|x| *x)
            || !self.latitude.trim().is_empty()
            || !self.longitude.trim().is_empty()
        {
            let lat = self
                .latitude
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|x| x.is_finite() && (-90.0..=90.0).contains(x));
            let lon = self
                .longitude
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|x| x.is_finite() && (-180.0..=180.0).contains(x));
            if lat.is_none() || lon.is_none() {
                return Err("Enter valid latitude (−90 to 90) and longitude (−180 to 180) for area sources.".into());
            }
            args.extend([
                "--latitude".into(),
                self.latitude.trim().into(),
                "--longitude".into(),
                self.longitude.trim().into(),
            ]);
        }
        if !self.mapping.trim().is_empty() {
            let parsed = serde_json::from_str::<Value>(&self.mapping).ok();
            let valid = parsed
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|map| {
                    map.iter().all(|(k, v)| {
                        ["lat", "lon", "ssid", "bssid", "signal", "type", "timestamp"]
                            .contains(&k.as_str())
                            && v.as_str().is_some_and(|s| !s.is_empty())
                    })
                });
            if !valid {
                return Err("Column mapping must be a JSON object with supported field names and string column names.".into());
            }
            args.extend(["--mapping".into(), self.mapping.clone()]);
        }
        for (flag, enabled) in [
            ("--wifi", self.wifi),
            ("--bluetooth", self.ble),
            ("--sdr", self.sdr),
        ] {
            if enabled {
                args.push(flag.into());
            }
        }
        Ok(args)
    }

    pub fn accept(&mut self, output: &str) {
        match serde_json::from_str::<Value>(output) {
            Ok(data) if data["records"].is_array() => {
                self.result = Some(data);
                self.edit_inputs = false;
                self.selected = None;
                self.error.clear();
            }
            Ok(data) => {
                self.error = data["error"]
                    .as_str()
                    .unwrap_or(
                        "Collector returned no observation report. Check the selected inputs.",
                    )
                    .into();
            }
            Err(_) => {
                self.error = "Collector response could not be read. Check the activity log.".into()
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<Action> {
        let mut action = None;
        crate::workspace_hero(
            ui,
            "📡",
            "Wireless survey · WireTapper",
            "Import a field survey or collect selected indexed and local observations.",
            Some(("RADIO INTEL", crate::theme::COLOR_INFO)),
        );
        if self.result.is_some() && !self.edit_inputs {
            ui.horizontal_wrapped(|ui| {
                ui.label(&self.query);
                if ui
                    .add_enabled(!busy, egui::Button::new("Edit collection settings"))
                    .clicked()
                {
                    self.edit_inputs = true;
                }
            });
        } else {
            crate::card(ui, |ui| {
                ui.add_enabled_ui(!busy,|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(egui::RichText::new("Survey name").strong());
                        ui.add(egui::TextEdit::singleline(&mut self.query).desired_width(260.0));
                        if !self.query.is_empty() && ui.small_button("✖").on_hover_text("Clear survey name").clicked() {
                            self.query.clear();
                        }
                        if ui.button("Add telemetry files…").clicked() {
                            if let Some(paths)=pick_files(){append_files(&mut self.files,paths);}
                        }
                        if ui.button("Clear files").clicked(){self.files.clear();}
                    });
                    let drops=ui.ctx().input(|i|i.raw.dropped_files.iter().map(|f|f.path().to_path_buf()).collect::<Vec<_>>());
                    append_files(&mut self.files,drops);
                    ui.add(egui::TextEdit::multiline(&mut self.files).desired_rows(2).desired_width(f32::INFINITY)
                        .hint_text("Drop telemetry files here or choose them above. One path per line."));
                    egui::CollapsingHeader::new("Indexed area sources").show(ui,|ui| {
                        ui.horizontal_wrapped(|ui| {for (name,value) in ["WiGLE","OpenCelliD","Shodan area index","Censys imported IPs"].iter().zip(self.providers.iter_mut()) {ui.checkbox(value,*name);}});
                        ui.horizontal_wrapped(|ui| {
                            ui.label("Latitude");
                            ui.add(egui::TextEdit::singleline(&mut self.latitude).desired_width(80.0));
                            if !self.latitude.is_empty() && ui.small_button("✖").clicked() { self.latitude.clear(); }
                            ui.label("Longitude");
                            ui.add(egui::TextEdit::singleline(&mut self.longitude).desired_width(80.0));
                            if !self.longitude.is_empty() && ui.small_button("✖").clicked() { self.longitude.clear(); }
                            ui.label("Radius km");ui.add(egui::DragValue::new(&mut self.radius).range(0.1..=10.0));
                        });
                        ui.label("Keys use osint-keys.env or environment. Censys uses public IPs in selected telemetry. Indexed locations are estimates.");
                    });
                    egui::CollapsingHeader::new("Local discovery").show(ui,|ui| {
                        ui.horizontal_wrapped(|ui| {ui.checkbox(&mut self.wifi,"Windows Wi-Fi");ui.checkbox(&mut self.ble,"BLE advertisements");ui.checkbox(&mut self.sdr,"SDR USB presence");ui.label("Seconds");ui.add(egui::DragValue::new(&mut self.seconds).range(1..=30));});
                        ui.label("Local discovery measures no device coordinates. Wi-Fi percentage is separate from RSSI. SDR USB presence does not decode RF.");
                    });
                    egui::CollapsingHeader::new("Import column mapping").show(ui,|ui| {
                        ui.label("Optional JSON: {\"lat\":\"GPS_Y\",\"lon\":\"GPS_X\"}");
                        ui.add(egui::TextEdit::singleline(&mut self.mapping).desired_width(f32::INFINITY));
                    });
                });
            });
        }
        let validation = self.args();
        if crate::primary_button(
            ui,
            "Collect selected observations",
            !busy && validation.is_ok(),
        )
        .on_disabled_hover_text(if busy {
            "A collection is running."
        } else {
            "Select valid inputs first."
        })
        .clicked()
        {
            self.error.clear();
            action = validation.clone().ok().map(Action::Collect);
        }
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Collecting selected sources…");
            });
        } else if let Err(message) = validation {
            ui.label(message);
        }
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        let Some(data) = self.result.clone() else {
            return action;
        };
        let Some(rows) = data["records"].as_array() else {
            return action;
        };
        ui.separator();
        crate::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let rows_count = rows.len().to_string();
                crate::bento_chip(
                    ui,
                    "📡",
                    "OBSERVATIONS",
                    &rows_count,
                    crate::theme::COLOR_ACCENT,
                );
                let status_str = data["status"].as_str().unwrap_or("unknown");
                let status_upper = status_str.to_uppercase();
                crate::bento_chip(
                    ui,
                    "⚡",
                    "STATUS",
                    &status_upper,
                    if status_str.eq_ignore_ascii_case("completed") || status_str.eq_ignore_ascii_case("ok") {
                        crate::theme::COLOR_SUCCESS
                    } else {
                        crate::theme::COLOR_INFO
                    },
                );
                if !self.query.trim().is_empty() {
                    crate::bento_chip(
                        ui,
                        "🗺",
                        "SURVEY",
                        &self.query,
                        crate::theme::COLOR_WARN,
                    );
                }
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        !busy && data["dossier"]["report_json"].is_string(),
                        egui::Button::new("🔬 View dossier / AI / graph"),
                    )
                    .clicked()
                {
                    action = Some(Action::Research);
                }
                for (icon, label, key) in [
                    ("🗺", "Offline map", "map"),
                    ("📄", "JSON", "json"),
                    ("📊", "CSV", "csv"),
                    ("🌐", "GeoJSON", "geojson"),
                ] {
                    if let Some(path) = data["reports"][key].as_str() {
                        if ui.button(format!("{icon} {label}")).clicked() {
                            action = Some(Action::Open(path.into()));
                        }
                    }
                }
            });
        });
        egui::CollapsingHeader::new("Source checks").show(ui, |ui| {
            if let Some(checks) = data["statuses"].as_array() {
                for row in checks {
                    ui.label(format!(
                        "{} · {} · {}",
                        row["source"].as_str().unwrap_or("Source"),
                        row["status"].as_str().unwrap_or("unknown"),
                        row["detail"].as_str().unwrap_or("")
                    ));
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Filter observations:");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(260.0));
            if !self.filter.is_empty() && ui.button("✖").on_hover_text("Clear filter").clicked() {
                self.filter.clear();
            }
        });
        let term = self.filter.to_lowercase();
        let filtered: Vec<_> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                ["name", "device_id", "source"].iter().any(|k| {
                    row[*k]
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&term)
                })
            })
            .collect();
        self.plot(ui, &filtered);
        egui::ScrollArea::vertical()
            .id_salt("wireless-records")
            .max_height(240.0)
            .show(ui, |ui| {
                for (index, row) in filtered.iter().take(500) {
                    let signal = row["rssi_dbm"]
                        .as_f64()
                        .map(|n| format!("{n} dBm"))
                        .or_else(|| row["signal_percent"].as_f64().map(|n| format!("{n}%")))
                        .unwrap_or_else(|| "Signal unknown".into());
                    let location = coordinates(row)
                        .map(|(lat, lon)| format!("{lat}, {lon}"))
                        .unwrap_or_else(|| "Coordinates not supplied".into());
                    if ui
                        .selectable_label(
                            self.selected == Some(*index),
                            format!(
                                "{} · {} · {} · {}",
                                row["name"].as_str().unwrap_or("Observation"),
                                signal,
                                location,
                                row["source"].as_str().unwrap_or("")
                            ),
                        )
                        .clicked()
                    {
                        self.selected = Some(*index);
                    }
                }
            });
        if filtered.len() > 500 {
            ui.label("Showing 500 matching rows; exports contain the full retained dataset.");
        }
        if let Some(row) = self.selected.and_then(|i| rows.get(i)) {
            egui::CollapsingHeader::new("Selected observation / provenance")
                .default_open(true)
                .show(ui, |ui| {
                    ui.label(serde_json::to_string_pretty(row).unwrap_or_default());
                });
        }
        action
    }

    fn plot(&mut self, ui: &mut egui::Ui, rows: &[(usize, &Value)]) {
        let points: Vec<_> = rows
            .iter()
            .filter_map(|(i, r)| coordinates(r).map(|(lat, lon)| (*i, lat, lon)))
            .collect();
        ui.label(format!(
            "{} supplied coordinate points · WGS84 · associations remain candidates",
            points.len()
        ));
        if points.is_empty() {
            ui.label(
                "No coordinates supplied. Local signal strength does not establish a location.",
            );
            return;
        }
        let (response, painter) = ui.allocate_painter(
            egui::vec2(ui.available_width(), 250.0),
            egui::Sense::hover(),
        );
        let rect = response.rect.shrink2(egui::vec2(32.0, 24.0));
        painter.rect_filled(response.rect, 4.0, ui.visuals().extreme_bg_color);
        let (mut xmin, mut xmax, mut ymin, mut ymax) = (
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::INFINITY,
            f64::NEG_INFINITY,
        );
        for (_, lat, lon) in &points {
            xmin = xmin.min(*lon);
            xmax = xmax.max(*lon);
            ymin = ymin.min(*lat);
            ymax = ymax.max(*lat);
        }
        let dx = ((xmax - xmin) * 0.05).max(0.0001);
        let dy = ((ymax - ymin) * 0.05).max(0.0001);
        xmin -= dx;
        xmax += dx;
        ymin -= dy;
        ymax += dy;
        for step in 0..=4 {
            let t = step as f32 / 4.0;
            let x = egui::lerp(rect.x_range(), t);
            let y = egui::lerp(rect.y_range(), t);
            let stroke =
                egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color);
            painter.line_segment(
                [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                stroke,
            );
        }
        for (index, lat, lon) in points {
            let pos = egui::pos2(
                rect.left() + rect.width() * ((lon - xmin) / (xmax - xmin)) as f32,
                rect.bottom() - rect.height() * ((lat - ymin) / (ymax - ymin)) as f32,
            );
            let selected = self.selected == Some(index);
            painter.circle_filled(
                pos,
                if selected { 7.0 } else { 5.0 },
                if selected {
                    ui.visuals().warn_fg_color
                } else {
                    ui.visuals().hyperlink_color
                },
            );
            let hit = ui.interact(
                egui::Rect::from_center_size(pos, egui::vec2(18.0, 18.0)),
                ui.id().with(("wireless-point", index)),
                egui::Sense::click(),
            );
            if hit.clicked() {
                self.selected = Some(index);
            }
            hit.on_hover_text(format!("{lat}, {lon}"));
        }
        let font = egui::FontId::proportional(12.0);
        let color = ui.visuals().text_color();
        painter.text(
            rect.left_bottom() + egui::vec2(0.0, 10.0),
            egui::Align2::LEFT_TOP,
            format!("Longitude {xmin:.5} → {xmax:.5}"),
            font.clone(),
            color,
        );
        painter.text(
            rect.left_top() - egui::vec2(0.0, 7.0),
            egui::Align2::LEFT_BOTTOM,
            format!("Latitude {ymin:.5} → {ymax:.5}"),
            font,
            color,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_implicit_discovery() {
        let w = Workspace::default();
        assert!(w.args().is_err());
        assert!(!w.wifi && !w.ble && !w.sdr);
    }
    #[test]
    fn geographic_inputs_are_finite_and_zero_is_valid() {
        let mut w = Workspace::default();
        w.providers[0] = true;
        w.latitude = "NaN".into();
        w.longitude = "0".into();
        assert!(w.args().is_err());
        w.latitude = "0".into();
        let a = w.args().unwrap();
        assert!(a.windows(2).any(|x| x == ["--latitude", "0"]));
        assert!(!a.contains(&"--wifi".into()));
    }
    #[test]
    fn mappings_cannot_choose_paths_or_commands() {
        let mut w = Workspace::default();
        w.ble = true;
        w.mapping = r#"{"command":"execute"}"#.into();
        assert!(w.args().is_err());
        w.mapping = r#"{"lat":"GPS_Y","lon":"GPS_X"}"#.into();
        assert!(w.args().unwrap().contains(&"--mapping".into()));
    }
    #[test]
    fn drops_deduplicate_quoted_paths() {
        let mut text = "\"C:\\a.csv\"".into();
        append_files(
            &mut text,
            [PathBuf::from("C:\\a.csv"), PathBuf::from("C:\\b.csv")],
        );
        assert_eq!(text.lines().count(), 2);
    }
    #[test]
    fn map_does_not_invent_missing_coordinates() {
        assert!(coordinates(&serde_json::json!({"latitude":null,"longitude":12})).is_none());
        assert_eq!(
            coordinates(&serde_json::json!({"latitude":0,"longitude":0})),
            Some((0.0, 0.0))
        );
    }
    #[test]
    fn errors_preserve_prior_successful_report() {
        let mut w = Workspace::default();
        w.accept(r#"{"records":[],"status":"empty"}"#);
        w.accept(r#"{"error":"Invalid selection"}"#);
        assert!(w.result.is_some());
        assert_eq!(w.error, "Invalid selection");
    }
}
