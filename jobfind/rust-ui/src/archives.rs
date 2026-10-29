use eframe::egui;
use serde_json::Value;

pub enum Action {
    Collect(Vec<String>),
    Research,
    Open(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_import_does_not_enable_sources_or_responses() {
        let mut workspace = Workspace::default();
        workspace.offline_import("synthetic.json".into());
        let args = workspace.args().unwrap();
        assert_eq!(
            args[args.iter().position(|s| s == "--providers").unwrap() + 1],
            ""
        );
        assert_eq!(
            args[args.iter().position(|s| s == "--captures").unwrap() + 1],
            "0"
        );
        assert!(args.windows(2).any(|p| p == ["--import", "synthetic.json"]));
    }
    #[test]
    fn invalid_dates_are_reviewable_before_collection() {
        let mut workspace = Workspace::default();
        workspace.domain = "example.org".into();
        workspace.start = "2023-01".into();
        assert!(workspace.args().is_err());
    }
    #[test]
    fn failed_collection_retains_successful_archive_result() {
        let mut workspace = Workspace::default();
        workspace.accept(r#"{"records":[],"status":"empty"}"#);
        workspace.accept(r#"{"error":"bad date"}"#);
        assert_eq!(workspace.error, "bad date");
        assert!(workspace.result.is_some());
    }
}
pub struct Workspace {
    pub domain: String,
    pub imports: String,
    pub result: Option<Value>,
    pub error: String,
    providers: [bool; 7],
    subs: bool,
    start: String,
    end: String,
    limit: u32,
    captures: u32,
    category: String,
    status_codes: String,
    mime: String,
    collapse: bool,
    filter: String,
    selected: Option<usize>,
}
impl Default for Workspace {
    fn default() -> Self {
        Self {
            domain: String::new(),
            imports: String::new(),
            result: None,
            error: String::new(),
            providers: [true, true, true, true, false, false, false],
            subs: true,
            start: String::new(),
            end: String::new(),
            limit: 500,
            captures: 0,
            category: String::new(),
            status_codes: String::new(),
            mime: String::new(),
            collapse: false,
            filter: String::new(),
            selected: None,
        }
    }
}
impl Workspace {
    pub fn offline_import(&mut self, path: String) {
        self.domain = "example.org".into();
        self.imports = path;
        self.providers = [false; 7];
    }
    pub fn args(&self) -> Result<Vec<String>, String> {
        if self.domain.trim().is_empty() {
            return Err("Enter a domain to search its archived URLs.".into());
        }
        for date in [&self.start, &self.end] {
            if !date.is_empty()
                && (![4, 6, 8].contains(&date.len()) || !date.chars().all(|c| c.is_ascii_digit()))
            {
                return Err("Use YYYY, YYYYMM or YYYYMMDD dates.".into());
            }
        }
        let names = [
            "wayback",
            "commoncrawl",
            "otx",
            "urlscan",
            "virustotal",
            "intelx",
            "ghostarchive",
        ];
        let providers = names
            .iter()
            .zip(self.providers)
            .filter(|(_, b)| *b)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>()
            .join(",");
        let mut args = vec![
            "archive-search".into(),
            "--domain".into(),
            self.domain.trim().into(),
            "--providers".into(),
            providers,
            "--limit".into(),
            self.limit.to_string(),
            "--captures".into(),
            self.captures.to_string(),
        ];
        for (key, value) in [
            ("--from", &self.start),
            ("--to", &self.end),
            ("--category", &self.category),
            ("--status-codes", &self.status_codes),
            ("--mime", &self.mime),
        ] {
            if !value.trim().is_empty() {
                args.extend([key.into(), value.trim().into()]);
            }
        }
        for file in self
            .imports
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            args.extend(["--import".into(), file.trim_matches('"').into()]);
        }
        if !self.subs {
            args.push("--no-subdomains".into());
        }
        if self.collapse {
            args.push("--collapse-parameters".into());
        }
        if !self.providers.iter().any(|x| *x) && self.imports.trim().is_empty() {
            return Err("Select an archive source or an exported URL file.".into());
        }
        Ok(args)
    }
    pub fn accept(&mut self, output: &str) {
        match serde_json::from_str::<Value>(output) {
            Ok(value) if value["records"].is_array() => {
                self.result = Some(value);
                self.error.clear();
                self.selected = None;
            }
            Ok(value) => {
                self.error = value["error"]
                    .as_str()
                    .unwrap_or("Could not read archive results.")
                    .into()
            }
            Err(_) => {
                self.error =
                    "Archive collection could not finish. Review sources and dependencies.".into()
            }
        }
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<Action> {
        let mut action = None;
        crate::card(ui, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                    ui.label(egui::RichText::new("Domain").strong());
                    let width = ui.available_width();
                    let clear_w = if self.domain.is_empty() { 0.0 } else { 32.0 };
                    if width >= 620.0 {
                        ui.horizontal(|ui| {
                            ui.add_sized([width - 220.0 - clear_w, 32.0],
                                egui::TextEdit::singleline(&mut self.domain).hint_text("example.org").margin(egui::vec2(10.0,7.0)));
                            if !self.domain.is_empty() && ui.button("✖").on_hover_text("Clear domain").clicked() {
                                self.domain.clear();
                            }
                            ui.checkbox(&mut self.subs,"Include subdomains");
                        });
                    } else {
                        ui.horizontal(|ui| {
                            ui.add_sized([width - clear_w, 32.0], egui::TextEdit::singleline(&mut self.domain).hint_text("example.org").margin(egui::vec2(10.0,7.0)));
                            if !self.domain.is_empty() && ui.button("✖").on_hover_text("Clear domain").clicked() {
                                self.domain.clear();
                            }
                        });
                        ui.checkbox(&mut self.subs,"Include subdomains");
                    }
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Sources").strong());
                    let names=["Wayback Machine","Common Crawl","AlienVault OTX","URLScan","VirusTotal","Intelligence X","GhostArchive"];
                    let columns=if ui.available_width()>=820.0 {4}else if ui.available_width()>=570.0 {3}else {2};
                    let gap=16.0;
                    let column_width=(ui.available_width()-gap*(columns-1) as f32)/columns as f32;
                    egui::Grid::new("archive-sources")
                        .num_columns(columns).spacing(egui::vec2(gap,2.0))
                        .min_col_width(column_width).max_col_width(column_width)
                        .show(ui,|ui| {
                            for (i,name) in names.iter().enumerate() {
                                ui.allocate_ui_with_layout(egui::vec2(column_width,28.0),egui::Layout::left_to_right(egui::Align::Center),|ui| {
                                    ui.checkbox(&mut self.providers[i],*name);
                                });
                                if i%columns==columns-1 || i==names.len()-1 {ui.end_row();}
                            }
                        });
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(2.0);
                    let columns=if ui.available_width()>=660.0 {4}else {2};
                    let width=(ui.available_width()-16.0*(columns-1) as f32)/columns as f32;
                    egui::Grid::new("archive-range")
                        .num_columns(columns).spacing(egui::vec2(16.0,10.0))
                        .min_col_width(width).max_col_width(width)
                        .show(ui,|ui| {
                            for index in 0..4 {
                                ui.vertical(|ui| {
                                    ui.set_width(width);
                                    ui.label(egui::RichText::new(["From date","To date","URL limit","Save responses"][index]).small().color(ui.visuals().weak_text_color()));
                                    match index {
                                        0=>{
                                            let cw = if self.start.is_empty() { 0.0 } else { 26.0 };
                                            ui.horizontal(|ui| {
                                                ui.add_sized([width - cw, 32.0], egui::TextEdit::singleline(&mut self.start).hint_text("YYYYMMDD").margin(egui::vec2(10.0,7.0)));
                                                if !self.start.is_empty() && ui.small_button("✖").on_hover_text("Clear start date").clicked() {
                                                    self.start.clear();
                                                }
                                            });
                                        },
                                        1=>{
                                            let cw = if self.end.is_empty() { 0.0 } else { 26.0 };
                                            ui.horizontal(|ui| {
                                                ui.add_sized([width - cw, 32.0], egui::TextEdit::singleline(&mut self.end).hint_text("YYYYMMDD").margin(egui::vec2(10.0,7.0)));
                                                if !self.end.is_empty() && ui.small_button("✖").on_hover_text("Clear end date").clicked() {
                                                    self.end.clear();
                                                }
                                            });
                                        },
                                        2=>{ui.add_sized([width,32.0],egui::DragValue::new(&mut self.limit).range(1..=5000).speed(25));},
                                        _=>{ui.add_sized([width,32.0],egui::DragValue::new(&mut self.captures).range(0..=20));},
                                    }
                                });
                                if index%columns==columns-1 {ui.end_row();}
                            }
                        });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        egui::ComboBox::from_id_salt("archive-category")
                            .width(210.0)
                            .selected_text(if self.category.is_empty(){"All path categories"}else{&self.category})
                            .show_ui(ui,|ui| {
                                ui.selectable_value(&mut self.category,String::new(),"All path categories");
                                for name in ["api","admin","debug","backup","config","javascript","parameters","other"] {
                                    ui.selectable_value(&mut self.category,name.into(),name);
                                }
                            });
                        ui.checkbox(&mut self.collapse,"Collapse parameter values");
                    });
                    egui::CollapsingHeader::new("Advanced filters and imports").show(ui,|ui| {
                        let width=(ui.available_width()-16.0)/2.0;
                        ui.columns(2,|columns| {
                            columns[0].label("Historical HTTP status");
                            columns[0].add_sized([width,32.0],egui::TextEdit::singleline(&mut self.status_codes).hint_text("200,301").margin(egui::vec2(10.0,7.0)));
                            columns[1].label("MIME prefix");
                            columns[1].add_sized([width,32.0],egui::TextEdit::singleline(&mut self.mime).hint_text("application/javascript").margin(egui::vec2(10.0,7.0)));
                        });
                        ui.add_space(4.0);
                        if ui.button("Choose URL export…").clicked() {
                            if let Some(paths)=rfd::FileDialog::new().add_filter("URL exports",&["txt","json","jsonl"]).pick_files() {
                                crate::wireless::append_files(&mut self.imports,paths);
                            }
                        }
                        ui.add(egui::TextEdit::multiline(&mut self.imports).desired_rows(2).desired_width(f32::INFINITY)
                            .hint_text("waymore, gau, waybackurls or CDX exports").margin(egui::vec2(10.0,7.0)));
                        ui.label(egui::RichText::new("Dates and metadata may be missing from archive indices. Common Crawl searches up to two collections. Optional source keys use osint-keys.env.").small().color(ui.visuals().weak_text_color()));
                    });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        if crate::primary_button(ui, "Search archives", true).clicked() {
                            match self.args() {
                                Ok(args)=>{self.error.clear();action=Some(Action::Collect(args));},
                                Err(error)=>self.error=error,
                            }
                        }
                        ui.label(egui::RichText::new(format!("{} sources selected",self.providers.iter().filter(|enabled|**enabled).count())).small().color(ui.visuals().weak_text_color()));
                    });
                });
            });
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        let Some(result) = self.result.as_ref() else {
            return action;
        };
        let records = result["records"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        ui.add_space(14.0);
        crate::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                crate::bento_chip(ui, "🏛", "ARCHIVED URLS", &format!("{}", records.len()), crate::theme::COLOR_INFO);
                let status = result["status"].as_str().unwrap_or("unknown");
                let status_color = if status == "ok" || status == "complete" {
                    crate::theme::COLOR_SUCCESS
                } else {
                    crate::theme::COLOR_WARN
                };
                crate::bento_chip(ui, "⚡", "STATUS", status, status_color);
                crate::bento_chip(ui, "🌐", "DOMAIN", &self.domain, crate::theme::COLOR_ACCENT);
            });
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("🔍 View dossier / AI / graph").clicked() {
                    action = Some(Action::Research);
                }
                for (key, label) in [("json", "JSON"), ("csv", "CSV"), ("urls", "URL list")] {
                    if let Some(path) = result["reports"][key].as_str() {
                        if ui.button(label).clicked() {
                            action = Some(Action::Open(path.into()));
                        }
                    }
                }
            });
        });
        egui::CollapsingHeader::new("Source checks")
            .default_open(records.is_empty())
            .show(ui, |ui| {
                if let Some(checks) = result["statuses"].as_array() {
                    for item in checks {
                        ui.label(format!(
                            "{} · {} · {}",
                            item["source"].as_str().unwrap_or(""),
                            item["status"].as_str().unwrap_or(""),
                            item["detail"].as_str().unwrap_or("")
                        ));
                    }
                }
            });
        ui.horizontal(|ui| {
            let clear_w = if self.filter.is_empty() { 0.0 } else { 32.0 };
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter URL, parameters or category")
                    .desired_width(ui.available_width() - clear_w),
            );
            if !self.filter.is_empty() && ui.button("✖").on_hover_text("Clear filter").clicked() {
                self.filter.clear();
            }
        });
        let filter = self.filter.to_lowercase();
        egui::ScrollArea::vertical()
            .id_salt("archive-records")
            .max_height(270.)
            .show(ui, |ui| {
                for (i, row) in records.iter().enumerate() {
                    if !filter.is_empty() && !row.to_string().to_lowercase().contains(&filter) {
                        continue;
                    }
                    let label = format!(
                        "{} · {} · {}",
                        row["snapshot_at"]
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("Date unknown"),
                        row["source"].as_str().unwrap_or(""),
                        row["original_url"].as_str().unwrap_or("")
                    );
                    if ui
                        .add(
                            egui::Button::new(label)
                                .selected(self.selected == Some(i))
                                .wrap(),
                        )
                        .clicked()
                    {
                        self.selected = Some(i);
                    }
                }
            });
        if let Some(row) = self.selected.and_then(|i| records.get(i)) {
            ui.separator();
            let orig_url = row["original_url"].as_str().unwrap_or("");
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(orig_url).strong());
                if !orig_url.is_empty() && ui.button("📋 Copy URL").clicked() {
                    ui.ctx().copy_text(orig_url.to_string());
                    ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Copied URL to clipboard".to_string()));
                }
            });
            ui.label(format!(
                "Categories: {} · Parameters: {}",
                row["categories"], row["parameters"]
            ));
            ui.label(format!(
                "Historical HTTP: {} · MIME: {}",
                row["http_status"].as_str().unwrap_or(""),
                row["mime_type"].as_str().unwrap_or("")
            ));
            if row["source"].as_str() == Some("wayback")
                && row["discovered_in"].is_null()
                && !row["snapshot_at"].as_str().unwrap_or("").is_empty()
            {
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Open archived snapshot").clicked() {
                        if let Some(url) = row["source_url"].as_str() {
                            action = Some(Action::Open(url.into()));
                        }
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("Save selected response"))
                        .clicked()
                    {
                        if let (Some(path), Some(url), Some(domain)) = (
                            result["reports"]["json"].as_str(),
                            row["source_url"].as_str(),
                            result["domain"].as_str(),
                        ) {
                            action = Some(Action::Collect(vec![
                                "archive-search".into(),
                                "--domain".into(),
                                domain.into(),
                                "--providers".into(),
                                String::new(),
                                "--import".into(),
                                path.into(),
                                "--captures".into(),
                                "1".into(),
                                "--capture-url".into(),
                                url.into(),
                                "--limit".into(),
                                "5000".into(),
                            ]));
                        }
                    }
                    if let Some(path) = row["capture_path"].as_str() {
                        if ui.button("Open saved response").clicked() {
                            action = Some(Action::Open(path.into()));
                        }
                    }
                });
            }
            if let Some(text) = row["text"].as_str() {
                egui::CollapsingHeader::new("Archived text and indicators").show(ui, |ui| {
                    ui.label(format!("Indicator names: {}", row["indicators"]));
                    ui.label(text);
                });
            }
        }
        action
    }
}
