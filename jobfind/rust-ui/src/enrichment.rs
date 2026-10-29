use eframe::egui;

// Flowsint's typed enricher/flow pattern, adapted to FindAll's bounded Python backend.
// Caption, input type, CLI selector, identifier.
pub const OPTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "Domain → DNS → ASN → prefixes",
        "Domain",
        "--flow",
        "domain-network",
    ),
    ("IP → ASN → prefixes", "IP", "--flow", "ip-network"),
    ("ASN → announced prefixes", "ASN", "--flow", "asn-network"),
    (
        "Website → links, trackers, root domain",
        "Website",
        "--flow",
        "website-evidence",
    ),
    (
        "Email → registrable domain",
        "Email",
        "--flow",
        "email-domain",
    ),
    (
        "CIDR → address sample (offline)",
        "CIDR",
        "--flow",
        "cidr-sample",
    ),
    (
        "Registrable domain (PSL)",
        "Domain",
        "--enricher",
        "domain_root",
    ),
    ("DNS A / AAAA", "Domain", "--enricher", "domain_dns"),
    (
        "HTTPS URL (syntax)",
        "Domain",
        "--enricher",
        "domain_website",
    ),
    (
        "URL hostname (syntax)",
        "Website",
        "--enricher",
        "website_domain",
    ),
    (
        "Published page links",
        "Website",
        "--enricher",
        "website_links",
    ),
    (
        "Published tracking identifiers",
        "Website",
        "--enricher",
        "website_trackers",
    ),
    (
        "Email domain (syntax)",
        "Email",
        "--enricher",
        "email_domain",
    ),
    ("Routing ASN", "IP", "--enricher", "ip_asn"),
    ("Announced prefixes", "ASN", "--enricher", "asn_prefixes"),
    (
        "Address sample (offline)",
        "CIDR",
        "--enricher",
        "cidr_addresses",
    ),
];

pub fn node_kind(kind: &str) -> &str {
    match kind {
        "Page" | "Profile" => "Website",
        other => other,
    }
}

pub fn arguments(index: usize, value: &str, limit: u32) -> Vec<String> {
    let option = OPTIONS[index];
    vec![
        "enrich".into(),
        option.2.into(),
        option.3.into(),
        "--value".into(),
        value.into(),
        "--limit".into(),
        limit.clamp(1, 100).to_string(),
        "--progress-json".into(),
    ]
}

pub enum Action {
    Run(Vec<String>),
    Diagram(String, String),
}

pub struct Workspace {
    pub result: Option<serde_json::Value>,
    pub error: String,
    value: String,
    selected: usize,
    flow_file: String,
    limit: u32,
}

impl Default for Workspace {
    fn default() -> Self {
        Self {
            result: None,
            error: String::new(),
            value: String::new(),
            selected: 0,
            flow_file: String::new(),
            limit: 20,
        }
    }
}

impl Workspace {
    pub fn show(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<Action> {
        let mut action = None;
        ui.label(
            egui::RichText::new("ENRICHMENT FLOWS")
                .strong()
                .color(ui.visuals().hyperlink_color),
        );
        ui.label("Expand an entity through typed, bounded steps. Results join the same workspace diagram.");
        egui::ComboBox::from_id_salt("enrichment-flow")
            .selected_text(OPTIONS[self.selected].0)
            .width(ui.available_width().min(360.0))
            .show_ui(ui, |ui| {
                for (index, option) in OPTIONS.iter().enumerate() {
                    ui.selectable_value(&mut self.selected, index, option.0);
                }
            });
        ui.label(format!("Input type: {}", OPTIONS[self.selected].1));
        ui.add(
            egui::TextEdit::singleline(&mut self.value)
                .desired_width(f32::INFINITY)
                .hint_text("python.org · 1.1.1.1 · AS13335 · https://www.python.org/"),
        );
        egui::CollapsingHeader::new("Flow options").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Results per step");
                ui.add(egui::DragValue::new(&mut self.limit).range(1..=100));
            });
            ui.label("Custom FindAll flow JSON (optional; overrides the selected preset)");
            ui.add(egui::TextEdit::singleline(&mut self.flow_file).desired_width(f32::INFINITY));
            ui.label(egui::RichText::new("Up to 12 collector calls. Links are not followed automatically; CIDR sampling makes no network requests.").small().weak());
        });
        let enabled = !busy && !self.value.trim().is_empty();
        let selection = ui.visuals().selection;
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(
                    egui::RichText::new("Run enrichment").color(selection.stroke.color),
                )
                .fill(selection.bg_fill),
            )
            .clicked()
        {
            let args = if self.flow_file.trim().is_empty() {
                arguments(self.selected, self.value.trim(), self.limit)
            } else {
                vec![
                    "enrich".into(),
                    "--flow-file".into(),
                    self.flow_file.trim().into(),
                    "--value".into(),
                    self.value.trim().into(),
                    "--limit".into(),
                    self.limit.to_string(),
                    "--progress-json".into(),
                ]
            };
            self.error.clear();
            action = Some(Action::Run(args));
        }
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        if let Some(result) = &self.result {
            ui.separator();
            ui.label(format!(
                "{} · {} relationships · {} collector calls",
                result["flow"]["status"].as_str().unwrap_or("unknown"),
                result["counts"]["enrichments"],
                result["counts"]["flow_tasks"]
            ));
            if ui
                .add_enabled(!busy, egui::Button::new("Show in diagram"))
                .clicked()
            {
                if let Some(path) = result["graph_path"].as_str() {
                    action = Some(Action::Diagram(
                        path.into(),
                        result["query"].as_str().unwrap_or("").into(),
                    ));
                }
            }
            egui::CollapsingHeader::new("Step results and source status").show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("flow-results")
                    .max_height(300.0)
                    .show(ui, |ui| {
                        if let Some(rows) = result["flow"]["trace"].as_array() {
                            for row in rows {
                                ui.label(format!(
                                    "{} · {} · {} result(s)",
                                    row["step"].as_str().unwrap_or(""),
                                    row["state"].as_str().unwrap_or("unknown"),
                                    row["count"]
                                ));
                                if let Some(detail) =
                                    row["detail"].as_str().filter(|s| !s.is_empty())
                                {
                                    ui.label(detail);
                                }
                            }
                        }
                        if let Some(rows) = result["sections"]["findings"].as_array() {
                            for row in rows {
                                ui.separator();
                                ui.label(row["snippet"].as_str().unwrap_or(""));
                                ui.label(
                                    egui::RichText::new(row["attribution"].as_str().unwrap_or(""))
                                        .small()
                                        .weak(),
                                );
                                if let Some(url) =
                                    row["url"].as_str().filter(|s| s.starts_with("https://"))
                                {
                                    ui.hyperlink_to("Open source ↗", url);
                                }
                            }
                        }
                    });
            });
        }
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_actions_keep_the_exact_entity_and_typed_selection() {
        let args = arguments(2, "AS13335", 500);
        assert_eq!(
            &args[1..5],
            &["--flow", "asn-network", "--value", "AS13335"]
        );
        assert_eq!(args[6], "100");
        assert_eq!(node_kind("Page"), "Website");
        assert!(OPTIONS.iter().any(|option| option.1 == node_kind("IP")));
        assert!(
            !OPTIONS
                .iter()
                .any(|option| option.1 == node_kind("AIClaim"))
        );
    }
}
