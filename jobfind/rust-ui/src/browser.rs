use eframe::egui;
use serde_json::Value;

pub struct Workspace {
    pub url: String,
    pub question: String,
    pub selector: String,
    pub pages: u8,
    pub items: u8,
    pub ai: bool,
    pub result: Option<Value>,
    pub error: String,
    pub open_dossier: bool,
    pub open_library: bool,
    pub configure_ai: bool,
}

impl Default for Workspace {
    fn default() -> Self {
        Self { url: String::new(), question: String::new(), selector: String::new(), pages: 3, items: 50, ai: false,
            result: None, error: String::new(), open_dossier: false, open_library: false, configure_ai: false }
    }
}

pub fn arguments(url: &str, question: &str, pages: u8, items: u8, ai: bool) -> Vec<String> {
    let mut args = vec!["browser-research".into(), "--url".into(), url.into(), "--question".into(), question.into(),
        "--pages".into(), pages.to_string(), "--items".into(), items.to_string()];
    if ai { args.push("--ai".into()); }
    args
}

impl Workspace {
    pub fn show(&mut self, ui: &mut egui::Ui, busy: bool, ai_ready: bool) -> Option<Vec<String>> {
        crate::workspace_hero(ui, "🌐", "Browser research",
            "Collect rendered pages, structured records and source snapshots into a dossier.", None);
        let mut command = None;
        crate::card(ui, |ui| {
            ui.label(egui::RichText::new("Public page URL").strong());
            ui.add(egui::TextEdit::singleline(&mut self.url).desired_width(f32::INFINITY).hint_text("https://example.org/directory"));
            ui.add_space(8.0);
            ui.label("Research question · optional");
            ui.add(egui::TextEdit::multiline(&mut self.question).desired_rows(2).desired_width(f32::INFINITY)
                .hint_text("What should the analysis focus on?"));
            ui.add_space(8.0);
            ui.label("CSS selector · optional");
            ui.add(egui::TextEdit::singleline(&mut self.selector).desired_width(f32::INFINITY).hint_text("For example .vacancy-card"));
            ui.label(egui::RichText::new("Scrapling can recover a previously matched element after the page layout changes. Review recovered matches.").small().weak());
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("Pages"); ui.add(egui::DragValue::new(&mut self.pages).range(1..=8));
                ui.label("Structured items"); ui.add(egui::DragValue::new(&mut self.items).range(1..=100));
            });
            ui.add_enabled_ui(ai_ready, |ui| { ui.checkbox(&mut self.ai, "Analyze with AI and source citations"); });
            if !ai_ready && ui.small_button("Configure AI in Dossier settings").clicked() { self.configure_ai = true; }
            ui.add_space(8.0);
            if crate::primary_button(ui, "Collect pages", !busy && !self.url.trim().is_empty())
                .on_disabled_hover_text("Enter a public page URL and wait for the current task to finish.").clicked() {
                let mut args = arguments(self.url.trim(), self.question.trim(), self.pages, self.items, self.ai && ai_ready);
                if !self.selector.trim().is_empty() { args.extend(["--selector".into(), self.selector.trim().into()]); }
                command = Some(args);
            }
            if busy { ui.horizontal(|ui| { ui.spinner(); ui.label("Collecting pages…"); }); }
            ui.add_space(8.0);
            ui.label(egui::RichText::new("Follows linked next pages on the same site and scrolls for dynamic content. Uses a fresh browser session. AI sends retained text to the configured provider.").small().weak());
        });
        if !self.error.is_empty() { ui.colored_label(ui.visuals().error_fg_color, &self.error); }
        if let Some(result) = &self.result {
            ui.add_space(12.0);
            crate::card(ui, |ui| {
                ui.heading("Saved research");
                ui.label(format!("Collection: {}", result["browser_research"]["status"].as_str().unwrap_or("unknown")));
                ui.label(format!("{} pages · {} records · {} source checks",
                    result["sections"]["web"].as_array().map_or(0, Vec::len),
                    result["sections"]["findings"].as_array().map_or(0, Vec::len),
                    result["source_checks"].as_array().map_or(0, Vec::len)));
                ui.horizontal_wrapped(|ui| {
                    if ui.button("View dossier and AI analysis").clicked() { self.open_dossier = true; }
                    if ui.button("Search in evidence library").clicked() { self.open_library = true; }
                    if let Some(path) = result["graph_path"].as_str() {
                        if ui.button("Open graph").clicked() { crate::open_url(path); }
                    }
                    if let Some(path) = result["report_csv"].as_str() {
                        if ui.button("Open CSV").clicked() { crate::open_url(path); }
                    }
                });
                for check in result["source_checks"].as_array().into_iter().flatten() {
                    ui.label(format!("{} · {}", check["state"].as_str().unwrap_or("unknown"), check["detail"].as_str().unwrap_or("")));
                }
            });
            for (index, row) in result["sections"]["web"].as_array().into_iter().flatten().enumerate() {
                egui::CollapsingHeader::new(row["title"].as_str().unwrap_or("Captured page")).id_salt(("browser-page", index)).show(ui, |ui| {
                    if let Some(url) = row["url"].as_str() { ui.hyperlink_to("Published source", url); }
                    if let Some(path) = row["artifact"].as_str() {
                        if ui.button("Open saved page").clicked() { crate::open_url(path); }
                    }
                    ui.label(row["snippet"].as_str().unwrap_or(""));
                });
            }
        }
        command
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn url_and_question_remain_single_arguments() {
        let args = super::arguments("https://example.org/?a=1&b=2", "Сравни \"Alpha\"; $(test)", 3, 50, true);
        assert_eq!(args[2], "https://example.org/?a=1&b=2");
        assert_eq!(args[4], "Сравни \"Alpha\"; $(test)");
        assert_eq!(args.last().unwrap(), "--ai");
    }
}
