use eframe::egui;
use serde_json::{json, Value};

#[derive(Default)]
pub struct Workspace {
    pub question: String,
    pub roots: String,
    pub files: String,
    pub password: String,
    pub source_url: String,
    pub result: Option<Value>,
    pub error: String,
    pub configure_ai: bool,
    pub open_dossier: Option<String>,
}

pub fn arguments(action: &str, question: &str, roots: &str) -> Vec<String> {
    let mut args = vec!["library".into(), "--action".into(), action.into()];
    if action == "search" || action == "ask" { args.extend(["--question".into(), question.into()]); }
    for root in roots.lines().map(str::trim).filter(|s| !s.is_empty()) {
        args.extend(["--dossier-root".into(), root.trim_matches('"').into()]);
    }
    args
}

fn source_buttons(ui: &mut egui::Ui, row: &Value, open: &mut Option<String>) {
    ui.horizontal_wrapped(|ui| {
        if let Some(url) = row["source_url"].as_str().filter(|s| s.starts_with("https://") || s.starts_with("http://")) {
            ui.hyperlink_to("Published source", url);
        }
        if let Some(path) = row["preview_path"].as_str().filter(|s| !s.is_empty()) {
            if ui.button("Open PDF page").clicked() { crate::open_url(path); }
        }
        if let Some(path) = row["dossier_path"].as_str().filter(|s| !s.is_empty()) {
            if ui.button("View dossier").clicked() { *open = Some(path.into()); }
        }
        if let Some(path) = row["snapshot_path"].as_str().filter(|s| !s.is_empty()) {
            if ui.button("Saved original").clicked() { crate::open_url(path); }
        }
    });
}

impl Workspace {
    pub fn show(&mut self, ui: &mut egui::Ui, busy: bool, ai_ready: bool) -> Option<(Vec<String>, Option<String>)> {
        crate::workspace_hero(
            ui,
            "📚",
            "Evidence library",
            "Search saved dossiers and PDF pages. Answers cite the retained source text.",
            Some(("CORPUS INDEX", crate::theme::COLOR_INFO)),
        );
        let mut command = None;
        crate::card(ui, |ui| {
            ui.label(egui::RichText::new("Question or search terms").strong());
            let input = ui.horizontal(|ui| {
                let clear_needed = !self.question.is_empty();
                let width = if clear_needed {
                    (ui.available_width() - 44.0).max(100.0)
                } else {
                    ui.available_width()
                };
                let f = ui.add_sized(
                    [width, 42.0],
                    egui::TextEdit::multiline(&mut self.question)
                        .desired_rows(2)
                        .hint_text("What do these materials say? Где источники противоречат друг другу?"),
                );
                if clear_needed {
                    if ui
                        .add_sized(
                            [36.0, 42.0],
                            egui::Button::new(
                                egui::RichText::new("✖")
                                    .size(13.0)
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .fill(egui::Color32::from_rgb(20, 26, 38))
                            .stroke(egui::Stroke::new(1.0, crate::theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(6)),
                        )
                        .on_hover_text("Clear question")
                        .clicked()
                    {
                        self.question.clear();
                    }
                }
                f
            }).inner;
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                let enabled = !busy && !self.question.trim().is_empty();
                if ui.add_enabled(enabled, egui::Button::new("Search library")).clicked()
                    || (enabled && input.lost_focus() && ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::Enter))) {
                    command = Some((arguments("search", self.question.trim(), &self.roots), None));
                }
                if crate::primary_button(ui, "Ask AI with citations", enabled && ai_ready)
                    .on_disabled_hover_text("Enter a question and configure an AI provider/model in Dossier settings.").clicked() {
                    command = Some((arguments("ask", self.question.trim(), &self.roots), None));
                }
                if ui.add_enabled(!busy, egui::Button::new("Update index")).clicked() {
                    command = Some((arguments("index", "", &self.roots), None));
                }
                if busy { ui.spinner(); ui.label("Processing library…"); }
            });
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Indexing and search stay local. Ask AI sends only the retrieved text to your configured provider.").small().color(ui.visuals().weak_text_color()));
            if !ai_ready && ui.small_button("Configure AI in Dossier settings").clicked() { self.configure_ai = true; }
            ui.add_space(8.0);
            egui::CollapsingHeader::new("Dossier folders").show(ui, |ui| {
                ui.label("Leave blank to include the normal results folder and project results. Optional folders, one per line:");
                ui.add(egui::TextEdit::multiline(&mut self.roots).desired_rows(2).desired_width(f32::INFINITY));
                if ui.button("Add folder…").clicked() {
                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                        if !self.roots.is_empty() { self.roots.push('\n'); }
                        self.roots.push_str(&path.to_string_lossy());
                    }
                }
            });
            egui::CollapsingHeader::new("Library setup").show(ui, |ui| {
                if ui.add_enabled(!busy, egui::Button::new("Set up local search and OCR")).clicked() {
                    command = Some((arguments("setup", "", &self.roots), None));
                }
            });
        });
        ui.add_space(12.0);
        egui::CollapsingHeader::new("Import PDF documents")
            .id_salt(("library-pdf-import", self.result.is_some()))
            .default_open(self.result.as_ref().is_none_or(|r| r["action"] == "pdf")).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!busy, egui::Button::new("Choose PDFs…")).clicked() {
                    if let Some(paths) = rfd::FileDialog::new().add_filter("PDF documents", &["pdf"]).pick_files() {
                        for path in paths {
                            if !self.files.is_empty() { self.files.push('\n'); }
                            self.files.push_str(&path.to_string_lossy());
                        }
                    }
                }
                if ui.add_enabled(!busy && !self.files.trim().is_empty(), egui::Button::new("Import and index PDFs")).clicked() {
                    let mut args = arguments("pdf", "", &self.roots);
                    for path in self.files.lines().map(str::trim).filter(|s| !s.is_empty()) {
                        args.extend(["--file".into(), path.trim_matches('"').into()]);
                    }
                    if !self.source_url.trim().is_empty() { args.extend(["--source-url".into(), self.source_url.trim().into()]); }
                    args.push("--password-stdin".into());
                    command = Some((args, Some(json!({"password":self.password}).to_string())));
                    self.password.clear();
                }
            });
            ui.add(egui::TextEdit::multiline(&mut self.files).desired_rows(2).desired_width(f32::INFINITY).hint_text("Selected local PDF paths"));
            ui.small("Text, page images and structured tables, including scans; English/Russian OCR; searchable PDF copy. Originals stay intact.");
            egui::CollapsingHeader::new("PDF origin and password").show(ui, |ui| {
                ui.label("Published origin URL · optional, supplied by you");
                ui.add(egui::TextEdit::singleline(&mut self.source_url).desired_width(f32::INFINITY).hint_text("https://…/document.pdf"));
                ui.label("Password · optional; not stored");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY));
            });
        });
        if !self.error.is_empty() { ui.colored_label(ui.visuals().error_fg_color, &self.error); }
        if let Some(result) = &self.result {
            let inventory = if result["inventory"].is_object() { &result["inventory"] } else { result };
            if inventory["document_count"].is_number() {
                ui.add_space(14.0);
                crate::card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let doc_cnt = inventory["document_count"].as_u64().unwrap_or(0);
                        let chunk_cnt = inventory["chunk_count"].as_u64().unwrap_or(0);
                        let sem_cnt = inventory["semantic_chunks"].as_u64().unwrap_or(0);
                        crate::bento_chip(ui, "📄", "DOCUMENTS", &format!("{doc_cnt}"), crate::theme::COLOR_INFO);
                        crate::bento_chip(ui, "📑", "INDEXED FRAGMENTS", &format!("{chunk_cnt}"), crate::theme::COLOR_SUCCESS);
                        crate::bento_chip(ui, "🧠", "SEMANTIC VECTORS", &format!("{sem_cnt}"), crate::theme::COLOR_ACCENT);
                    });
                });
            }
            let analysis = &result["analysis"];
            if analysis.is_object() {
                ui.separator(); ui.heading("Answer");
                ui.label(format!("AI: {}", analysis["status"].as_str().unwrap_or("unknown")));
                if let Some(error) = analysis["error"].as_str() { ui.colored_label(ui.visuals().error_fg_color, error); }
                ui.label(analysis["answer"].as_str().filter(|s| !s.is_empty()).unwrap_or("No supported conclusion. Review the retrieved source excerpts below."));
                if let Some(claims) = analysis["claims"].as_array() {
                    for claim in claims {
                        egui::CollapsingHeader::new(format!("{} · cited statement", claim["evidence_id"].as_str().unwrap_or(""))).show(ui, |ui| {
                            ui.label(claim["statement"].as_str().unwrap_or(""));
                            ui.label(egui::RichText::new(claim["quote"].as_str().unwrap_or("")).italics());
                            if let Some(page) = claim["page"].as_u64() {
                                ui.small(format!("Page {page}{}", claim["table"].as_u64().map(|t|
                                    format!(" · table {t} · row {}", claim["table_row"].as_u64().unwrap_or(0))).unwrap_or_default()));
                            }
                            source_buttons(ui, claim, &mut self.open_dossier);
                        });
                    }
                }
                if let Some(path) = result["report_markdown"].as_str() { if ui.button("Open answer export").clicked() { crate::open_url(path); } }
            }
            if let Some(rows) = result["evidence"].as_array() {
                ui.separator(); ui.heading(format!("Source excerpts · {}", rows.len()));
                if result["semantic_status"] == "unavailable" { ui.colored_label(ui.visuals().warn_fg_color, "Semantic model unavailable; keyword results are retained. Run setup-library.bat."); }
                for row in rows {
                    let page = row["page"].as_u64().map(|n| format!(" · page {n}")).unwrap_or_default();
                    let table = row["table"].as_u64().map(|n| format!(" · table {n} · row {}", row["table_row"].as_u64().unwrap_or(0))).unwrap_or_default();
                    egui::CollapsingHeader::new(format!("{} · {}{}{}", row["id"].as_str().unwrap_or(""), row["title"].as_str().unwrap_or("Source"), page, table)).default_open(true).show(ui, |ui| {
                        ui.label(row["text"].as_str().unwrap_or(""));
                        ui.small(row["attribution"].as_str().unwrap_or(""));
                        source_buttons(ui, row, &mut self.open_dossier);
                        ui.small(format!("SHA-256 {}", row["document_sha256"].as_str().unwrap_or("")));
                    });
                }
            }
            if let Some(pdfs) = result["pdfs"].as_array() {
                for pdf in pdfs {
                    ui.separator(); ui.strong(format!("{} · {}", pdf["title"].as_str().unwrap_or("PDF"), pdf["status"].as_str().unwrap_or("unknown")));
                    if let Some(count) = pdf["page_count"].as_u64() {
                        ui.label(format!("{count} pages · {} OCR pages · {} tables", pdf["ocr_pages"].as_u64().unwrap_or(0), pdf["table_count"].as_u64().unwrap_or(0)));
                    }
                    if let Some(path) = pdf["searchable_pdf"].as_str() { if ui.button("Open searchable PDF").clicked() { crate::open_url(path); } }
                    if let Some(pages) = pdf["pages"].as_array() {
                        egui::CollapsingHeader::new("Pages and extraction details").show(ui, |ui| {
                            for page in pages {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(format!("Page {} · {} · {}", page["page"], page["method"].as_str().unwrap_or(""), page["status"].as_str().unwrap_or("")));
                                    if let Some(path) = page["preview_path"].as_str() { if ui.button("View page").clicked() { crate::open_url(path); } }
                                });
                                for (index, table) in page["table_details"].as_array().into_iter().flatten().enumerate() {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(format!("Table {} · {} rows × {} columns · {}", index+1, table["rows"], table["columns"], table["method"].as_str().unwrap_or("")));
                                        if let Some(path) = page["table_csv"].get(index).and_then(Value::as_str) {
                                            if ui.button("Open CSV").clicked() { crate::open_url(path); }
                                        }
                                        if let Some(path) = page["table_json"].as_str() {
                                            if ui.button("Cells and spans JSON").clicked() { crate::open_url(path); }
                                        }
                                    });
                                    if table["cells"].as_array().is_some_and(|cells| cells.iter().any(|c| c["needs_review"] == true)) {
                                        ui.colored_label(ui.visuals().warn_fg_color, "Some cell text has low OCR confidence; verify the page image.");
                                    }
                                }
                                for error in page["errors"].as_array().into_iter().flatten() {
                                    ui.colored_label(ui.visuals().warn_fg_color, error.as_str().unwrap_or("Page extraction issue"));
                                }
                            }
                        });
                    }
                    for error in pdf["errors"].as_array().into_iter().flatten() { ui.colored_label(ui.visuals().warn_fg_color, error.as_str().unwrap_or("Extraction issue")); }
                }
            }
            egui::CollapsingHeader::new("Index and source diagnostics").show(ui, |ui| {
                ui.add(egui::TextEdit::multiline(&mut serde_json::to_string_pretty(inventory).unwrap_or_default()).desired_rows(8).desired_width(f32::INFINITY).interactive(false));
            });
        }
        command
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn question_and_roots_stay_separate_arguments() {
        let args = super::arguments("ask", "A company; $(echo test)", "C:/Saved dossiers\nD:/Other reports");
        assert_eq!(&args[3..5], &["--question", "A company; $(echo test)"]);
        assert_eq!(args.iter().filter(|v| *v == "--dossier-root").count(), 2);
    }
}
