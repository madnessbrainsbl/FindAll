use eframe::egui;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct ApplicationRecord {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub job_url: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub contact: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub next_date: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub updated: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct ApplicationStats {
    #[serde(default)]
    pub new: usize,
    #[serde(default)]
    pub contacted: usize,
    #[serde(default)]
    pub interview: usize,
    #[serde(default)]
    pub offer: usize,
    #[serde(default)]
    pub rejected: usize,
    #[serde(default)]
    pub closed: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TrackListOutput {
    #[serde(default)]
    pub stats: ApplicationStats,
    #[serde(default)]
    pub records: Vec<ApplicationRecord>,
    #[serde(default)]
    pub due: Vec<ApplicationRecord>,
    #[serde(default)]
    pub total: usize,
}

#[derive(Clone, Debug, Default)]
pub struct DraftState {
    pub is_open: bool,
    pub company: String,
    pub role: String,
    pub url: String,
    pub recipient: String,
    pub to_email: String,
    pub lang: String,
    pub kind: String,
    pub draft_text: String,
    pub is_loading: bool,
    pub error: String,
}

pub enum Action {
    Refresh,
    Add {
        company: String,
        role: String,
        url: String,
        contact: String,
        status: String,
        next_date: String,
        notes: String,
    },
    UpdateStatus {
        id: u64,
        status: String,
        next_date: Option<String>,
        notes: Option<String>,
    },
    GenerateDraft {
        company: String,
        role: String,
        url: String,
        recipient: String,
        to_email: String,
        lang: String,
        kind: String,
    },
    OpenUrl(String),
    SendEmail {
        recipient: String,
        subject: String,
        body: String,
    },
}

#[derive(Default)]
pub struct Workspace {
    pub output: Option<TrackListOutput>,
    pub error: String,
    pub status_filter: String,
    pub search_query: String,
    pub add_open: bool,
    pub new_company: String,
    pub new_role: String,
    pub new_url: String,
    pub new_contact: String,
    pub new_status: String,
    pub new_next_date: String,
    pub new_notes: String,
    pub editing_id: Option<u64>,
    pub edit_next_date: String,
    pub edit_notes: String,
    pub draft: DraftState,
}

impl Workspace {
    pub fn accept_list(&mut self, json_str: &str) {
        match serde_json::from_str::<TrackListOutput>(json_str) {
            Ok(data) => {
                self.output = Some(data);
                self.error.clear();
            }
            Err(e) => {
                self.error = format!("Failed to parse application tracking data: {e}");
            }
        }
    }

    pub fn accept_draft(&mut self, json_str: &str) {
        #[derive(Deserialize)]
        struct DraftResponse {
            ok: bool,
            #[serde(default)]
            draft: String,
            #[serde(default)]
            emails: String,
            #[serde(default)]
            error: String,
        }
        self.draft.is_loading = false;
        match serde_json::from_str::<DraftResponse>(json_str) {
            Ok(res) => {
                if res.ok {
                    self.draft.draft_text = res.draft;
                    if !res.emails.is_empty() && self.draft.to_email.is_empty() {
                        self.draft.to_email = res.emails;
                    }
                    self.draft.error.clear();
                } else {
                    self.draft.error = if !res.error.is_empty() {
                        res.error
                    } else {
                        "Failed to generate draft".into()
                    };
                }
            }
            Err(e) => {
                self.draft.error = format!("Failed to parse draft response: {e}");
            }
        }
    }

    pub fn open_draft_for_job(&mut self, company: String, role: String, url: String, contact_email: String) {
        self.draft.is_open = true;
        self.draft.company = company;
        self.draft.role = role;
        self.draft.url = url;
        self.draft.to_email = contact_email;
        self.draft.recipient = String::new();
        self.draft.lang = "ru".to_owned();
        self.draft.kind = "apply".to_owned();
        self.draft.draft_text.clear();
        self.draft.error.clear();
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<Action> {
        let mut action = None;

        if let Some(act) = self.render_draft_modal(ui, busy) {
            action = Some(act);
        }

        // Action Queue: Due follow-ups
        if let Some(out) = &self.output {
            if !out.due.is_empty() {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(32, 22, 14))
                    .stroke(egui::Stroke::new(1.0, crate::theme::COLOR_WARN))
                    .corner_radius(egui::CornerRadius::same(8))
                    .inner_margin(egui::Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("⏰").size(16.0));
                            ui.label(
                                egui::RichText::new(format!(
                                    "ACTION REQUIRED · {} application(s) due for follow-up today",
                                    out.due.len()
                                ))
                                .strong()
                                .color(crate::theme::COLOR_WARN),
                            );
                        });
                        ui.add_space(4.0);
                        for item in &out.due {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("• {} — {}", item.company, item.role))
                                        .strong()
                                        .color(egui::Color32::WHITE),
                                );
                                if !item.next_date.is_empty() {
                                    ui.label(
                                        egui::RichText::new(format!("(Due: {})", item.next_date))
                                            .size(11.0)
                                            .color(crate::theme::COLOR_WARN),
                                    );
                                }
                                if ui.small_button("⚡ Draft Re: Follow-up").clicked() {
                                    self.draft.is_open = true;
                                    self.draft.company = item.company.clone();
                                    self.draft.role = item.role.clone();
                                    self.draft.url = item.job_url.clone();
                                    self.draft.to_email = item.contact.clone();
                                    self.draft.lang = "ru".to_owned();
                                    self.draft.kind = "follow".to_owned();
                                    self.draft.draft_text.clear();
                                    action = Some(Action::GenerateDraft {
                                        company: item.company.clone(),
                                        role: item.role.clone(),
                                        url: item.job_url.clone(),
                                        recipient: String::new(),
                                        to_email: item.contact.clone(),
                                        lang: "ru".to_owned(),
                                        kind: "follow".to_owned(),
                                    });
                                }
                            });
                        }
                    });
                ui.add_space(10.0);
            }
        }

        // Bento Funnel Metrics
        crate::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let stats = self.output.as_ref().map(|o| &o.stats);
                let total = self.output.as_ref().map_or(0, |o| o.total);
                crate::bento_chip(ui, "📊", "TOTAL LEADS", &format!("{total}"), crate::theme::COLOR_INFO);
                crate::bento_chip(
                    ui,
                    "🆕",
                    "NEW",
                    &format!("{}", stats.map_or(0, |s| s.new)),
                    crate::theme::COLOR_INFO,
                );
                crate::bento_chip(
                    ui,
                    "📨",
                    "CONTACTED",
                    &format!("{}", stats.map_or(0, |s| s.contacted)),
                    crate::theme::COLOR_ACCENT,
                );
                crate::bento_chip(
                    ui,
                    "🤝",
                    "INTERVIEWS",
                    &format!("{}", stats.map_or(0, |s| s.interview)),
                    crate::theme::COLOR_WARN,
                );
                crate::bento_chip(
                    ui,
                    "🎉",
                    "OFFERS",
                    &format!("{}", stats.map_or(0, |s| s.offer)),
                    crate::theme::COLOR_SUCCESS,
                );
                let due_count = self.output.as_ref().map_or(0, |o| o.due.len());
                crate::bento_chip(
                    ui,
                    "⏰",
                    "DUE FOLLOW-UPS",
                    &format!("{due_count}"),
                    if due_count > 0 { crate::theme::COLOR_ERROR } else { crate::theme::COLOR_SUCCESS },
                );
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh Funnel").clicked() && !busy {
                    action = Some(Action::Refresh);
                }
                if ui
                    .button(if self.add_open { "✖ Close Form" } else { "➕ Add Application" })
                    .clicked()
                {
                    self.add_open = !self.add_open;
                }
                if ui.button("✍ Open Outreach Composer").clicked() {
                    self.draft.is_open = true;
                }
            });
        });

        // Add application form
        if self.add_open {
            ui.add_space(8.0);
            crate::card(ui, |ui| {
                ui.label(egui::RichText::new("Add Job Application to Tracking Pipeline").strong());
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Company *:");
                    ui.add(egui::TextEdit::singleline(&mut self.new_company).desired_width(180.0));
                    ui.label("Role / Title *:");
                    ui.add(egui::TextEdit::singleline(&mut self.new_role).desired_width(220.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Vacancy URL:");
                    ui.add(egui::TextEdit::singleline(&mut self.new_url).desired_width(320.0));
                    ui.label("Contact / Email:");
                    ui.add(egui::TextEdit::singleline(&mut self.new_contact).desired_width(180.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Status:");
                    egui::ComboBox::from_id_salt("new-app-status")
                        .selected_text(if self.new_status.is_empty() { "new" } else { &self.new_status })
                        .show_ui(ui, |ui| {
                            for s in &["new", "contacted", "interview", "offer", "rejected", "closed"] {
                                ui.selectable_value(&mut self.new_status, (*s).to_owned(), *s);
                            }
                        });
                    ui.label("Next Action Date (YYYY-MM-DD):");
                    ui.add(egui::TextEdit::singleline(&mut self.new_next_date).desired_width(110.0));
                });
                ui.horizontal(|ui| {
                    ui.label("Notes:");
                    ui.add(egui::TextEdit::singleline(&mut self.new_notes).desired_width(450.0));
                    if ui.add_enabled(!self.new_company.trim().is_empty() && !busy, egui::Button::new("Save Application")).clicked() {
                        let st = if self.new_status.is_empty() { "new".to_owned() } else { self.new_status.clone() };
                        action = Some(Action::Add {
                            company: self.new_company.trim().to_owned(),
                            role: self.new_role.trim().to_owned(),
                            url: self.new_url.trim().to_owned(),
                            contact: self.new_contact.trim().to_owned(),
                            status: st,
                            next_date: self.new_next_date.trim().to_owned(),
                            notes: self.new_notes.trim().to_owned(),
                        });
                        self.new_company.clear();
                        self.new_role.clear();
                        self.new_url.clear();
                        self.new_contact.clear();
                        self.new_notes.clear();
                        self.new_next_date.clear();
                        self.add_open = false;
                    }
                });
            });
        }

        ui.add_space(8.0);

        // Segmented Category Filter Pills
        let records = self.output.as_ref().map(|o| &o.records);
        let count_all = records.map_or(0, |r| r.len());
        let count_new = records.map_or(0, |r| r.iter().filter(|x| x.status == "new").count());
        let count_contacted = records.map_or(0, |r| r.iter().filter(|x| x.status == "contacted").count());
        let count_interview = records.map_or(0, |r| r.iter().filter(|x| x.status == "interview").count());
        let count_offer = records.map_or(0, |r| r.iter().filter(|x| x.status == "offer").count());
        let count_rejected = records.map_or(0, |r| r.iter().filter(|x| x.status == "rejected" || x.status == "closed").count());

        ui.horizontal_wrapped(|ui| {
            let pills = [
                ("all", format!("All ({count_all})")),
                ("new", format!("🆕 New ({count_new})")),
                ("contacted", format!("📨 Contacted ({count_contacted})")),
                ("interview", format!("🤝 Interview ({count_interview})")),
                ("offer", format!("🎉 Offer ({count_offer})")),
                ("rejected", format!("Archive ({count_rejected})")),
            ];
            for (key, label) in pills {
                let current_key = if self.status_filter.is_empty() { "all" } else { &self.status_filter };
                let is_active = current_key == key;
                let bg = if is_active {
                    crate::theme::BG_ACTIVE_PILL
                } else {
                    egui::Color32::from_rgb(16, 21, 30)
                };
                let border = if is_active {
                    crate::theme::COLOR_INFO
                } else {
                    crate::theme::BORDER_CARD
                };
                let text_color = if is_active {
                    egui::Color32::WHITE
                } else {
                    ui.visuals().weak_text_color()
                };
                let btn = egui::Button::new(egui::RichText::new(label).size(11.5).color(text_color).strong())
                    .fill(bg)
                    .stroke(egui::Stroke::new(1.0, border))
                    .corner_radius(egui::CornerRadius::same(6))
                    .min_size(egui::vec2(0.0, 24.0));
                if ui.add(btn).clicked() {
                    self.status_filter = if key == "all" { String::new() } else { key.to_owned() };
                }
            }
        });

        ui.add_space(4.0);

        // Search Filter
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔍 Search:").small().color(ui.visuals().weak_text_color()));
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Filter by company, role, or notes...")
                    .desired_width(260.0),
            );
            if !self.search_query.is_empty() && ui.button("✖").on_hover_text("Clear search query").clicked() {
                self.search_query.clear();
            }
        });

        ui.add_space(8.0);

        // List of Applications
        if let Some(out) = &self.output {
            let q = self.search_query.trim().to_lowercase();
            let filtered: Vec<_> = out
                .records
                .iter()
                .filter(|r| {
                    if !self.status_filter.is_empty() {
                        if self.status_filter == "rejected" {
                            if r.status != "rejected" && r.status != "closed" {
                                return false;
                            }
                        } else if r.status != self.status_filter {
                            return false;
                        }
                    }
                    if !q.is_empty() {
                        let text = format!("{} {} {} {}", r.company, r.role, r.notes, r.contact).to_lowercase();
                        if !text.contains(&q) {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if filtered.is_empty() {
                crate::card(ui, |ui| {
                    ui.label(egui::RichText::new("No applications match the current filter or search query.").small().weak());
                    ui.label(
                        egui::RichText::new("Search vacancies in the Jobs page and add them to the pipeline in 1 click.")
                            .small()
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for item in filtered {
                            if let Some(act) = self.render_application_row(ui, item, busy) {
                                action = Some(act);
                            }
                            ui.add_space(6.0);
                        }
                    });
            }
        } else if !busy {
            crate::card(ui, |ui| {
                ui.label("Applications pipeline not loaded.");
                if ui.button("Load from jobfind.db").clicked() {
                    action = Some(Action::Refresh);
                }
            });
        }

        action
    }

    fn render_application_row(&mut self, ui: &mut egui::Ui, item: &ApplicationRecord, busy: bool) -> Option<Action> {
        let mut action = None;
        let border_color = match item.status.as_str() {
            "new" => crate::theme::COLOR_INFO,
            "contacted" => crate::theme::COLOR_ACCENT,
            "interview" => crate::theme::COLOR_WARN,
            "offer" => crate::theme::COLOR_SUCCESS,
            _ => egui::Color32::from_rgb(100, 116, 139),
        };

        egui::Frame::new()
            .fill(egui::Color32::from_rgb(16, 21, 30))
            .stroke(egui::Stroke::new(1.0, crate::theme::BORDER_CARD))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 24.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, egui::CornerRadius::same(2), border_color);

                    ui.label(egui::RichText::new(&item.company).strong().size(14.0).color(egui::Color32::WHITE));
                    if !item.role.is_empty() {
                        ui.label(egui::RichText::new(format!("— {}", item.role)).color(crate::theme::COLOR_INFO));
                    }

                    egui::Frame::new()
                        .fill(border_color.gamma_multiply(0.2))
                        .stroke(egui::Stroke::new(1.0, border_color))
                        .corner_radius(egui::CornerRadius::same(4))
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(item.status.to_uppercase())
                                    .size(10.0)
                                    .strong()
                                    .color(border_color),
                            );
                        });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !item.job_url.is_empty() {
                            if ui.small_button("Open ↗").on_hover_text("Open vacancy posting URL in browser").clicked() {
                                action = Some(Action::OpenUrl(item.job_url.clone()));
                            }
                            if ui.small_button("📋 Link").clicked() {
                                ui.ctx().copy_text(item.job_url.clone());
                                ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Copied job URL".to_owned()));
                            }
                        }
                        if ui.small_button("✍ Draft Outreach").clicked() {
                            self.draft.is_open = true;
                            self.draft.company = item.company.clone();
                            self.draft.role = item.role.clone();
                            self.draft.url = item.job_url.clone();
                            self.draft.to_email = item.contact.clone();
                            self.draft.lang = "ru".to_owned();
                            self.draft.kind = "apply".to_owned();
                            self.draft.draft_text.clear();
                            action = Some(Action::GenerateDraft {
                                company: item.company.clone(),
                                role: item.role.clone(),
                                url: item.job_url.clone(),
                                recipient: String::new(),
                                to_email: item.contact.clone(),
                                lang: "ru".to_owned(),
                                kind: "apply".to_owned(),
                            });
                        }
                    });
                });

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if !item.contact.is_empty() {
                        ui.label(egui::RichText::new(format!("👤 Contact: {}", item.contact)).small().color(ui.visuals().weak_text_color()));
                        if ui.small_button("📋").on_hover_text("Copy contact info").clicked() {
                            ui.ctx().copy_text(item.contact.clone());
                            ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Contact copied to clipboard".to_owned()));
                        }
                        ui.label(egui::RichText::new("·").weak());
                    }
                    if !item.next_date.is_empty() {
                        ui.label(
                            egui::RichText::new(format!("📅 Next step: {}", item.next_date))
                                .small()
                                .color(crate::theme::COLOR_WARN),
                        );
                        ui.label(egui::RichText::new("·").weak());
                    }
                    if !item.updated.is_empty() {
                        let date_str = item.updated.split('T').next().unwrap_or(&item.updated);
                        ui.label(egui::RichText::new(format!("Updated: {date_str}")).small().color(ui.visuals().weak_text_color()));
                    }
                });

                if !item.notes.is_empty() {
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(&item.notes).small().color(egui::Color32::from_rgb(203, 213, 225)));
                }

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new("Stage:").size(11.0).weak());
                    if item.status == "new" && ui.add_enabled(!busy, egui::Button::new("→ Contacted").small()).clicked() {
                        action = Some(Action::UpdateStatus {
                            id: item.id,
                            status: "contacted".to_owned(),
                            next_date: None,
                            notes: None,
                        });
                    }
                    if (item.status == "new" || item.status == "contacted")
                        && ui.add_enabled(!busy, egui::Button::new("→ Interview").small()).clicked()
                    {
                        action = Some(Action::UpdateStatus {
                            id: item.id,
                            status: "interview".to_owned(),
                            next_date: None,
                            notes: None,
                        });
                    }
                    if item.status == "interview"
                        && ui.add_enabled(!busy, egui::Button::new("→ Offer 🎉").small()).clicked()
                    {
                        action = Some(Action::UpdateStatus {
                            id: item.id,
                            status: "offer".to_owned(),
                            next_date: None,
                            notes: None,
                        });
                    }
                    if item.status != "rejected" && item.status != "closed"
                        && ui.add_enabled(!busy, egui::Button::new("→ Reject / Close").small()).clicked()
                    {
                        action = Some(Action::UpdateStatus {
                            id: item.id,
                            status: "rejected".to_owned(),
                            next_date: None,
                            notes: None,
                        });
                    }
                    let is_editing = self.editing_id == Some(item.id);
                    if ui.small_button(if is_editing { "Done" } else { "✏ Edit Notes" }).clicked() {
                        if is_editing {
                            action = Some(Action::UpdateStatus {
                                id: item.id,
                                status: item.status.clone(),
                                next_date: Some(self.edit_next_date.trim().to_owned()),
                                notes: Some(self.edit_notes.trim().to_owned()),
                            });
                            self.editing_id = None;
                        } else {
                            self.editing_id = Some(item.id);
                            self.edit_next_date = item.next_date.clone();
                            self.edit_notes = item.notes.clone();
                        }
                    }
                });

                if self.editing_id == Some(item.id) {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("Next Date:");
                        ui.add(egui::TextEdit::singleline(&mut self.edit_next_date).desired_width(110.0));
                        ui.label("Notes:");
                        ui.add(egui::TextEdit::singleline(&mut self.edit_notes).desired_width(320.0));
                    });
                }
            });

        action
    }

    fn render_draft_modal(&mut self, ui: &mut egui::Ui, busy: bool) -> Option<Action> {
        let mut action = None;
        if !self.draft.is_open {
            return action;
        }

        crate::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("✍").size(16.0));
                ui.label(
                    egui::RichText::new(format!(
                        "Outreach & Cover Letter Composer — {} ({})",
                        if self.draft.company.is_empty() { "Custom Company" } else { &self.draft.company },
                        if self.draft.role.is_empty() { "Role" } else { &self.draft.role }
                    ))
                    .strong()
                    .color(egui::Color32::WHITE),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("✖ Close").clicked() {
                        self.draft.is_open = false;
                    }
                });
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Company:");
                ui.add(egui::TextEdit::singleline(&mut self.draft.company).desired_width(180.0));
                ui.label("Role / Title:");
                ui.add(egui::TextEdit::singleline(&mut self.draft.role).desired_width(200.0));
                ui.label("Recipient Name:");
                ui.add(egui::TextEdit::singleline(&mut self.draft.recipient).desired_width(140.0));
            });

            ui.horizontal(|ui| {
                ui.label("Recipient Email:");
                ui.add(egui::TextEdit::singleline(&mut self.draft.to_email).desired_width(240.0));
                ui.label("Language:");
                egui::ComboBox::from_id_salt("draft-lang")
                    .selected_text(if self.draft.lang == "en" { "English (EN)" } else { "Русский (RU)" })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.draft.lang, "ru".to_owned(), "Русский (RU)");
                        ui.selectable_value(&mut self.draft.lang, "en".to_owned(), "English (EN)");
                    });
                ui.label("Template:");
                egui::ComboBox::from_id_salt("draft-kind")
                    .selected_text(match self.draft.kind.as_str() {
                        "apply" => "Прямой отклик (Apply)",
                        "recruiter" => "Рекрутеру (Recruiter)",
                        "follow" => "Фоллоу-ап (Follow-up)",
                        _ => "Прямой отклик",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.draft.kind, "apply".to_owned(), "Прямой отклик (Apply)");
                        ui.selectable_value(&mut self.draft.kind, "recruiter".to_owned(), "Рекрутеру (Recruiter)");
                        ui.selectable_value(&mut self.draft.kind, "follow".to_owned(), "Фоллоу-ап (Follow-up)");
                    });
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("⚡ Generate Draft"))
                    .clicked()
                {
                    self.draft.is_loading = true;
                    action = Some(Action::GenerateDraft {
                        company: self.draft.company.clone(),
                        role: self.draft.role.clone(),
                        url: self.draft.url.clone(),
                        recipient: self.draft.recipient.clone(),
                        to_email: self.draft.to_email.clone(),
                        lang: self.draft.lang.clone(),
                        kind: self.draft.kind.clone(),
                    });
                }

                if !self.draft.draft_text.is_empty() {
                    if ui.button("📋 Copy to Clipboard").clicked() {
                        ui.ctx().copy_text(self.draft.draft_text.clone());
                        ui.data_mut(|d| {
                            d.insert_temp(
                                egui::Id::new("toast_pending"),
                                "Cover letter copied to clipboard".to_owned(),
                            )
                        });
                    }

                    if ui.button("✉ Send via SMTP").clicked() {
                        let mut lines = self.draft.draft_text.lines();
                        let first = lines.next().unwrap_or("");
                        let subject = if first.starts_with("Тема:") || first.starts_with("Subject:") {
                            first.trim_start_matches("Тема:").trim_start_matches("Subject:").trim().to_owned()
                        } else {
                            format!("Application: {} at {}", self.draft.role, self.draft.company)
                        };
                        let body = lines.collect::<Vec<_>>().join("\n").trim().to_owned();

                        action = Some(Action::SendEmail {
                            recipient: self.draft.to_email.clone(),
                            subject,
                            body,
                        });
                    }
                }
            });

            if !self.draft.error.is_empty() {
                ui.colored_label(ui.visuals().error_fg_color, &self.draft.error);
            }

            if !self.draft.draft_text.is_empty() {
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.draft.draft_text)
                        .desired_width(ui.available_width())
                        .desired_rows(12)
                        .font(egui::TextStyle::Monospace),
                );
            }
        });
        ui.add_space(10.0);

        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_output_deserialization() {
        let json = r#"{
            "stats": {"new": 2, "contacted": 1, "interview": 0, "offer": 0, "rejected": 0, "closed": 0},
            "records": [
                {"id": 1, "job_url": "https://example.com/job/1", "company": "Acme", "role": "Rust Dev", "contact": "hr@acme.com", "status": "new", "next_date": "2026-10-30", "notes": "Applied", "updated": "2026-10-24T12:00:00Z"}
            ],
            "due": [],
            "total": 3
        }"#;

        let mut ws = Workspace::default();
        ws.accept_list(json);
        assert!(ws.error.is_empty());
        let out = ws.output.unwrap();
        assert_eq!(out.total, 3);
        assert_eq!(out.stats.new, 2);
        assert_eq!(out.stats.contacted, 1);
        assert_eq!(out.records.len(), 1);
        assert_eq!(out.records[0].company, "Acme");
    }

    #[test]
    fn test_draft_response_parsing() {
        let json = r#"{
            "ok": true,
            "draft": "Subject: Rust Dev — Experience\n\nHello Team,\n\nI am applying...",
            "emails": "recruiter@corp.com",
            "error": ""
        }"#;

        let mut ws = Workspace::default();
        ws.accept_draft(json);
        assert!(ws.draft.error.is_empty());
        assert!(ws.draft.draft_text.contains("Subject: Rust Dev"));
        assert_eq!(ws.draft.to_email, "recruiter@corp.com");
    }

    #[test]
    fn test_open_draft_for_job() {
        let mut ws = Workspace::default();
        ws.open_draft_for_job("Stripe".into(), "Staff Engineer".into(), "https://stripe.com/jobs/1".into(), "hr@stripe.com".into());
        assert!(ws.draft.is_open);
        assert_eq!(ws.draft.company, "Stripe");
        assert_eq!(ws.draft.role, "Staff Engineer");
        assert_eq!(ws.draft.to_email, "hr@stripe.com");
        assert_eq!(ws.draft.lang, "ru");
        assert_eq!(ws.draft.kind, "apply");
    }
}
