#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod archives;
mod diagram;
mod enrichment;
mod analytics;
mod library;
mod browser;
mod theme;
mod wireless;
use eframe::egui;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

pub(crate) fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> egui::InnerResponse<R> {
    let width = ui.available_width();
    egui::Frame::new()
        .fill(theme::BG_CARD)
        .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(theme::CARD_PADDING)
        .show(ui, |ui| {
            ui.set_width((width - 2.0 * f32::from(theme::CARD_PADDING) - 2.0).max(0.0));
            add(ui)
        })
}

fn primary_button(ui: &mut egui::Ui, label: &str, enabled: bool) -> egui::Response {
    let fill = if enabled {
        ui.visuals().selection.bg_fill
    } else {
        egui::Color32::from_rgb(20, 25, 36)
    };
    let stroke = if enabled {
        egui::Stroke::new(1.0, ui.visuals().hyperlink_color)
    } else {
        egui::Stroke::new(1.0, theme::BORDER_CARD)
    };
    let text = if enabled {
        egui::RichText::new(label)
            .color(ui.visuals().selection.stroke.color)
            .strong()
    } else {
        egui::RichText::new(label).color(ui.visuals().weak_text_color())
    };
    ui.add_enabled(
        enabled,
        egui::Button::new(text)
            .fill(fill)
            .stroke(stroke)
            .corner_radius(egui::CornerRadius::same(6))
            .min_size(egui::vec2(
                ui.available_width().min(220.0),
                theme::ACTION_HEIGHT,
            )),
    )
}

pub(crate) fn workspace_hero(
    ui: &mut egui::Ui,
    icon: &str,
    title: &str,
    description: &str,
    badge: Option<(&str, egui::Color32)>,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{icon}  {title}"))
                .size(22.0)
                .strong()
                .color(egui::Color32::WHITE),
        );
        if let Some((badge_text, badge_color)) = badge {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(badge_color.gamma_multiply(0.15))
                .stroke(egui::Stroke::new(1.0, badge_color.gamma_multiply(0.5)))
                .corner_radius(egui::CornerRadius::same(4))
                .inner_margin(egui::Margin::symmetric(8, 3))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(badge_text)
                            .size(11.0)
                            .strong()
                            .color(badge_color),
                    );
                });
        }
    });
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(description)
            .size(13.5)
            .color(ui.visuals().weak_text_color()),
    );
    ui.add_space(14.0);
}

fn enter_submitted(ui: &egui::Ui, response: &egui::Response) -> bool {
    response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter))
}

pub(crate) fn bento_chip(ui: &mut egui::Ui, icon: &str, label: &str, value: &str, accent: egui::Color32) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(16, 21, 30))
        .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(icon).size(13.0));
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(label)
                            .size(10.5)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.label(
                        egui::RichText::new(value)
                            .size(13.0)
                            .strong()
                            .color(accent),
                    );
                });
            });
        });
}

pub(crate) fn kbd_badge(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(24, 30, 42))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 64, 84)))
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(5, 2))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .monospace()
                    .size(10.0)
                    .strong()
                    .color(egui::Color32::from_rgb(203, 213, 225)),
            );
        });
}

fn dossier_row(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    source: &str,
    url: &str,
    status: &str,
) {
    let width = ui.available_width().min(900.0);
    let border_color = if status.contains("unverified") || status.contains("warning") {
        theme::COLOR_WARN.gamma_multiply(0.4)
    } else {
        theme::BORDER_CARD
    };
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(15, 19, 28))
        .stroke(egui::Stroke::new(1.0, border_color))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width((width - 26.0).max(0.0));
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("▪").size(10.0).color(theme::COLOR_INFO));
                    ui.label(egui::RichText::new(title).strong().color(egui::Color32::WHITE));
                });
                if !detail.is_empty() {
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(detail).color(ui.visuals().weak_text_color()));
                }
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if !source.is_empty() || !status.is_empty() {
                        let (icon, color) = if status.contains("verified") || status.contains("Published") {
                            ("✓", theme::COLOR_SUCCESS)
                        } else if status.contains("unverified") || status.contains("warning") || status.contains("candidate") {
                            ("⚠", theme::COLOR_WARN)
                        } else if status.contains("error") || status.contains("blocked") || status.contains("failed") {
                            ("✖", theme::COLOR_ERROR)
                        } else {
                            ("ℹ", theme::COLOR_INFO)
                        };
                        let badge_text = format!(
                            "{}{}{}",
                            source,
                            if source.is_empty() || status.is_empty() { "" } else { " · " },
                            status
                        );
                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(20, 26, 38))
                            .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(icon).size(10.5).color(color).strong());
                                    ui.label(
                                        egui::RichText::new(badge_text)
                                            .color(ui.visuals().text_color())
                                            .size(11.0),
                                    );
                                });
                            });
                    }
                    if url.starts_with("https://") {
                        ui.hyperlink_to("Open source ↗", url);
                    } else if let Some(hash) = url.strip_prefix("artifact:sha256:") {
                        ui.label(
                            egui::RichText::new(format!(
                                "SHA-256 {}",
                                &hash[..hash.len().min(12)]
                            ))
                            .monospace()
                            .size(11.0)
                            .color(ui.visuals().weak_text_color()),
                        );
                        if ui.small_button("📋 Copy checksum").clicked() {
                            ui.ctx().copy_text(hash.to_owned());
                            ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Copied SHA-256 to clipboard".to_owned()));
                        }
                    } else if !url.is_empty() && ui.small_button("📋 Copy source URL").clicked() {
                        ui.ctx().copy_text(url.to_owned());
                        ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Copied URL to clipboard".to_owned()));
                    }
                });
            });
        });
    ui.add_space(6.0);
}

fn observation_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => if *value { "Yes" } else { "No" }.to_owned(),
        serde_json::Value::Array(values) => values
            .iter()
            .take(12)
            .filter_map(|item| {
                if item.is_string() || item.is_number() {
                    Some(observation_value(item))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    }
}

fn observation_field(ui: &mut egui::Ui, label: &str, value: &serde_json::Value) {
    let text = observation_value(value);
    if text.is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).color(ui.visuals().weak_text_color()));
        ui.label(text);
    });
}

fn observation_source(ui: &mut egui::Ui, row: &serde_json::Value) {
    ui.horizontal_wrapped(|ui| {
        if let Some(source) = row["source"].as_str().filter(|source| !source.is_empty()) {
            ui.label(
                egui::RichText::new(source)
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }
        if let Some(date) = row["checked_at"].as_str().filter(|date| !date.is_empty()) {
            ui.label(
                egui::RichText::new(format!("Checked {date}"))
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        }
        if let Some(url) = row["url"]
            .as_str()
            .filter(|url| url.starts_with("https://"))
        {
            ui.hyperlink_to("Open source ↗", url);
        }
    });
}

fn render_domain_card(ui: &mut egui::Ui, structured: &serde_json::Value) {
    egui::CollapsingHeader::new("DNS and domain registration").default_open(true).show(ui, |ui| {
        ui.label(egui::RichText::new("Registration is a domain event, not the company's founding date. DNS and ASN links do not establish ownership.").small().color(ui.visuals().weak_text_color()));
        let registration = &structured["registration"];
        ui.add_space(8.0);
        ui.label(egui::RichText::new(format!("Registration · {}", registration["state"].as_str().unwrap_or("not checked")).replace('_', " ")).strong());
        for (field, label) in [("created", "Registered"), ("updated", "Last changed"),
                               ("expires", "Expires"), ("registrar", "Registrar"), ("age_years", "Domain age in years")] {
            observation_field(ui, label, &registration[field]);
        }
        if registration["redacted"].as_bool().unwrap_or(false) {
            ui.label(egui::RichText::new("Registration contacts are redacted; the owner cannot be identified from this response.").small().color(ui.visuals().weak_text_color()));
        }
        observation_field(ui, "Domain status", &registration["domain_status"]);
        observation_field(ui, "Collection note", &registration["detail"]);
        observation_source(ui, registration);
        if structured["null_mx"].as_bool().unwrap_or(false) {
            ui.add_space(8.0);
            ui.label("Null MX: this domain explicitly declares that it does not accept email.");
        }
        if let Some(records) = structured["records"].as_object() {
            ui.add_space(12.0);
            ui.label(egui::RichText::new("DNS records").strong());
            for (kind, record) in records {
                let rows = record["records"].as_array();
                let count = rows.map_or(0, Vec::len);
                let state = record["state"].as_str().unwrap_or("not checked").replace('_', " ");
                let title = format!("{kind} · {count} record{} · {state}", if count == 1 { "" } else { "s" });
                egui::CollapsingHeader::new(title).id_salt(("domain-record", kind)).default_open(count > 0 && matches!(kind.as_str(), "A" | "AAAA" | "MX")).show(ui, |ui| {
                    if let Some(rows) = rows.filter(|rows| !rows.is_empty()) {
                        for row in rows.iter().take(20) {
                            observation_field(ui, "Value", &row["value"]);
                            ui.horizontal_wrapped(|ui| {
                                if let Some(name) = row["name"].as_str() { ui.label(egui::RichText::new(name).small().color(ui.visuals().weak_text_color())); }
                                if let Some(ttl) = row["ttl"].as_u64() { ui.label(egui::RichText::new(format!("TTL {ttl} s")).small().color(ui.visuals().weak_text_color())); }
                            });
                            ui.add_space(4.0);
                        }
                        if rows.len() > 20 { ui.label(format!("Showing 20 of {} records. The dossier retains all records.", rows.len())); }
                    } else {
                        ui.label(match record["state"].as_str().unwrap_or("") {
                            "no_records" => "The response contains no records of this type.",
                            "nxdomain" => "The resolver reported NXDOMAIN for this name.",
                            "timeout" => "The lookup timed out; record availability is unknown.",
                            "error" | "blocked" | "rate_limited" => "The lookup failed; record availability is unknown.",
                            _ => "No DNS record values were collected.",
                        });
                    }
                    observation_field(ui, "Collection note", &record["detail"]);
                    observation_source(ui, record);
                    if kind == "PTR" {
                        if let Some(queries) = record["queries"].as_array() {
                            for query in queries.iter().take(4) {
                                ui.add_space(4.0);
                                ui.label(format!("Reverse lookup {} · {}", query["address"].as_str().unwrap_or(""), query["state"].as_str().unwrap_or("unknown").replace('_', " ")));
                                observation_source(ui, query);
                            }
                        }
                    }
                });
            }
        }
    });
}

fn render_history(ui: &mut egui::Ui, history: &serde_json::Value) {
    if !history.is_object() {
        return;
    }
    let comparison = &history["comparison"];
    egui::CollapsingHeader::new("Snapshot comparison").default_open(true).show(ui, |ui| {
        ui.label(egui::RichText::new("An incomplete source check cannot establish deletion. Archived observations do not confirm current availability.").small().color(ui.visuals().weak_text_color()));
        if comparison["status"].as_str() == Some("no_previous_snapshot") {
            ui.label("This is the first retained snapshot for this query and input type.");
            return;
        }
        observation_field(ui, "Comparison outcome", &comparison["status"]);
        observation_field(ui, "Previous collection", &comparison["previous_observed_at"]);
        observation_field(ui, "Current collection", &comparison["current_observed_at"]);
        if let Some(path) = comparison["previous_report"].as_str() {
            if ui.small_button("Open previous dossier").clicked() { open_url(path); }
        }
        let added = comparison["added"].as_array();
        let missing = comparison["missing"].as_array();
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for text in [format!("{} newly observed", added.map_or(0, Vec::len)),
                         format!("{} not observed again", missing.map_or(0, Vec::len)),
                         format!("{} unchanged", comparison["unchanged_count"].as_u64().unwrap_or(0))] { ui.label(text); }
        });
        for (label, rows) in [("Newly observed", added), ("Not observed in the current snapshot", missing)] {
            if let Some(rows) = rows.filter(|rows| !rows.is_empty()) {
                egui::CollapsingHeader::new(format!("{label} · {}", rows.len())).show(ui, |ui| {
                    for row in rows.iter().take(30) {
                        let state = if row["change"].as_str() == Some("absent_from_complete_snapshot") {
                            "Absent from a complete source response; deletion is not established"
                        } else if row["change"].as_str() == Some("not_observed") {
                            "Not observed again; comparison coverage is incomplete"
                        } else { "Newly collected observation" };
                        let detail = format!("{}{}", row["section"].as_str().unwrap_or("Evidence").replace('_', " "),
                            if row["archived"].as_bool().unwrap_or(false) { " · historical evidence; current validity unverified" } else { "" });
                        dossier_row(ui, row["value"].as_str().unwrap_or("Observation"), &detail,
                            row["source"].as_str().unwrap_or(""), row["url"].as_str().unwrap_or(""), state);
                    }
                    if rows.len() > 30 { ui.label(format!("Showing 30 of {} changes. Open Markdown or JSON for the full comparison.", rows.len())); }
                });
            }
        }
    });
    if let Some(events) = history["timeline"]
        .as_array()
        .filter(|events| !events.is_empty())
    {
        egui::CollapsingHeader::new(format!("Observation timeline · {}", events.len())).show(ui, |ui| {
            ui.label(egui::RichText::new("Source snapshot and provider first/last seen dates differ from collection time.").small().color(ui.visuals().weak_text_color()));
            for event in events.iter().rev().take(40) {
                ui.label(egui::RichText::new(format!("{} · {}", event["date"].as_str().unwrap_or("Undated"), event["event"].as_str().unwrap_or("Observation").replace('_', " "))).strong());
                let status = if event["archived"].as_bool().unwrap_or(false) { "Historical evidence · present validity unverified" } else { "Dated source observation" };
                dossier_row(ui, event["label"].as_str().unwrap_or("Observation"),
                    &format!("Collected {}", event["collected_at"].as_str().unwrap_or("unknown")),
                    event["source"].as_str().unwrap_or(""), event["url"].as_str().unwrap_or(""), status);
            }
            if events.len() > 40 { ui.label(format!("Showing the latest 40 of {} events. Open Markdown or JSON for the full timeline.", events.len())); }
        });
    }
}

fn render_dossier_sections(ui: &mut egui::Ui, sections: &serde_json::Value) {
    let web = sections["web"].as_array();
    let profiles = sections["profiles"].as_array();
    let emails = sections["emails"].as_array();
    let findings = sections["findings"].as_array();
    let domain = &sections["domain"];
    let assets = domain["assets"].as_array();
    let jobs = sections["jobs"].as_array();
    let spiderfoot_events = sections["spiderfoot"]["event_count"].as_u64().unwrap_or(0) as usize;
    ui.add_space(12.0);
    ui.horizontal_wrapped(|ui| {
        for (name, count) in [
            ("Web pages kept", web.map_or(0, Vec::len)),
            ("Profiles", profiles.map_or(0, Vec::len)),
            ("Published emails", emails.map_or(0, Vec::len)),
            ("Domain assets", assets.map_or(0, Vec::len)),
            ("Company vacancies", jobs.map_or(0, Vec::len)),
            ("SpiderFoot events", spiderfoot_events),
        ] {
            ui.label(
                egui::RichText::new(format!("{count} {name}")).color(ui.visuals().hyperlink_color),
            );
        }
    });
    if let Some(rows) = jobs.filter(|rows| !rows.is_empty()) {
        egui::CollapsingHeader::new(format!("Company vacancies · {}", rows.len()))
            .default_open(true)
            .show(ui, |ui| {
                for row in rows.iter().take(30) {
                    let detail = format!(
                        "{} · {}",
                        row["company"].as_str().unwrap_or(""),
                        row["location"].as_str().unwrap_or("")
                    );
                    dossier_row(
                        ui,
                        row["title"].as_str().unwrap_or("Vacancy"),
                        &detail,
                        row["source"].as_str().unwrap_or("ATS"),
                        row["url"].as_str().unwrap_or(""),
                        "Published by linked career platform",
                    );
                    if let Some(source) = row["company_source_url"].as_str() {
                        if ui.small_button("Open company association source").clicked() {
                            open_url(source);
                        }
                    }
                }
            });
    }
    if let Some(rows) = sections["careers"]
        .as_array()
        .filter(|rows| !rows.is_empty())
    {
        egui::CollapsingHeader::new(format!("Career pages · {}", rows.len())).show(ui, |ui| {
            for row in rows {
                dossier_row(
                    ui,
                    row["title"].as_str().unwrap_or("Career page"),
                    row["tenant"].as_str().unwrap_or(""),
                    row["source"].as_str().unwrap_or("Company site"),
                    row["url"].as_str().unwrap_or(""),
                    row["status"].as_str().unwrap_or("Candidate"),
                );
            }
        });
    }
    if let Some(rows) = web.filter(|rows| !rows.is_empty()) {
        ui.add_space(8.0);
        egui::CollapsingHeader::new(format!("Web pages · {}", rows.len()))
            .default_open(true)
            .show(ui, |ui| {
                for row in rows.iter().take(12) {
                    dossier_row(
                        ui,
                        row["title"].as_str().unwrap_or("Untitled page"),
                        row["snippet"].as_str().unwrap_or(""),
                        row["source"].as_str().unwrap_or("Web search"),
                        row["url"].as_str().unwrap_or(""),
                        "Search match · identity unverified",
                    );
                }
                if rows.len() > 12 {
                    ui.label(format!(
                        "Showing 12 of {}. Open the dossier for all pages.",
                        rows.len()
                    ));
                }
            });
    }
    if let Some(rows) = profiles.filter(|rows| !rows.is_empty()) {
        egui::CollapsingHeader::new(format!("Public profiles · {}", rows.len()))
            .default_open(true)
            .show(ui, |ui| {
                for row in rows.iter().take(12) {
                    let detail = match row["bio"].as_str().filter(|bio| !bio.is_empty()) {
                        Some(bio) => format!("{} · {bio}", row["username"].as_str().unwrap_or("")),
                        None => row["username"].as_str().unwrap_or("").to_owned(),
                    };
                    dossier_row(
                        ui,
                        row["site"].as_str().unwrap_or("Profile"),
                        &detail,
                        row["source"].as_str().unwrap_or("Maigret"),
                        row["url"].as_str().unwrap_or(""),
                        "Same handle · account ownership unverified",
                    );
                }
                if rows.len() > 12 {
                    ui.label(format!(
                        "Showing 12 of {}. Open the dossier for all profiles.",
                        rows.len()
                    ));
                }
            });
    }
    if let Some(rows) = emails.filter(|rows| !rows.is_empty()) {
        egui::CollapsingHeader::new(format!("Published emails · {}", rows.len()))
            .default_open(true)
            .show(ui, |ui| {
                for row in rows {
                    dossier_row(
                        ui,
                        row["email"].as_str().unwrap_or("Email"),
                        row["attribution"].as_str().unwrap_or(""),
                        row["source"].as_str().unwrap_or("Public page"),
                        row["url"].as_str().unwrap_or(""),
                        "Published · mailbox owner unverified",
                    );
                }
            });
    }
    if let Some(name) = domain["domain"].as_str() {
        egui::CollapsingHeader::new(format!("Domain details · {name}"))
            .default_open(true).show(ui, |ui| {
                let structured = if domain["domain_card"].is_object() { &domain["domain_card"] }
                    else if sections["domain_card"].is_object() { &sections["domain_card"] }
                    else { &domain["dns"] };
                if structured.is_object() {
                    if structured["records"].is_object() || structured["registration"].is_object() { render_domain_card(ui, structured); }
                }
                if let Some(dns) = domain["dns"].as_object() {
                    ui.label(egui::RichText::new("DNS and registration").strong());
                    for (field, value) in dns {
                        if matches!(field.as_str(), "domain" | "records" | "registration" | "limits" | "checked_at" | "domain_card") || value.is_null() { continue; }
                        let detail = observation_value(value);
                        if detail.is_empty() { continue; }
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(field.replace('_', " ")).color(ui.visuals().weak_text_color()));
                            ui.label(detail);
                        });
                    }
                    if ui.button("Open registration source ↗").clicked() {
                        open_url(&format!("https://rdap.org/domain/{name}"));
                    }
                }
                if let Some(rows) = domain["subdomains"].as_array().filter(|rows| !rows.is_empty()) {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!("Subdomains · {}", rows.len())).strong());
                    for row in rows.iter().take(20) {
                        let ips = row["ips"].as_array().map(|values| values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                        let providers = row["sources"].as_array().map(|values| values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
                        let source_url = if providers.contains("crt.sh") {
                            format!("https://crt.sh/?q=%25.{name}")
                        } else if providers.contains("CertSpotter") {
                            format!("https://api.certspotter.com/v1/issuances?domain={name}&include_subdomains=true")
                        } else { String::new() };
                        dossier_row(ui, row["name"].as_str().unwrap_or(""), &ips, &providers,
                            &source_url, "Certificate/DNS match · ownership unverified");
                    }
                    if rows.len() > 20 { ui.label(format!("Showing 20 of {}. Open the dossier for all names.", rows.len())); }
                }
                if let Some(rows) = assets.filter(|rows| !rows.is_empty()) {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!("Observed services · {}", rows.len())).strong());
                    ui.label(egui::RichText::new("Services relate to resolved IPs; this does not prove equipment ownership.").color(ui.visuals().weak_text_color()).small());
                    for row in rows.iter().take(20) {
                        let ip = row["ip"].as_str().unwrap_or("");
                        let port = row["port"].as_str().unwrap_or("");
                        dossier_row(ui, &format!("{ip}{}", if port.is_empty() { String::new() } else { format!(":{port}") }),
                            row["product"].as_str().unwrap_or(""), row["provider"].as_str().unwrap_or(""),
                            row["url"].as_str().unwrap_or(""), "Observed service");
                    }
                    if rows.len() > 20 { ui.label(format!("Showing 20 of {}. Open the dossier for all services.", rows.len())); }
                }
                if let Some(rows) = domain["technologies"].as_array().filter(|rows| !rows.is_empty()) {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!("Website technologies · {}", rows.len())).strong());
                    for row in rows.iter().take(20) {
                        let confidence = row["confidence"].as_i64().map_or(String::new(), |number| format!("Detection confidence {number}"));
                        dossier_row(ui, row["name"].as_str().unwrap_or(""), row["version"].as_str().unwrap_or(""),
                            &confidence, &format!("https://{name}/"), "Detected on public website");
                    }
                }
                if let Some(statuses) = domain["statuses"].as_array().filter(|rows| !rows.is_empty()) {
                    egui::CollapsingHeader::new("Source status").show(ui, |ui| {
                        for row in statuses {
                            dossier_row(ui, row["name"].as_str().unwrap_or("Source"),
                                row["detail"].as_str().unwrap_or(""), "",
                                "", row["state"].as_str().unwrap_or(""));
                        }
                    });
                }
            });
    }
    if sections
        .get("spiderfoot")
        .is_some_and(|value| value.is_object())
    {
        let status = sections["spiderfoot"]["status"].as_str().unwrap_or("");
        let use_case = sections["spiderfoot"]["use_case"]
            .as_str()
            .unwrap_or("passive");
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(format!(
                "SpiderFoot {use_case} scan · {status} · {spiderfoot_events} events"
            ))
            .color(ui.visuals().weak_text_color()),
        );
    }
    if let Some(rows) = findings.filter(|rows| !rows.is_empty()) {
        ui.horizontal_wrapped(|ui| {
            bento_chip(ui, "📑", "FINDINGS", &format!("{} items", rows.len()), theme::COLOR_INFO);
            bento_chip(ui, "🌐", "FEDERATION", "Public sources", theme::COLOR_SUCCESS);
            bento_chip(ui, "⚖", "INTELLIGENCE", "Unverified claims", theme::COLOR_WARN);
        });
        ui.add_space(8.0);
        let facet = ui.data_mut(|d| {
            d.get_temp::<String>(egui::Id::new("dossier_findings_facet"))
                .unwrap_or_else(|| "all".to_owned())
        });
        let is_match = |row: &serde_json::Value, f: &str| -> bool {
            if f == "all" {
                return true;
            }
            let text = format!(
                "{} {} {} {}",
                row["event_type"].as_str().unwrap_or(""),
                row["title"].as_str().unwrap_or(""),
                row["source"].as_str().unwrap_or(""),
                row["value"].as_str().unwrap_or("")
            )
            .to_lowercase();
            match f {
                "profiles" => text.contains("profile") || text.contains("username") || text.contains("handle") || text.contains("social") || text.contains("maigret"),
                "infra" => text.contains("domain") || text.contains("dns") || text.contains("ip") || text.contains("host") || text.contains("network") || text.contains("port") || text.contains("cert"),
                "leaks" => text.contains("leak") || text.contains("breach") || text.contains("credential") || text.contains("password") || text.contains("hash"),
                "other" => !text.contains("profile") && !text.contains("username") && !text.contains("handle") && !text.contains("social") && !text.contains("domain") && !text.contains("dns") && !text.contains("ip") && !text.contains("host") && !text.contains("leak") && !text.contains("breach"),
                _ => true,
            }
        };
        let count_profiles = rows.iter().filter(|r| is_match(r, "profiles")).count();
        let count_infra = rows.iter().filter(|r| is_match(r, "infra")).count();
        let count_leaks = rows.iter().filter(|r| is_match(r, "leaks")).count();
        let count_other = rows.iter().filter(|r| is_match(r, "other")).count();

        ui.horizontal_wrapped(|ui| {
            let pills = [
                ("all", format!("All ({})", rows.len())),
                ("profiles", format!("👤 Profiles ({count_profiles})")),
                ("infra", format!("🌐 Infrastructure ({count_infra})")),
                ("leaks", format!("⚡ Leaks ({count_leaks})")),
                ("other", format!("📑 Records ({count_other})")),
            ];
            for (key, label) in pills {
                let is_active = facet == key;
                let bg = if is_active { theme::BG_ACTIVE_PILL } else { egui::Color32::from_rgb(16, 21, 30) };
                let border = if is_active { theme::COLOR_INFO } else { theme::BORDER_CARD };
                let text_color = if is_active { egui::Color32::WHITE } else { ui.visuals().weak_text_color() };
                let btn = egui::Button::new(egui::RichText::new(label).size(11.5).color(text_color).strong())
                    .fill(bg)
                    .stroke(egui::Stroke::new(1.0, border))
                    .corner_radius(egui::CornerRadius::same(6))
                    .min_size(egui::vec2(0.0, 24.0));
                if ui.add(btn).clicked() {
                    ui.data_mut(|d| d.insert_temp(egui::Id::new("dossier_findings_facet"), key.to_owned()));
                }
            }
        });
        ui.add_space(6.0);

        let mut query = ui.data_mut(|d| {
            d.get_temp::<String>(egui::Id::new("dossier_findings_query"))
                .unwrap_or_default()
        });
        let mut query_changed = false;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("🔍 Search:").small().color(ui.visuals().weak_text_color()));
            let response = ui.add(
                egui::TextEdit::singleline(&mut query)
                    .hint_text("Filter by keyword, source, URL...")
                    .desired_width(220.0),
            );
            if response.changed() {
                query_changed = true;
            }
            if !query.is_empty() && ui.button("✖").on_hover_text("Clear search filter").clicked() {
                query.clear();
                query_changed = true;
            }
        });
        if query_changed {
            ui.data_mut(|d| d.insert_temp(egui::Id::new("dossier_findings_query"), query.clone()));
        }
        ui.add_space(4.0);

        let query_lower = query.trim().to_lowercase();
        let filtered: Vec<_> = rows
            .iter()
            .filter(|r| {
                if !is_match(r, &facet) {
                    return false;
                }
                if query_lower.is_empty() {
                    return true;
                }
                let text = format!(
                    "{} {} {} {} {}",
                    r["event_type"].as_str().unwrap_or(""),
                    r["title"].as_str().unwrap_or(""),
                    r["source"].as_str().unwrap_or(""),
                    r["value"].as_str().unwrap_or(""),
                    r["url"].as_str().unwrap_or("")
                )
                .to_lowercase();
                text.contains(&query_lower)
            })
            .collect();

        ui.horizontal(|ui| {
            if !filtered.is_empty()
                && ui
                    .button("📋 Copy visible findings")
                    .on_hover_text("Copy visible findings to clipboard as Markdown list")
                    .clicked()
            {
                let mut md = String::new();
                for r in &filtered {
                    let etype = r["event_type"]
                        .as_str()
                        .or_else(|| r["title"].as_str())
                        .or_else(|| r["kind"].as_str())
                        .unwrap_or("Finding");
                    let val = r["value"]
                        .as_str()
                        .or_else(|| r["text"].as_str())
                        .unwrap_or("");
                    let src = r["source"]
                        .as_str()
                        .or_else(|| r["module"].as_str())
                        .unwrap_or("Collector");
                    let url = r["url"].as_str().unwrap_or("");
                    if !url.is_empty() {
                        md.push_str(&format!("- **{etype}**: {val} (via {src}, <{url}>)\n"));
                    } else {
                        md.push_str(&format!("- **{etype}**: {val} (via {src})\n"));
                    }
                }
                ui.ctx().copy_text(md);
                ui.data_mut(|d| {
                    d.insert_temp(
                        egui::Id::new("toast_pending"),
                        format!("✓ Copied {} finding(s) to clipboard", filtered.len()),
                    )
                });
            }
        });
        ui.add_space(4.0);

        egui::CollapsingHeader::new(format!("Collected findings · {}", filtered.len()))
            .default_open(true)
            .show(ui, |ui| {
                if filtered.is_empty() {
                    ui.label(egui::RichText::new("No findings match the selected filter category or query.").small().weak());
                }
                for row in filtered.iter().take(20) {
                    dossier_row(
                        ui,
                        row["event_type"]
                            .as_str()
                            .or_else(|| row["title"].as_str())
                            .or_else(|| row["kind"].as_str())
                            .unwrap_or("Finding"),
                        row["value"]
                            .as_str()
                            .or_else(|| row["text"].as_str())
                            .unwrap_or(""),
                        row["source"]
                            .as_str()
                            .or_else(|| row["module"].as_str())
                            .unwrap_or("Collector"),
                        row["url"].as_str().unwrap_or(""),
                        row["status"]
                            .as_str()
                            .unwrap_or("Collected record · ownership unverified"),
                    );
                }
                if filtered.len() > 20 {
                    ui.label(format!(
                        "Showing 20 of {}. Open the dossier for every finding.",
                        filtered.len()
                    ));
                }
            });
    }
    for (field, label) in [
        ("businesses", "Businesses and map objects"),
        ("webcheck_modules", "Web-Check modules"),
    ] {
        if let Some(rows) = sections[field].as_array().filter(|rows| !rows.is_empty()) {
            egui::CollapsingHeader::new(format!("{label} · {}", rows.len())).show(ui, |ui| {
                for row in rows.iter().take(50) {
                    let detail = if field == "businesses" {
                        row["address"].as_str().unwrap_or("").to_owned()
                    } else {
                        row["data"].to_string().chars().take(1200).collect()
                    };
                    dossier_row(
                        ui,
                        row["name"].as_str().unwrap_or("Record"),
                        &detail,
                        row["source"].as_str().unwrap_or(label),
                        row["url"].as_str().unwrap_or(""),
                        row["status"].as_str().unwrap_or("Public source record"),
                    );
                }
            });
        }
    }
    if web.map_or(true, Vec::is_empty)
        && profiles.map_or(true, Vec::is_empty)
        && emails.map_or(true, Vec::is_empty)
        && domain.is_null()
        && findings.map_or(true, Vec::is_empty)
        && spiderfoot_events == 0
    {
        ui.label("No matching public records were returned. Check source warnings and try a more specific query.");
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Browser,
    Library,
    Dossier,
    Search,
    Osint,
    Tools,
    Contacts,
    Network,
    Wireless,
    Archives,
    Diagram,
    Statistics,
}

impl Page {
    const GROUPS: [(&'static str, &'static [Self]); 3] = [
        ("Research", &[Self::Dossier, Self::Library, Self::Browser, Self::Archives, Self::Wireless]),
        (
            "Discovery",
            &[Self::Osint, Self::Search, Self::Tools, Self::Contacts],
        ),
        ("Workspace", &[Self::Diagram, Self::Statistics, Self::Network]),
    ];

    const ALL: [Self; 12] = [
        Self::Browser,
        Self::Library,
        Self::Dossier,
        Self::Archives,
        Self::Wireless,
        Self::Osint,
        Self::Search,
        Self::Tools,
        Self::Contacts,
        Self::Network,
        Self::Diagram,
        Self::Statistics,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Browser => "Browser research",
            Self::Library => "Evidence library",
            Self::Dossier => "Dossier",
            Self::Archives => "Archives",
            Self::Wireless => "Wireless",
            Self::Osint => "Web search",
            Self::Search => "Jobs and projects",
            Self::Tools => "Tools",
            Self::Contacts => "Contacts and email",
            Self::Network => "Network",
            Self::Diagram => "Diagram",
            Self::Statistics => "Statistics",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Browser => "🌐",
            Self::Library => "📁",
            Self::Dossier => "👤",
            Self::Archives => "🏛",
            Self::Wireless => "📡",
            Self::Osint => "🌐",
            Self::Search => "💼",
            Self::Tools => "🛠",
            Self::Contacts => "📇",
            Self::Network => "⚡",
            Self::Diagram => "🕸",
            Self::Statistics => "📊",
        }
    }

    fn group_name(self) -> &'static str {
        for (label, pages) in Self::GROUPS {
            if pages.contains(&self) {
                return label;
            }
        }
        "Workspace"
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Library => "library",
            Self::Dossier => "dossier",
            Self::Archives => "archives",
            Self::Wireless => "wireless",
            Self::Osint => "osint",
            Self::Search => "search",
            Self::Tools => "tools",
            Self::Contacts => "contacts",
            Self::Network => "network",
            Self::Diagram => "diagram",
            Self::Statistics => "statistics",
        }
    }

    fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|page| page.slug() == slug)
    }
}

#[derive(Clone, Copy)]
enum TaskKind {
    Browser,
    Library,
    Statistics,
    Enrichment,
    Network,
    Wireless,
    Archives,
    Dossier,
    AiModels,
    AiCheck,
    UnifiedSearch,
    OsintSearch,
    WorkspaceGraph,
    PageParse,
    ToolsCatalog,
    LocalAudit,
    WebCheck,
    DomainRecon,
    Maigret,
    GithubEmail,
    TikTokProfile,
    OnionSearch,
    TwoGis,
    ContactSearch,
    EmailSend,
}

struct TaskResult {
    kind: TaskKind,
    label: String,
    result: Result<String, String>,
    progress: Option<ProgressUpdate>,
}

#[derive(Clone, Default, Deserialize)]
struct ProgressUpdate {
    percent: u8,
    #[serde(default)]
    stage: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    completed: usize,
    #[serde(default)]
    total: usize,
    #[serde(default)]
    source: String,
    #[serde(default)]
    state: String,
}

#[derive(Clone, Default, Deserialize)]
struct DossierResult {
    query: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    include_onion: bool,
    #[serde(default)]
    sections: serde_json::Value,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default)]
    report_json: String,
    #[serde(default)]
    report_csv: String,
    #[serde(default)]
    ai_analysis: serde_json::Value,
    #[serde(default)]
    quality_report: serde_json::Value,
    #[serde(default)]
    diagnostics: serde_json::Value,
    #[serde(default)]
    source_checks: Vec<serde_json::Value>,
    #[serde(default)]
    artifacts: Vec<serde_json::Value>,
    #[serde(default)]
    ai_investigation: serde_json::Value,
    #[serde(default)]
    relationship_graph: serde_json::Value,
    #[serde(default)]
    history: serde_json::Value,
    #[serde(default)]
    exported_paths: serde_json::Value,
    #[serde(default)]
    graph_path: String,
    #[serde(default)]
    graph_json_path: String,
    #[serde(default)]
    bloodhound_graph_path: String,
}

#[derive(Clone, Default, Deserialize)]
struct AiCheckResult {
    #[serde(default)]
    status: String,
    #[serde(default)]
    error: String,
}

#[derive(Clone, Default, Deserialize)]
struct AiModelsResult {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    error: String,
}

#[derive(Clone)]
struct Backend {
    python: String,
    script: PathBuf,
    database: PathBuf,
    output: PathBuf,
}

impl Backend {
    fn new() -> Self {
        let bundled_root = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(PathBuf::from))
            .filter(|path| path.join("jobfind.py").is_file());
        let root = bundled_root.unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("rust-ui must live under the project folder")
                .to_path_buf()
        });
        let data = root.parent().unwrap_or(&root).to_path_buf();
        let local_python = root.join(".venv").join("Scripts").join("python.exe");
        Self {
            python: if local_python.is_file() {
                local_python.to_string_lossy().into_owned()
            } else {
                "python".to_owned()
            },
            script: root.join("jobfind.py"),
            database: data.join("jobfind.db"),
            output: data.join("jobfind_out"),
        }
    }

    fn run(
        &self,
        args: &[String],
        input: Option<&str>,
        progress: Option<Sender<TaskResult>>,
        ai: Option<(&str, &str, &str, &str, &str)>,
    ) -> Result<String, String> {
        let mut command = Command::new(&self.python);
        command
            .arg(&self.script)
            .arg("--db")
            .arg(&self.database)
            .arg("--out")
            .arg(&self.output)
            .args(args)
            .current_dir(
                self.script
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some((provider, model, key, account_id, gateway_url)) = ai {
            command
                .env("JOBFIND_AI_PROVIDER", provider)
                .env("JOBFIND_AI_MODEL", model)
                .env("JOBFIND_AI_API_KEY", key)
                .env("JOBFIND_AI_ACCOUNT_ID", account_id)
                .env("JOBFIND_AI_GATEWAY_URL", gateway_url);
        }
        if input.is_some() {
            command.stdin(Stdio::piped());
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("Could not start Python: {e}"))?;
        if let Some(input) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(input.as_bytes())
                    .map_err(|e| format!("Could not send settings: {e}"))?;
            }
        }
        let progress_reader = progress.and_then(|tx| {
            child.stderr.take().map(|stderr| {
                thread::spawn(move || {
                    let mut messages = String::new();
                    for line in BufReader::new(stderr).lines() {
                        let Ok(line) = line else { break };
                        if let Ok(update) = serde_json::from_str::<ProgressUpdate>(&line) {
                            let _ = tx.send(TaskResult {
                                kind: TaskKind::Dossier,
                                label: String::new(),
                                result: Ok(String::new()),
                                progress: Some(update),
                            });
                        } else {
                            messages.push_str(&line);
                            messages.push('\n');
                        }
                    }
                    messages
                })
            })
        });
        let output = child
            .wait_with_output()
            .map_err(|e| format!("Could not wait for command: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = progress_reader
            .map(|reader| reader.join().unwrap_or_default())
            .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).into_owned());
        if output.status.success() {
            if args.first().is_some_and(|arg| {
                matches!(
                    arg.as_str(),
                    "network"
                        | "library"
                        | "browser-research"
                        | "dossier"
                        | "dossier-analyze"
                        | "dossier-graph"
                        | "dossier-export"
                        | "ai-models"
                        | "search"
                        | "osint-search"
                        | "osint-history"
                        | "osint-page"
                        | "tools-catalog"
                        | "local-audit"
                        | "web-check"
                        | "domain-recon"
                        | "maigret"
                        | "github-email"
                        | "tiktok-profile"
                        | "onion-search"
                        | "2gis-search"
                )
            }) {
                return Ok(stdout.into_owned());
            }
            Ok(format!("{stdout}{stderr}"))
        } else {
            Err(format!("{stdout}{stderr}"))
        }
    }
}

const AI_PROVIDERS: &[(&str, &str)] = &[
    ("groq", "Groq"),
    ("openrouter", "OpenRouter"),
    ("cerebras", "Cerebras"),
    ("google", "Google Gemini"),
    ("cloudflare", "Cloudflare Workers AI"),
    ("nvidia", "NVIDIA NIM"),
    ("tokenharbor", "Token Harbor"),
    ("bai", "B.AI"),
    ("gemini", "Antigravity (Gemini)"),
    ("codex", "ChatGPT / Codex CLI"),
    ("claude", "Claude Code CLI"),
    ("grok", "Grok CLI"),
];

fn ai_provider_info(provider: &str) -> Option<&'static str> {
    AI_PROVIDERS
        .iter()
        .find(|(id, _)| *id == provider)
        .map(|(_, label)| *label)
}

fn ai_needs_key(provider: &str) -> bool {
    !matches!(provider, "codex" | "claude" | "grok" | "gemini")
}

#[derive(Clone, Deserialize)]
struct PersonContact {
    email: String,
    company: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    full_name: String,
    #[serde(default)]
    position: String,
    verification: String,
    #[serde(default)]
    evidence: Vec<String>,
}

#[derive(Default, Deserialize)]
struct MailStatus {
    #[serde(default)]
    mx: Vec<String>,
    #[serde(default)]
    spf: Vec<String>,
    #[serde(default)]
    dmarc: Vec<String>,
}

#[derive(Deserialize)]
struct ContactSearchResult {
    rows: Vec<PersonContact>,
    counts: [usize; 2],
    mail: MailStatus,
    #[serde(default)]
    candidates: Vec<SiteCandidate>,
    #[serde(default)]
    errors: Vec<String>,
    #[serde(default)]
    needs_domain: bool,
}

#[derive(Clone, Deserialize)]
struct SiteCandidate {
    domain: String,
    title: String,
    url: String,
    source: String,
}

#[derive(Clone, Default, Deserialize)]
struct SearchJob {
    #[serde(default)]
    title: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    remote: bool,
    #[serde(default)]
    found_emails: String,
}

#[derive(Clone, Default, Deserialize)]
struct SearchProject {
    #[serde(default)]
    name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    language: String,
    #[serde(default)]
    stars: u64,
}

#[derive(Clone, Default, Deserialize)]
struct SearchEmail {
    #[serde(default)]
    email: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    job_url: String,
}

#[derive(Clone, Default, Deserialize)]
struct SearchLink {
    #[serde(default)]
    label: String,
    #[serde(default)]
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct SearchWebResult {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    snippet: String,
    #[serde(default)]
    source: String,
}

#[derive(Clone, Default, Deserialize)]
struct UnifiedSearchResults {
    #[serde(default)]
    query: String,
    #[serde(default)]
    jobs: Vec<SearchJob>,
    #[serde(default)]
    projects: Vec<SearchProject>,
    #[serde(default)]
    contacts: Vec<SearchEmail>,
    #[serde(default)]
    company_links: Vec<SearchLink>,
    #[serde(default)]
    web_links: Vec<SearchLink>,
    #[serde(default)]
    web_results: Vec<SearchWebResult>,
    #[serde(default)]
    web_search_error: String,
    #[serde(default)]
    project_error: String,
    #[serde(default)]
    source_errors: String,
}

#[derive(Clone, Default, Deserialize)]
struct OsintRow {
    title: String,
    url: String,
    snippet: String,
    source: String,
    category: String,
    seen_at: String,
}

#[derive(Clone, Default, Deserialize)]
struct OsintResults {
    query: String,
    #[serde(default)]
    mode: String,
    results: Vec<OsintRow>,
    errors: Vec<String>,
    #[serde(default)]
    statuses: Vec<OsintStatus>,
    #[serde(default)]
    emails: Vec<OsintEmail>,
    #[serde(default)]
    pages: Vec<VerifiedPage>,
    #[serde(default)]
    integrations: BTreeMap<String, OsintIntegration>,
    links: Vec<SearchLink>,
    domain: Option<serde_json::Value>,
}

#[derive(Clone, Default, Deserialize)]
struct OsintIntegration {
    status: String,
    error: String,
    data: serde_json::Value,
}

fn integration_state(integration: &OsintIntegration) -> &str {
    if integration.data["timed_out"].as_bool() == Some(true) {
        let matches = integration.data["rows"].as_array().map_or(0, Vec::len)
            + integration.data["emails"].as_array().map_or(0, Vec::len);
        if matches == 0 {
            "timeout · no matches"
        } else {
            "partial · time limit"
        }
    } else if integration.status == "ok" && !integration.error.is_empty() {
        "partial · source error"
    } else if integration.status == "ok" {
        "completed"
    } else {
        &integration.status
    }
}

#[derive(Clone, Default, Deserialize)]
struct OsintEmail {
    email: String,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct ParsedPage {
    #[serde(default)]
    query: String,
    title: String,
    url: String,
    excerpt: String,
    emails: Vec<String>,
    observed_at: String,
    html_sha256: String,
    snapshot: String,
}

#[derive(Clone, Default, Deserialize)]
struct VerifiedPage {
    title: String,
    url: String,
    excerpt: String,
    observed_at: String,
    html_sha256: String,
    snapshot: String,
}

#[derive(Clone, Default, Deserialize)]
struct OsintStatus {
    #[serde(alias = "name")]
    source: String,
    count: usize,
    #[serde(default)]
    error: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    detail: String,
}

#[derive(Clone, Default, Deserialize)]
struct ToolCatalog {
    total: usize,
    matched: usize,
    offset: usize,
    rows: Vec<ToolEntry>,
}

#[derive(Clone, Default, Deserialize)]
struct ToolEntry {
    id: String,
    name: String,
    description: String,
    category: String,
    method: String,
    action: String,
}

#[derive(Clone, Default, Deserialize)]
struct WebCheckResult {
    domain: String,
    modules: Vec<WebCheckModule>,
    counts: WebCheckCounts,
    report: String,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct WebCheckModule {
    name: String,
    status: String,
    detail: String,
}

#[derive(Clone, Default, Deserialize)]
struct WebCheckCounts {
    ok: usize,
    skipped: usize,
    error: usize,
}

#[derive(Clone, Default, Deserialize)]
struct DomainReconResult {
    domain: String,
    dns: serde_json::Value,
    subdomains: Vec<DomainName>,
    assets: Vec<DomainAsset>,
    web_results: Vec<OsintRow>,
    technologies: Vec<DomainTechnology>,
    script_sources: Vec<String>,
    statuses: Vec<DomainStatus>,
    truncated: bool,
    report: String,
    csv: String,
}

#[derive(Clone, Default, Deserialize)]
struct DomainName {
    name: String,
    ips: Vec<String>,
    sources: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
struct DomainAsset {
    provider: String,
    ip: String,
    port: String,
    product: String,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct DomainTechnology {
    name: String,
    version: String,
    confidence: usize,
}

#[derive(Clone, Default, Deserialize)]
struct DomainStatus {
    name: String,
    state: String,
    count: usize,
    detail: String,
}

#[derive(Clone, Default, Deserialize)]
struct MaigretResult {
    username: String,
    rows: Vec<MaigretEntry>,
    warnings: Vec<String>,
    report: String,
}

#[derive(Clone, Default, Deserialize)]
struct MaigretEntry {
    site: String,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct GithubEmailResult {
    username: String,
    status: String,
    email: String,
    repository: String,
    source_url: String,
    errors: Vec<String>,
    report: String,
}

#[derive(Clone, Default, Deserialize)]
struct TikTokResult {
    username: String,
    name: String,
    bio: String,
    url: String,
    stats: serde_json::Value,
    source: String,
    report: String,
}

#[derive(Clone, Default, Deserialize)]
struct OnionResult {
    rows: Vec<OnionEntry>,
    warnings: Vec<String>,
    report: String,
    proxy: String,
}

#[derive(Clone, Default, Deserialize)]
struct OnionEntry {
    engine: String,
    title: String,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
struct TwoGisResult {
    rows: Vec<TwoGisBusiness>,
    new: usize,
    updated: usize,
    new_emails: usize,
    csv: String,
    json: String,
    xlsx: String,
    raw: String,
}

#[derive(Clone, Default, Deserialize)]
struct TwoGisBusiness {
    name: String,
    address: String,
    city: String,
    phones: Vec<String>,
    emails: Vec<String>,
    websites: Vec<String>,
    categories: Vec<String>,
    url: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct NetworkResult {
    enabled: bool,
    selected: String,
    rows: Vec<NetworkNode>,
    core: String,
    updated: String,
    coverage: String,
    separate_routes: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct NetworkNode {
    id: String,
    name: String,
    host: String,
    port: u16,
    protocol: String,
    status: String,
    latency_ms: Option<u64>,
}

// Only the result count is retained here. Raw matches/secret fields are ignored
// during deserialization, even if a future backend accidentally adds them.
#[derive(Clone, Default, Deserialize)]
struct LocalAuditFinding {}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct LocalAuditResult {
    status: String,
    scope: String,
    report: String,
    findings: Vec<LocalAuditFinding>,
    truncated: bool,
}

impl LocalAuditResult {
    fn status_label(&self) -> &'static str {
        match self.status.as_str() {
            "installed" => "Official Gitleaks tool installed",
            "findings" => "Potential exposed secrets found",
            "no_findings" => "No findings in the completed audit",
            "partial" => "Audit incomplete; review the partial report",
            "unavailable" => "Gitleaks is unavailable; install the official tool",
            _ => "Local audit or installation failed",
        }
    }
}

struct JobFindApp {
    command_palette_open: bool,
    command_palette_query: String,
    command_palette_selected: usize,
    toast: Option<(String, std::time::Instant)>,
    library: library::Workspace,
    browser: browser::Workspace,
    statistics: analytics::Workspace,
    archives: archives::Workspace,
    wireless: wireless::Workspace,
    diagram: diagram::Workspace,
    enrichment: enrichment::Workspace,
    ui_smoke: Option<UiSmoke>,
    dossier_wireless: String,
    dossier_browser: String,
    network_result: Option<NetworkResult>,
    network_group: String,
    network_country: String,
    network_subscription: String,
    network_node: String,
    network_limit: u32,
    network_checks: u32,
    backend: Backend,
    sender: Sender<TaskResult>,
    receiver: Receiver<TaskResult>,
    page: Page,
    busy: bool,
    status: String,
    log: String,
    dossier_query: String,
    dossier_kind: String,
    dossier_scope: String,
    dossier_onion: bool,
    dossier_spiderfoot: bool,
    dossier_ai: bool,
    dossier_coverage: String,
    dossier_capture: bool,
    dossier_careers: bool,
    dossier_domain_card: bool,
    dossier_archives: bool,
    dossier_vault: String,
    dossier_extra: bool,
    dossier_ai_investigate: bool,
    dossier_city: String,
    dossier_business: String,
    dossier_map_location: String,
    dossier_metadata: String,
    ai_provider: String,
    ai_model: String,
    ai_models: Vec<String>,
    ai_model_filter: String,
    ai_models_error: String,
    ai_key: String,
    ai_account_id: String,
    ai_gateway_url: String,
    ai_check: Option<AiCheckResult>,
    dossier_progress: ProgressUpdate,
    dossier_checks: Vec<ProgressUpdate>,
    dossier_results: Option<DossierResult>,
    keywords: String,
    sources: Vec<(String, bool)>,
    search_results: Option<UnifiedSearchResults>,
    osint_query: String,
    osint_email_only: bool,
    osint_domain: String,
    osint_username: String,
    osint_onion: bool,
    osint_sources: Vec<(String, bool)>,
    osint_results: Option<OsintResults>,
    parsed_page: Option<ParsedPage>,
    tool_query: String,
    local_audit_path: String,
    local_audit_history: bool,
    local_audit_result: Option<LocalAuditResult>,
    tool_domain: String,
    tool_username: String,
    onion_query: String,
    two_gis_query: String,
    two_gis_city: String,
    two_gis_limit: String,
    two_gis_results: Option<TwoGisResult>,
    catalog_results: Option<ToolCatalog>,
    webcheck_results: Option<WebCheckResult>,
    domain_results: Option<DomainReconResult>,
    maigret_results: Option<MaigretResult>,
    github_email_results: Option<GithubEmailResult>,
    tiktok_results: Option<TikTokResult>,
    onion_results: Option<OnionResult>,
    company: String,
    domain: String,
    employee_name: String,
    contacts: Vec<PersonContact>,
    contact_candidates: Vec<SiteCandidate>,
    contact_errors: Vec<String>,
    contact_searched: bool,
    selected_contact: Option<usize>,
    mail_status: Option<MailStatus>,
    new_contacts: usize,
    smtp_host: String,
    smtp_port: String,
    smtp_security: String,
    sender_email: String,
    sender_name: String,
    smtp_user: String,
    smtp_password: String,
    subject: String,
    body: String,
    ask_send: bool,
}

struct UiSmoke {
    output: PathBuf,
    frames: usize,
    requested: bool,
    started: std::time::Instant,
    form_only: bool,
    horizontal_overflow: f32,
}

impl JobFindApp {
    fn finish_ui_smoke(&mut self, ctx: &egui::Context) {
        let Some(smoke) = self.ui_smoke.as_mut() else {
            return;
        };
        if smoke.started.elapsed().as_secs() > 120 {
            let _ = std::fs::write(
                smoke.output.join("ui-smoke-error.txt"),
                "Native smoke run timed out",
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let events = ctx.input(|i| i.events.clone());
        for event in events {
            if let egui::Event::Screenshot { image, .. } = event {
                let pixels: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                let archive = self.page == Page::Archives;
                let path = smoke
                    .output
                    .join(format!("{}-native.png", self.page.slug()));
                let saved = image::save_buffer(
                    &path,
                    &pixels,
                    image.size[0] as u32,
                    image.size[1] as u32,
                    image::ColorType::Rgba8,
                );
                let result = json!({"screenshot_saved":saved.is_ok(),"error":if self.page == Page::Browser {&self.browser.error} else if self.page == Page::Library {&self.library.error} else if self.page == Page::Statistics {&self.statistics.error} else if self.page == Page::Diagram {&self.diagram.error} else if archive {&self.archives.error}else{&self.wireless.error},
                    "dossier_report":self.dossier_results.as_ref().map(|r| &r.report_json),
                    "diagram_nodes":self.diagram.graph.as_ref().map_or(0, |g|g.nodes.len()),
                    "diagram_edges":self.diagram.graph.as_ref().map_or(0, |g|g.edges.len()),
                    "result":if self.page == Page::Browser {&self.browser.result} else if self.page == Page::Library {&self.library.result} else if self.page == Page::Statistics {&self.statistics.result} else if archive {&self.archives.result}else{&self.wireless.result},"native_process_id":std::process::id(),"page":self.page.slug(),"dark_theme":ctx.theme() == egui::Theme::Dark,"horizontal_overflow":smoke.horizontal_overflow});
                let _ = std::fs::write(
                    smoke.output.join("ui-smoke-result.json"),
                    serde_json::to_vec_pretty(&result).unwrap_or_default(),
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
        }
        if !self.busy
            && (self.wireless.result.is_some()
                || !self.wireless.error.is_empty()
                || self.archives.result.is_some()
                || !self.archives.error.is_empty()
                || self.osint_results.is_some()
                || self.dossier_results.is_some()
                || self.library.result.is_some()
                || !self.library.error.is_empty()
                || self.browser.result.is_some()
                || !self.browser.error.is_empty()
                || smoke.form_only)
        {
            smoke.frames += 1;
            if smoke.frames >= 10 && smoke.started.elapsed().as_millis() >= 1500 && !smoke.requested
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
                smoke.requested = true;
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (sender, receiver) = mpsc::channel();
        let ai_provider = std::env::var("JOBFIND_AI_PROVIDER").unwrap_or_else(|_| "codex".into());
        let ai_model = std::env::var("JOBFIND_AI_MODEL").unwrap_or_default();
        theme::install(&cc.egui_ctx);
        if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("Segoe UI".into(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, "Segoe UI".into());
            cc.egui_ctx.set_fonts(fonts);
        }
        Self {
            library: library::Workspace::default(),
            browser: browser::Workspace::default(),
            network_result: None,
            network_group: "full".into(),
            network_country: String::new(),
            network_subscription: String::new(),
            network_node: String::new(),
            network_limit: 300,
            network_checks: 12,
            backend: Backend::new(),
            sender,
            receiver,
            page: Page::Dossier,
            busy: false,
            status: "Ready".to_owned(),
            log: "FindAll is ready. Enter a query and choose sources.\n".to_owned(),
            dossier_query: String::new(),
            dossier_kind: "auto".into(),
            dossier_scope: "full".into(),
            dossier_onion: true,
            dossier_spiderfoot: true,
            dossier_ai: true,
            dossier_coverage: "quick".into(),
            dossier_capture: true,
            dossier_careers: true,
            dossier_domain_card: true,
            dossier_archives: true,
            dossier_vault: String::new(),
            dossier_extra: true,
            dossier_ai_investigate: true,
            dossier_city: String::new(),
            dossier_business: String::new(),
            dossier_map_location: String::new(),
            dossier_metadata: String::new(),
            dossier_wireless: String::new(),
            dossier_browser: String::new(),
            wireless: wireless::Workspace::default(),
            command_palette_open: false,
            command_palette_query: String::new(),
            command_palette_selected: 0,
            toast: None,
            diagram: diagram::Workspace::default(),
            enrichment: enrichment::Workspace::default(),
            statistics: analytics::Workspace::default(),
            archives: archives::Workspace::default(),
            ui_smoke: None,
            ai_provider,
            ai_model,
            ai_models: Vec::new(),
            ai_model_filter: String::new(),
            ai_models_error: String::new(),
            ai_key: std::env::var("JOBFIND_AI_API_KEY").unwrap_or_default(),
            ai_account_id: std::env::var("JOBFIND_AI_ACCOUNT_ID").unwrap_or_default(),
            ai_gateway_url: std::env::var("JOBFIND_AI_GATEWAY_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8045/v1/chat/completions".into()),
            ai_check: None,
            dossier_progress: ProgressUpdate::default(),
            dossier_checks: Vec::new(),
            dossier_results: None,
            keywords: String::new(),
            sources: vec![
                ("hh".into(), true),
                ("jobicy".into(), true),
                ("remoteok".into(), true),
                ("remotive".into(), true),
                ("arbeitnow".into(), true),
                ("simplify".into(), false),
                ("hn".into(), false),
            ],
            search_results: None,
            osint_query: String::new(),
            osint_email_only: false,
            osint_domain: String::new(),
            osint_username: String::new(),
            osint_onion: true,
            osint_sources: vec![
                ("google".into(), true),
                ("yandex".into(), true),
                ("bing".into(), true),
                ("duckduckgo".into(), true),
                ("yahoo".into(), true),
                ("brave".into(), true),
                ("mojeek".into(), true),
                ("web".into(), true),
                ("wikipedia".into(), true),
                ("news".into(), true),
                ("github".into(), true),
                ("public".into(), true),
            ],
            osint_results: None,
            parsed_page: None,
            tool_query: String::new(),
            local_audit_path: String::new(),
            local_audit_history: false,
            local_audit_result: None,
            tool_domain: String::new(),
            tool_username: String::new(),
            onion_query: String::new(),
            two_gis_query: String::new(),
            two_gis_city: "moscow".into(),
            two_gis_limit: "25".into(),
            two_gis_results: None,
            catalog_results: None,
            webcheck_results: None,
            domain_results: None,
            maigret_results: None,
            github_email_results: None,
            tiktok_results: None,
            onion_results: None,
            company: String::new(),
            domain: String::new(),
            employee_name: String::new(),
            contacts: Vec::new(),
            contact_candidates: Vec::new(),
            contact_errors: Vec::new(),
            contact_searched: false,
            selected_contact: None,
            mail_status: None,
            new_contacts: 0,
            smtp_host: "smtp.gmail.com".to_owned(),
            smtp_port: "587".to_owned(),
            smtp_security: "STARTTLS".to_owned(),
            sender_email: String::new(),
            sender_name: String::new(),
            smtp_user: String::new(),
            smtp_password: String::new(),
            subject: String::new(),
            body: String::new(),
            ask_send: false,
        }
    }

    fn launch(
        &mut self,
        commands: Vec<(Vec<String>, Option<String>)>,
        kind: TaskKind,
        label: String,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.status = format!("Running: {label}…");
        let backend = self.backend.clone();
        let tx = self.sender.clone();
        let ai = (matches!(kind, TaskKind::AiCheck | TaskKind::AiModels | TaskKind::Library | TaskKind::Browser)
            || matches!(kind, TaskKind::Dossier) && self.dossier_ai)
            .then(|| {
                (
                    self.ai_provider.clone(),
                    self.ai_model.clone(),
                    self.ai_key.clone(),
                    self.ai_account_id.clone(),
                    self.ai_gateway_url.clone(),
                )
            });
        thread::spawn(move || {
            let mut output = String::new();
            let mut result = Ok(());
            for (args, input) in commands {
                let progress =
                    matches!(kind, TaskKind::Dossier | TaskKind::Enrichment).then(|| tx.clone());
                let ai_env = ai
                    .as_ref()
                    .map(|(provider, model, key, account_id, gateway_url)| {
                        (
                            provider.as_str(),
                            model.as_str(),
                            key.as_str(),
                            account_id.as_str(),
                            gateway_url.as_str(),
                        )
                    });
                match backend.run(&args, input.as_deref(), progress, ai_env) {
                    Ok(text) => {
                        output.push_str(&text);
                        if !text.ends_with('\n') {
                            output.push('\n');
                        }
                    }
                    Err(error) => {
                        output.push_str(&error);
                        result = Err(());
                        break;
                    }
                }
            }
            let result = match result {
                Ok(()) => Ok(output),
                Err(()) => Err(output),
            };
            let _ = tx.send(TaskResult {
                kind,
                label,
                result,
                progress: None,
            });
        });
    }

    fn run_network(&mut self, action: &str) {
        let mut args = self.base_args("network");
        args.push(action.into());
        if action == "refresh" {
            args.extend([
                "--group".into(),
                self.network_group.clone(),
                "--limit".into(),
                self.network_limit.to_string(),
            ]);
            if !self.network_country.trim().is_empty() {
                args.extend(["--country".into(), self.network_country.trim().into()]);
            }
            if !self.network_subscription.trim().is_empty() {
                args.extend([
                    "--subscription".into(),
                    self.network_subscription.trim().into(),
                ]);
            }
        }
        if action == "check" {
            args.extend(["--limit".into(), self.network_checks.to_string()]);
        }
        if action == "enable" && !self.network_node.is_empty() {
            args.extend(["--node".into(), self.network_node.clone()]);
        }
        self.launch(
            vec![(args, None)],
            TaskKind::Network,
            format!("Apex: {action}"),
        );
    }

    fn network_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            workspace_hero(
                ui,
                "⚡",
                "Network & Privacy Routing",
                "Refresh subscriptions, check node latency, and route research through verified proxies.",
                Some(("APEX", theme::COLOR_INFO)),
            );

            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("UPSTREAM PRIVACY & SUBSCRIPTIONS").color(ui.visuals().hyperlink_color).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::Frame::new()
                            .fill(theme::COLOR_INFO.gamma_multiply(0.15))
                            .stroke(egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.5)))
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("ROUTING").size(10.0).strong().color(theme::COLOR_INFO));
                            });
                    });
                });
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label("Profile group");
                    egui::ComboBox::from_id_salt("apex-group")
                        .selected_text(&self.network_group)
                        .show_ui(ui, |ui| {
                            for group in ["full", "wl", "bl", "ai", "torrent"] {
                                ui.selectable_value(&mut self.network_group, group.into(), group);
                            }
                        });
                    ui.add_space(8.0);
                    ui.label("Country");
                    let clear_c = if self.network_country.is_empty() { 0.0 } else { 22.0 };
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.network_country)
                                .desired_width(55.0 - clear_c)
                                .hint_text("NL"),
                        );
                        if !self.network_country.is_empty() && ui.small_button("✖").clicked() {
                            self.network_country.clear();
                        }
                    });
                    ui.add_space(8.0);
                    ui.label("Nodes limit");
                    ui.add(egui::DragValue::new(&mut self.network_limit).range(1..=2000));
                    ui.add_space(8.0);
                    ui.label("Latency checks");
                    ui.add(egui::DragValue::new(&mut self.network_checks).range(1..=100));
                });
                ui.add_space(4.0);
                ui.label("Custom HTTPS subscription");
                ui.horizontal(|ui| {
                    let clear_s = if self.network_subscription.is_empty() { 0.0 } else { 32.0 };
                    ui.add(
                        egui::TextEdit::singleline(&mut self.network_subscription)
                            .desired_width(ui.available_width() - clear_s)
                            .hint_text("Custom HTTPS subscription URL (optional)"),
                    );
                    if !self.network_subscription.is_empty() && ui.button("✖").on_hover_text("Clear subscription URL").clicked() {
                        self.network_subscription.clear();
                    }
                });
                ui.add_space(8.0);
                ui.add_enabled_ui(!self.busy, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let click_check = primary_button(ui, "⚡ Check nodes", !self.busy).clicked();
                        if click_check { self.run_network("check"); }
                        for (label, action) in [
                            ("Refresh subscriptions", "refresh"),
                            ("Reload status", "status"),
                            ("Install Xray", "install"),
                            ("Disable Apex", "disable"),
                        ] {
                            if ui.button(label).clicked() {
                                self.run_network(action);
                            }
                        }
                    });
                });
            });

            if let Some(result) = self.network_result.clone() {
                ui.add_space(10.0);

                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let (route_text, route_color, route_bg) = if result.enabled {
                            ("⚡ APEX PROXY ACTIVE", theme::COLOR_SUCCESS, theme::COLOR_SUCCESS.gamma_multiply(0.18))
                        } else {
                            ("● DIRECT ENVIRONMENT", ui.visuals().weak_text_color(), egui::Color32::from_rgb(24, 30, 42))
                        };
                        egui::Frame::new()
                            .fill(route_bg)
                            .stroke(egui::Stroke::new(1.0, route_color.gamma_multiply(0.6)))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(10, 5))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(route_text).size(12.0).strong().color(route_color));
                            });

                        ui.add_space(6.0);
                        let core_text = if result.core.is_empty() { "Xray: not installed" } else { &result.core };
                        bento_chip(ui, "⚙", "CORE", core_text, ui.visuals().hyperlink_color);

                        let ok_nodes = result.rows.iter().filter(|r| r.status == "ok").count();
                        let total_nodes = result.rows.len();
                        bento_chip(ui, "📡", "NODES", &format!("{ok_nodes} ok / {total_nodes}"), theme::COLOR_SUCCESS);

                        if !result.updated.is_empty() {
                            bento_chip(ui, "⏱", "UPDATED", &result.updated, ui.visuals().weak_text_color());
                        }
                    });

                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        let selected_label = result
                            .rows
                            .iter()
                            .find(|row| row.id == self.network_node)
                            .map(|row| format!("{} · {} · {} ms", row.protocol.to_uppercase(), row.host, row.latency_ms.unwrap_or(0)))
                            .unwrap_or_else(|| "Select checked node".into());
                        ui.label("Active Node:");
                        egui::ComboBox::from_id_salt("apex-node")
                            .width(280.0)
                            .selected_text(selected_label)
                            .show_ui(ui, |ui| {
                                for row in result.rows.iter().filter(|row| row.status == "ok") {
                                    ui.selectable_value(
                                        &mut self.network_node,
                                        row.id.clone(),
                                        format!(
                                            "{} · {}:{} · {} ms",
                                            row.protocol.to_uppercase(),
                                            row.host,
                                            row.port,
                                            row.latency_ms.unwrap_or(0)
                                        ),
                                    );
                                }
                            });
                        let can_route = !self.busy && !self.network_node.is_empty();
                        if ui.add_enabled(can_route, egui::Button::new("⚡ Route through selected")).clicked() {
                            self.run_network("enable");
                        }
                    });

                    if !result.coverage.is_empty() || !result.separate_routes.is_empty() {
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(format!("{} · {}", result.coverage, result.separate_routes)).small().color(ui.visuals().weak_text_color()));
                    }
                });

                ui.add_space(10.0);
                card(ui, |ui| {
                    let mut node_filter: String = ui.data_mut(|d| d.get_temp(egui::Id::new("apex_node_filter")).unwrap_or_default());
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("CHECKED UPSTREAM NODES").color(ui.visuals().hyperlink_color).strong());
                        ui.label(egui::RichText::new(format!("({} total)", result.rows.len())).small().color(ui.visuals().weak_text_color()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let clear_w = if node_filter.is_empty() { 0.0 } else { 26.0 };
                            if !node_filter.is_empty() && ui.small_button("✖").clicked() {
                                node_filter.clear();
                                ui.data_mut(|d| d.insert_temp(egui::Id::new("apex_node_filter"), String::new()));
                            }
                            let field = ui.add_sized([160.0 - clear_w, 28.0], egui::TextEdit::singleline(&mut node_filter).hint_text("Search nodes…"));
                            if field.changed() {
                                ui.data_mut(|d| d.insert_temp(egui::Id::new("apex_node_filter"), node_filter.clone()));
                            }
                        });
                    });
                    ui.separator();

                    let filter_lc = node_filter.trim().to_lowercase();
                    let mut enable_node_id = None;

                    egui::ScrollArea::vertical()
                        .id_salt("apex-nodes-scroll")
                        .max_height(380.0)
                        .show(ui, |ui| {
                            let mut displayed = 0;
                            for row in &result.rows {
                                if !filter_lc.is_empty() {
                                    let matches = row.name.to_lowercase().contains(&filter_lc)
                                        || row.host.to_lowercase().contains(&filter_lc)
                                        || row.protocol.to_lowercase().contains(&filter_lc);
                                    if !matches {
                                        continue;
                                    }
                                }
                                displayed += 1;
                                let is_active = row.id == self.network_node && result.enabled;

                                ui.horizontal(|ui| {
                                    let proto_upper = row.protocol.to_uppercase();
                                    egui::Frame::new()
                                        .fill(egui::Color32::from_rgb(28, 35, 50))
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 64, 88)))
                                        .corner_radius(egui::CornerRadius::same(4))
                                        .inner_margin(egui::Margin::symmetric(6, 2))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new(&proto_upper).monospace().size(10.0).strong().color(ui.visuals().hyperlink_color));
                                        });

                                    ui.label(egui::RichText::new(format!("{}:{}", row.host, row.port)).monospace().strong().color(egui::Color32::WHITE));

                                    if let Some(ms) = row.latency_ms {
                                        let (lat_color, lat_icon) = if ms < 150 {
                                            (theme::COLOR_SUCCESS, "●")
                                        } else if ms < 350 {
                                            (theme::COLOR_WARN, "●")
                                        } else {
                                            (theme::COLOR_ERROR, "⚠")
                                        };
                                        egui::Frame::new()
                                            .fill(lat_color.gamma_multiply(0.12))
                                            .stroke(egui::Stroke::new(1.0, lat_color.gamma_multiply(0.4)))
                                            .corner_radius(egui::CornerRadius::same(4))
                                            .inner_margin(egui::Margin::symmetric(5, 2))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new(format!("{lat_icon} {ms} ms")).monospace().size(10.5).strong().color(lat_color));
                                            });
                                    } else {
                                        ui.label(egui::RichText::new(&row.status).size(10.5).color(ui.visuals().weak_text_color()));
                                    }

                                    if !row.name.is_empty() {
                                        ui.label(egui::RichText::new(&row.name).size(11.5).color(ui.visuals().weak_text_color()));
                                    }

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if is_active {
                                            egui::Frame::new()
                                                .fill(theme::COLOR_SUCCESS.gamma_multiply(0.2))
                                                .stroke(egui::Stroke::new(1.0, theme::COLOR_SUCCESS))
                                                .corner_radius(egui::CornerRadius::same(4))
                                                .inner_margin(egui::Margin::symmetric(8, 2))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new("✓ ACTIVE").size(10.5).strong().color(theme::COLOR_SUCCESS));
                                                });
                                        } else if row.status == "ok" && ui.add_enabled(!self.busy, egui::Button::new("⚡ Use node")).clicked() {
                                            enable_node_id = Some(row.id.clone());
                                        }
                                    });
                                });
                                ui.separator();
                            }
                            if displayed == 0 {
                                ui.label(egui::RichText::new("No nodes matched the filter.").color(ui.visuals().weak_text_color()));
                            }
                        });

                    if let Some(id) = enable_node_id {
                        self.network_node = id;
                        self.run_network("enable");
                    }
                });
            }
        });
    }

    fn base_args(&self, command: &str) -> Vec<String> {
        vec![command.to_owned()]
    }

    fn start_archives(&mut self) {
        match self.archives.args() {
            Ok(args) => self.launch(
                vec![(args, None)],
                TaskKind::Archives,
                "Archive search".into(),
            ),
            Err(message) => self.archives.error = message,
        }
    }

    fn archives_page(&mut self, ui: &mut egui::Ui) {
        workspace_hero(
            ui,
            "🏛",
            "Archive intelligence",
            "Query historical internet archives and URL indexes to recover deleted websites and endpoints.",
            Some(("WAYBACK & OTX", theme::COLOR_INFO)),
        );
        match self.archives.ui(ui, self.busy) {
            Some(archives::Action::Collect(args)) => self.launch(
                vec![(args, None)],
                TaskKind::Archives,
                "Archive search".into(),
            ),
            Some(archives::Action::Open(path)) => open_url(&path),
            Some(archives::Action::Research) => {
                let path = self
                    .archives
                    .result
                    .as_ref()
                    .and_then(|r| r["dossier"]["report_json"].as_str());
                let loaded = path
                    .and_then(|p| std::fs::read_to_string(p).ok())
                    .and_then(|text| serde_json::from_str::<DossierResult>(&text).ok());
                if let Some(result) = loaded {
                    self.dossier_query = result.query.clone();
                    self.dossier_results = Some(result);
                    self.page = Page::Dossier;
                    self.status =
                        "Archive dossier loaded. Review historical evidence or run AI analysis."
                            .into();
                } else {
                    self.archives.error = "Saved archive dossier could not be opened.".into();
                }
            }
            None => {}
        }
    }

    fn start_wireless(&mut self) {
        match self.wireless.args() {
            Ok(args) => self.launch(
                vec![(args, None)],
                TaskKind::Wireless,
                "Wireless observations".into(),
            ),
            Err(message) => self.wireless.error = message,
        }
    }

    fn wireless_page(&mut self, ui: &mut egui::Ui) {
        match self.wireless.ui(ui, self.busy) {
            Some(wireless::Action::Collect(args)) => self.launch(
                vec![(args, None)],
                TaskKind::Wireless,
                "Wireless observations".into(),
            ),
            Some(wireless::Action::Open(path)) => open_url(&path),
            Some(wireless::Action::Research) => self.open_wireless_dossier(),
            None => (),
        }
    }

    fn open_wireless_dossier(&mut self) {
        let path = self
            .wireless
            .result
            .as_ref()
            .and_then(|r| r["dossier"]["report_json"].as_str());
        let loaded = path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|text| serde_json::from_str::<DossierResult>(&text).ok());
        if let Some(result) = loaded {
            self.dossier_query = result.query.clone();
            self.dossier_results = Some(result);
            self.page = Page::Dossier;
            self.status = "Wireless dossier loaded. Review evidence or run AI analysis.".into();
        } else {
            self.wireless.error = "Saved dossier could not be opened. Run collection again.".into();
        }
    }

    fn start_dossier(&mut self) {
        let query = self.dossier_query.trim();
        if query.len() < 2 {
            self.status = "Enter a name, username, or domain".into();
            return;
        }
        let mut args = vec![
            "dossier".into(),
            "--query".into(),
            query.into(),
            "--kind".into(),
            self.dossier_kind.clone(),
            "--scope".into(),
            self.dossier_scope.clone(),
            "--coverage".into(),
            self.dossier_coverage.clone(),
            "--progress-json".into(),
        ];
        if !self.dossier_capture {
            args.extend(["--capture-pages".into(), "-1".into()]);
        }
        if !self.dossier_careers {
            args.push("--no-careers".into());
        }
        if !self.dossier_domain_card {
            args.push("--no-domain-card".into());
        }
        if !self.dossier_archives {
            args.push("--no-archives".into());
        }
        if !self.dossier_vault.trim().is_empty() {
            args.extend(["--vault".into(), self.dossier_vault.trim().into()]);
        }
        if !self.dossier_extra {
            args.push("--no-extra-tools".into());
        }
        if !self.dossier_city.trim().is_empty() {
            args.extend(["--city".into(), self.dossier_city.trim().into()]);
            if !self.dossier_business.trim().is_empty() {
                args.extend([
                    "--business-query".into(),
                    self.dossier_business.trim().into(),
                ]);
            }
        }
        if !self.dossier_map_location.trim().is_empty() {
            args.extend([
                "--map-location".into(),
                self.dossier_map_location.trim().into(),
            ]);
        }
        for path in self
            .dossier_metadata
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            args.extend(["--metadata-file".into(), path.trim_matches('"').into()]);
        }
        for path in self
            .dossier_wireless
            .lines()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            args.extend(["--wireless-file".into(), path.trim_matches('"').into()]);
        }
        for path in self.dossier_browser.lines().map(str::trim).filter(|value| !value.is_empty()) {
            args.extend(["--browser-file".into(), path.trim_matches('"').into()]);
        }
        if self.dossier_onion && self.dossier_scope == "full" {
            args.push("--onion".into());
        }
        if !self.dossier_spiderfoot {
            args.push("--no-spiderfoot".into());
        }
        if self.dossier_ai {
            args.push("--ai".into());
        }
        if self.dossier_ai && self.dossier_ai_investigate {
            args.push("--ai-investigate".into());
        }
        self.dossier_progress = ProgressUpdate {
            percent: 0,
            stage: "starting".into(),
            detail: "Preparing sources".into(),
            ..Default::default()
        };
        self.dossier_checks.clear();
        self.dossier_results = None;
        self.launch(
            vec![(args, None)],
            TaskKind::Dossier,
            "Research dossier".into(),
        );
    }

    fn start_phone(&mut self, local_only: bool) {
        let query = self.dossier_query.trim();
        if !query.starts_with('+') || !(9..=16).contains(&query.len())
            || !query[1..].bytes().all(|ch| ch.is_ascii_digit())
        {
            self.status = "Enter an international phone number, for example +12025550123".into();
            return;
        }
        let mut args = vec!["phone".into(), "--number".into(), query.into()];
        if local_only { args.push("--local-only".into()); }
        self.dossier_results = None;
        self.dossier_checks.clear();
        self.dossier_progress = ProgressUpdate { stage: "starting".into(), detail: "PhoneInfoga scanners".into(), ..Default::default() };
        self.launch(vec![(args, None)], TaskKind::Dossier, "PhoneInfoga".into());
    }

    fn ai_connection_ready(&self) -> bool {
        ai_provider_info(&self.ai_provider).is_some()
            && (!ai_needs_key(&self.ai_provider) || !self.ai_key.trim().is_empty())
            && (self.ai_provider != "cloudflare"
                || (self.ai_account_id.trim().len() == 32
                    && self
                        .ai_account_id
                        .trim()
                        .chars()
                        .all(|ch| ch.is_ascii_hexdigit())))
            && (self.ai_provider != "gemini" || !self.ai_gateway_url.trim().is_empty())
    }

    fn ai_config_ready(&self) -> bool {
        self.ai_connection_ready() && !self.ai_model.trim().is_empty()
    }

    fn ai_config_hint(&self) -> &'static str {
        if self.ai_provider == "cloudflare"
            && (self.ai_account_id.trim().len() != 32
                || !self
                    .ai_account_id
                    .trim()
                    .chars()
                    .all(|ch| ch.is_ascii_hexdigit()))
        {
            "Enter the 32-character Cloudflare account ID."
        } else if self.ai_provider == "gemini" && self.ai_gateway_url.trim().is_empty() {
            "Enter the local Antigravity gateway URL."
        } else if ai_needs_key(&self.ai_provider) && self.ai_key.trim().is_empty() {
            "Enter the provider API key."
        } else if self.ai_model.trim().is_empty() {
            "Test the connection, then choose a model."
        } else {
            "Choose a supported provider."
        }
    }

    fn invalidate_ai_catalog(&mut self) {
        self.ai_models.clear();
        self.ai_model_filter.clear();
        self.ai_models_error.clear();
        self.ai_check = None;
    }

    fn load_ai_models(&mut self) {
        if !self.ai_connection_ready() {
            self.status = format!("AI setup: {}", self.ai_config_hint());
            return;
        }
        self.invalidate_ai_catalog();
        self.launch(
            vec![(vec!["ai-models".into()], None)],
            TaskKind::AiModels,
            "Load available models".into(),
        );
    }

    fn analyze_saved_dossier(&mut self) {
        if self.busy {
            return;
        }
        let Some(path) = self
            .dossier_results
            .as_ref()
            .map(|result| result.report_json.clone())
        else {
            return;
        };
        if path.is_empty() || !self.ai_config_ready() {
            self.status = format!("AI setup: {}", self.ai_config_hint());
            return;
        }
        self.dossier_ai = true;
        self.dossier_progress = ProgressUpdate {
            percent: 95,
            stage: "ai".into(),
            detail: "Analyzing saved dossier".into(),
            ..Default::default()
        };
        self.launch(
            vec![(vec!["dossier-analyze".into(), "--path".into(), path], None)],
            TaskKind::Dossier,
            "AI answer".into(),
        );
    }

    fn build_saved_graph(&mut self) {
        if self.busy {
            return;
        }
        let Some(path) = self
            .dossier_results
            .as_ref()
            .map(|result| result.report_json.clone())
            .filter(|path| !path.is_empty())
        else {
            return;
        };
        self.dossier_progress = ProgressUpdate {
            percent: 0,
            stage: "graph".into(),
            detail: "Mapping relationships in the saved dossier".into(),
            ..Default::default()
        };
        self.launch(
            vec![(vec!["dossier-graph".into(), "--path".into(), path], None)],
            TaskKind::Dossier,
            "Build relationship graph".into(),
        );
    }

    fn export_saved_dossier(&mut self) {
        if self.busy {
            return;
        }
        let Some(path) = self
            .dossier_results
            .as_ref()
            .map(|result| result.report_json.clone())
            .filter(|path| !path.is_empty())
        else {
            return;
        };
        let mut args = vec!["dossier-export".into(), "--path".into(), path];
        if !self.dossier_vault.trim().is_empty() {
            args.extend(["--vault".into(), self.dossier_vault.trim().into()]);
        }
        self.launch(
            vec![(args, None)],
            TaskKind::Dossier,
            "Export Markdown and compare history".into(),
        );
    }

    fn check_ai_provider(&mut self) {
        if !self.ai_config_ready() {
            self.status = format!("AI setup: {}", self.ai_config_hint());
            return;
        }
        self.ai_check = None;
        self.launch(
            vec![(vec!["ai-check".into()], None)],
            TaskKind::AiCheck,
            "Check AI provider".into(),
        );
    }

    fn start_scan(&mut self) {
        if self.keywords.trim().is_empty() {
            self.status = "Enter a profession, specialty, or skill".into();
            return;
        }
        let selected = self
            .sources
            .iter()
            .filter(|(_, active)| *active)
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if selected.is_empty() {
            self.status = "Select at least one job source".into();
            return;
        }
        let mut search = self.base_args("search");
        search.extend([
            "--sources".into(),
            selected.join(","),
            "--kw".into(),
            self.keywords.trim().to_owned(),
        ]);
        self.search_results = None;
        self.launch(
            vec![(search, None)],
            TaskKind::UnifiedSearch,
            "Search jobs, projects, and contacts".into(),
        );
    }

    fn start_osint(&mut self) {
        if self.osint_query.trim().len() < 2 {
            self.status = "Enter a topic, domain, or username".into();
            return;
        }
        let selected: Vec<_> = self
            .osint_sources
            .iter()
            .filter(|(_, active)| *active)
            .map(|(source, _)| source.clone())
            .collect();
        if selected.is_empty() && !self.osint_email_only {
            self.status = "Select at least one source".into();
            return;
        }
        let mut args = self.base_args("osint-search");
        args.extend([
            "--query".into(),
            self.osint_query.trim().into(),
            "--mode".into(),
            if self.osint_email_only {
                "email"
            } else {
                "full"
            }
            .into(),
            "--sources".into(),
            selected.join(","),
            "--domain".into(),
            if self.osint_email_only {
                ""
            } else {
                self.osint_domain.trim()
            }
            .into(),
            "--username".into(),
            if self.osint_email_only {
                ""
            } else {
                self.osint_username.trim()
            }
            .into(),
        ]);
        if self.osint_onion && !self.osint_email_only {
            args.push("--onion".into());
        }
        self.osint_results = None;
        self.parsed_page = None;
        self.launch(
            vec![(args, None)],
            TaskKind::OsintSearch,
            "OSINT search".into(),
        );
    }

    fn load_osint_history(&mut self) {
        if self.osint_query.trim().is_empty() {
            self.status = "Enter a query from a previous search".into();
            return;
        }
        let mut args = self.base_args("osint-history");
        args.extend(["--query".into(), self.osint_query.trim().into()]);
        self.parsed_page = None;
        self.launch(
            vec![(args, None)],
            TaskKind::OsintSearch,
            "Saved results".into(),
        );
    }

    fn parse_osint_page(&mut self, url: String, query: String) {
        let mut args = self.base_args("osint-page");
        args.extend(["--query".into(), query, "--url".into(), url]);
        self.parsed_page = None;
        self.launch(vec![(args, None)], TaskKind::PageParse, "Parse page".into());
    }

    fn search_tool_catalog(&mut self, offset: usize) {
        let mut args = self.base_args("tools-catalog");
        args.extend([
            "--query".into(),
            self.tool_query.trim().into(),
            "--limit".into(),
            "100".into(),
            "--offset".into(),
            offset.to_string(),
        ]);
        self.launch(
            vec![(args, None)],
            TaskKind::ToolsCatalog,
            "Tool catalog".into(),
        );
    }

    fn run_local_audit(&mut self, install: bool) {
        let mut args = self.base_args("local-audit");
        if install {
            args.push("--install".into());
        } else {
            let path = self.local_audit_path.trim();
            if path.is_empty() || !std::path::Path::new(path).is_dir() {
                self.status = "Enter an existing local source directory".into();
                return;
            }
            args.extend([
                "--path".into(),
                path.into(),
                "--timeout".into(),
                "120".into(),
            ]);
            if self.local_audit_history {
                args.push("--history".into());
            }
        }
        self.local_audit_result = None;
        self.launch(
            vec![(args, None)],
            TaskKind::LocalAudit,
            if install {
                "Install official Gitleaks".into()
            } else {
                "Audit selected local directory".into()
            },
        );
    }

    fn run_web_check(&mut self) {
        if self.tool_domain.trim().is_empty() {
            self.status = "Enter a public domain".into();
            return;
        }
        let mut args = self.base_args("web-check");
        args.extend(["--domain".into(), self.tool_domain.trim().into()]);
        self.launch(
            vec![(args, None)],
            TaskKind::WebCheck,
            "Web-Check domain scan".into(),
        );
    }

    fn run_domain_recon(&mut self) {
        if self.tool_domain.trim().is_empty() {
            self.status = "Enter a public domain".into();
            return;
        }
        let mut args = self.base_args("domain-recon");
        args.extend(["--domain".into(), self.tool_domain.trim().into()]);
        self.domain_results = None;
        self.launch(
            vec![(args, None)],
            TaskKind::DomainRecon,
            "Domain OSINT".into(),
        );
    }

    fn run_maigret(&mut self) {
        if self.tool_username.trim().is_empty() {
            self.status = "Enter a username".into();
            return;
        }
        let mut args = self.base_args("maigret");
        args.extend(["--username".into(), self.tool_username.trim().into()]);
        self.launch(
            vec![(args, None)],
            TaskKind::Maigret,
            "Maigret profile search".into(),
        );
    }

    fn run_github_email(&mut self) {
        if self.tool_username.trim().is_empty() {
            self.status = "Enter a GitHub username".into();
            return;
        }
        let mut args = self.base_args("github-email");
        args.extend(["--username".into(), self.tool_username.trim().into()]);
        self.github_email_results = None;
        self.launch(
            vec![(args, None)],
            TaskKind::GithubEmail,
            "GitHub public email search".into(),
        );
    }

    fn run_tiktok_profile(&mut self) {
        if self.tool_username.trim().is_empty() {
            self.status = "Enter a TikTok username".into();
            return;
        }
        let mut args = self.base_args("tiktok-profile");
        args.extend(["--username".into(), self.tool_username.trim().into()]);
        self.tiktok_results = None;
        self.launch(
            vec![(args, None)],
            TaskKind::TikTokProfile,
            "TikTok profile".into(),
        );
    }

    fn run_onion_search(&mut self) {
        if self.onion_query.trim().len() < 2 {
            self.status = "Enter a query for onion search".into();
            return;
        }
        let mut args = self.base_args("onion-search");
        args.extend(["--query".into(), self.onion_query.trim().into()]);
        self.launch(
            vec![(args, None)],
            TaskKind::OnionSearch,
            "Tor search".into(),
        );
    }

    fn run_two_gis(&mut self) {
        if self.two_gis_query.trim().len() < 2 {
            self.status = "Enter a business name or category".into();
            return;
        }
        let mut args = self.base_args("2gis-search");
        args.extend([
            "--query".into(),
            self.two_gis_query.trim().into(),
            "--city".into(),
            self.two_gis_city.trim().into(),
            "--limit".into(),
            self.two_gis_limit.trim().into(),
        ]);
        self.two_gis_results = None;
        self.launch(
            vec![(args, None)],
            TaskKind::TwoGis,
            "2GIS business search".into(),
        );
    }

    fn search_contacts(&mut self) {
        if self.company.trim().is_empty() {
            self.status = "Enter a company or domain".into();
            return;
        }
        let mut args = self.base_args("contact-search");
        args.extend([
            "--company".into(),
            self.company.trim().to_owned(),
            "--domain".into(),
            self.domain.trim().to_owned(),
            "--name".into(),
            self.employee_name.trim().to_owned(),
        ]);
        self.contacts.clear();
        self.contact_candidates.clear();
        self.contact_errors.clear();
        self.contact_searched = false;
        self.mail_status = None;
        self.selected_contact = None;
        self.launch(
            vec![(args, None)],
            TaskKind::ContactSearch,
            "Public email search".into(),
        );
    }

    fn select_contact(&mut self, index: usize) {
        if self.selected_contact == Some(index) {
            return;
        }
        self.selected_contact = Some(index);
        if let Some(contact) = self.contacts.get(index) {
            let first = contact
                .full_name
                .split_whitespace()
                .next()
                .unwrap_or("there");
            let position = if contact.position.is_empty() {
                "your team"
            } else {
                &contact.position
            };
            self.subject = format!("Question about {position} at {}", contact.company);
            self.body = format!(
                "Hello {first},\n\nI found your publicly listed contact at {} and wanted to ask about opportunities related to {position}. I have relevant experience and would be happy to share my resume if you are the right person to contact.\n\nBest regards,\n",
                contact.company
            );
        }
    }

    fn begin_send(&mut self) {
        let Some(contact) = self.selected_contact.and_then(|i| self.contacts.get(i)) else {
            self.status = "Select a contact first".into();
            return;
        };
        if contact.verification != "published" || contact.evidence.is_empty() {
            self.status =
                "Guessed addresses cannot receive mail here. Select an address with a source page."
                    .into();
            return;
        }
        if self.smtp_password.is_empty() {
            self.status = "Enter your SMTP app password".into();
            return;
        }
        self.ask_send = true;
    }

    fn send_confirmed(&mut self) {
        let Some(contact) = self
            .selected_contact
            .and_then(|i| self.contacts.get(i))
            .cloned()
        else {
            return;
        };
        let port = match self.smtp_port.trim().parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                self.status = "Check the SMTP port".into();
                return;
            }
        };
        let payload = json!({
            "recipient": contact.email,
            "company": contact.company,
            "subject": self.subject,
            "body": self.body,
            "sender": self.sender_email,
            "sender_name": self.sender_name,
            "smtp_user": self.smtp_user,
            "password": self.smtp_password,
            "host": self.smtp_host,
            "port": port,
            "security": self.smtp_security,
        });
        let mut args = self.base_args("email-send");
        self.ask_send = false;
        self.launch(
            vec![(std::mem::take(&mut args), Some(payload.to_string()))],
            TaskKind::EmailSend,
            "Send one email".into(),
        );
    }

    fn receive_results(&mut self) {
        while let Ok(event) = self.receiver.try_recv() {
            if let Some(progress) = event.progress {
                if !progress.source.is_empty() && !progress.state.is_empty() {
                    self.dossier_checks
                        .retain(|check| check.source != progress.source);
                    self.dossier_checks.push(progress.clone());
                }
                self.dossier_progress = progress;
                self.status = format!(
                    "{} · {}%",
                    self.dossier_progress.stage, self.dossier_progress.percent
                );
                continue;
            }
            self.busy = false;
            match event.result {
                Ok(output) => {
                    self.status = format!("Done: {}", event.label);
                    match event.kind {
                        TaskKind::Browser => {
                            match serde_json::from_str::<serde_json::Value>(&output) {
                                Ok(result) if result["sections"].is_object() => {
                                    self.browser.error.clear();
                                    self.browser.result = Some(result);
                                }
                                _ => self.browser.error = "Could not read browser research output. Check the retained results folder.".into(),
                            }
                        }
                        TaskKind::Library => {
                            match serde_json::from_str::<serde_json::Value>(&output) {
                                Ok(result) => {
                                    self.library.error.clear();
                                    self.status = format!("Library: {}", result["status"].as_str().unwrap_or("ready"));
                                    self.library.result = Some(result);
                                }
                                Err(_) => self.library.error = "Could not read library output".into(),
                            }
                        }
                        TaskKind::Statistics => {
                            match serde_json::from_str::<serde_json::Value>(&output) {
                                Ok(result) if result["model_setup"]["status"] == "ok" => {
                                    self.statistics.model_status = "Pinned BERT model installed and verified. Analysis now runs offline.".into();
                                    self.statistics.error.clear();
                                }
                                Ok(result) if result["analytics"].is_object() => {
                                    self.status = format!("Statistics: {} observations", result["analytics"]["coverage"]["retained"]);
                                    self.statistics.error.clear();
                                    self.statistics.result = Some(result);
                                }
                                _ => self.statistics.error = "Could not read statistical analysis output".into(),
                            }
                        }
                        TaskKind::Enrichment => {
                            match serde_json::from_str::<serde_json::Value>(&output) {
                                Ok(result) if result["flow"].is_object() => {
                                    self.status = format!(
                                        "Enrichment: {} · {} relationships",
                                        result["flow"]["status"].as_str().unwrap_or("unknown"),
                                        result["counts"]["enrichments"]
                                    );
                                    self.enrichment.error.clear();
                                    if let Some(path) = result["graph_path"].as_str() {
                                        self.diagram.requested_query =
                                            result["query"].as_str().unwrap_or("").into();
                                        self.diagram.load(std::path::Path::new(path));
                                    }
                                    self.enrichment.result = Some(result);
                                }
                                _ => {
                                    self.enrichment.error =
                                        "Could not read enrichment output".into()
                                }
                            }
                        }
                        TaskKind::WorkspaceGraph => {
                            match serde_json::from_str::<serde_json::Value>(&output) {
                                Ok(result) => {
                                    if let Some(path) = result["export_folder"].as_str() {
                                        open_output(&PathBuf::from(path));
                                    } else if let Some(path) = result["graph_path"].as_str() {
                                        self.diagram.load(std::path::Path::new(path));
                                        self.page = Page::Diagram;
                                    }
                                    self.status = format!(
                                        "Workspace graph · {} nodes · {} relationships",
                                        result["graph_nodes"], result["graph_edges"]
                                    );
                                    if result["export_folder"].is_null()
                                        && !self.diagram.error.is_empty()
                                    {
                                        self.status = self.diagram.error.clone();
                                    }
                                }
                                Err(error) => {
                                    self.diagram.error =
                                        format!("Could not read workspace graph: {error}");
                                    self.status = self.diagram.error.clone();
                                }
                            }
                        }
                        TaskKind::Network => match serde_json::from_str::<NetworkResult>(&output) {
                            Ok(result) => {
                                self.network_node = result.selected.clone();
                                self.network_result = Some(result);
                            }
                            Err(error) => self.log.push_str(&format!("Apex: {error}\n{output}\n")),
                        },
                        TaskKind::Wireless => {
                            self.wireless.accept(&output);
                            self.status = if self.wireless.error.is_empty() {
                                format!(
                                    "Wireless: {}",
                                    self.wireless
                                        .result
                                        .as_ref()
                                        .and_then(|r| r["status"].as_str())
                                        .unwrap_or("unknown")
                                )
                            } else {
                                self.wireless.error.clone()
                            };
                        }
                        TaskKind::Archives => {
                            self.archives.accept(&output);
                            self.status = if self.archives.error.is_empty() {
                                format!(
                                    "Archives: {}",
                                    self.archives
                                        .result
                                        .as_ref()
                                        .and_then(|r| r["status"].as_str())
                                        .unwrap_or("unknown")
                                )
                            } else {
                                self.archives.error.clone()
                            };
                        }
                        TaskKind::AiModels => {
                            match serde_json::from_str::<AiModelsResult>(&output) {
                                Ok(result) => {
                                    if result.provider != self.ai_provider {
                                        continue;
                                    }
                                    self.ai_models = result.models;
                                    self.ai_models_error = result.error;
                                    if !self.ai_models.is_empty()
                                        && !self.ai_models.contains(&self.ai_model)
                                    {
                                        self.ai_model.clear();
                                    }
                                    self.status =
                                        if result.status == "ok" || result.status == "partial" {
                                            format!("{} models listed", self.ai_models.len())
                                        } else {
                                            "Model list unavailable".into()
                                        };
                                }
                                Err(_) => self.status = "Could not read model list response".into(),
                            }
                        }
                        TaskKind::AiCheck => match serde_json::from_str::<AiCheckResult>(&output) {
                            Ok(result) => {
                                self.status = if result.status == "ok" {
                                    "AI provider connected".into()
                                } else {
                                    "AI provider check failed".into()
                                };
                                self.ai_check = Some(result);
                            }
                            Err(_) => self.status = "Could not read provider check response".into(),
                        },
                        TaskKind::Dossier => match serde_json::from_str::<DossierResult>(&output) {
                            Ok(result) => {
                                self.dossier_progress.percent = 100;
                                self.status = format!("Dossier ready: {}", result.query);
                                let count = |section: &str| {
                                    result.sections[section].as_array().map_or(0, Vec::len)
                                };
                                self.log.push_str(&format!("Dossier '{}': kept {} web pages from several result pages of each source, {} profiles, {} published emails, {} source warnings. Not a count of the whole web.\n",
                                        result.query, count("web"), count("profiles"), count("emails"), result.errors.len()));
                                self.dossier_results = Some(result);
                            }
                            Err(error) => {
                                self.status = "Could not read dossier".into();
                                self.log
                                    .push_str(&format!("Dossier response: {error}\n{output}\n"));
                            }
                        },
                        TaskKind::UnifiedSearch => {
                            match serde_json::from_str::<UnifiedSearchResults>(&output) {
                                Ok(result) => {
                                    self.status = "Results ready".into();
                                    self.log.push_str(&format!(
                                        "Query '{}': {} jobs, {} projects, {} web pages, {} published emails.\n",
                                        result.query, result.jobs.len(), result.projects.len(), result.web_results.len(), result.contacts.len()
                                    ));
                                    if !result.web_search_error.is_empty() {
                                        self.log
                                            .push_str(&format!("{}\n", result.web_search_error));
                                    }
                                    if !result.project_error.is_empty() {
                                        self.log.push_str(&format!(
                                            "GitHub: {}\n",
                                            result.project_error
                                        ));
                                    }
                                    self.search_results = Some(result);
                                }
                                Err(error) => self.log.push_str(&format!(
                                    "Could not read search results: {error}\n{output}\n"
                                )),
                            }
                        }
                        TaskKind::OsintSearch => {
                            match serde_json::from_str::<OsintResults>(&output) {
                                Ok(result) => {
                                    self.status = "Results ready".into();
                                    self.log.push_str(&format!(
                                        "OSINT '{}': {} results, {} source errors.\n",
                                        result.query,
                                        result.results.len(),
                                        result.errors.len()
                                    ));
                                    self.osint_results = Some(result);
                                }
                                Err(error) => {
                                    self.status =
                                        "Search response could not be displayed; see Activity log"
                                            .into();
                                    self.log.push_str(&format!(
                                        "Could not read OSINT results: {error}\n"
                                    ));
                                }
                            }
                        }
                        TaskKind::PageParse => match serde_json::from_str::<ParsedPage>(&output) {
                            Ok(result) => {
                                self.status = "Page parsed".into();
                                self.log.push_str(&format!(
                                    "Page {}: {} published emails.\n",
                                    result.url,
                                    result.emails.len()
                                ));
                                if let Some(search) = self
                                    .osint_results
                                    .as_mut()
                                    .filter(|search| search.query == result.query)
                                {
                                    for email in &result.emails {
                                        if !search.emails.iter().any(|entry| {
                                            entry.email == *email && entry.url == result.url
                                        }) {
                                            search.emails.push(OsintEmail {
                                                email: email.clone(),
                                                url: result.url.clone(),
                                            });
                                        }
                                    }
                                    let page = VerifiedPage {
                                        title: result.title.clone(),
                                        url: result.url.clone(),
                                        excerpt: result.excerpt.clone(),
                                        observed_at: result.observed_at.clone(),
                                        html_sha256: result.html_sha256.clone(),
                                        snapshot: result.snapshot.clone(),
                                    };
                                    if let Some(saved) =
                                        search.pages.iter_mut().find(|page| page.url == result.url)
                                    {
                                        *saved = page;
                                    } else {
                                        search.pages.push(page);
                                    }
                                }
                                self.parsed_page = Some(result);
                            }
                            Err(error) => self.log.push_str(&format!(
                                "Could not read parser output: {error}\n{output}\n"
                            )),
                        },
                        TaskKind::ToolsCatalog => {
                            match serde_json::from_str::<ToolCatalog>(&output) {
                                Ok(result) => {
                                    self.status = format!("Tools found: {}", result.matched);
                                    self.catalog_results = Some(result);
                                }
                                Err(error) => {
                                    self.log.push_str(&format!("Catalog: {error}\n{output}\n"))
                                }
                            }
                        }
                        TaskKind::LocalAudit => {
                            match serde_json::from_str::<LocalAuditResult>(&output) {
                                Ok(result) => {
                                    self.status = result.status_label().into();
                                    self.log.push_str(&format!(
                                        "Local source audit: {} · {} candidate finding(s).\n",
                                        result.status_label(),
                                        result.findings.len()
                                    ));
                                    self.local_audit_result = Some(result);
                                }
                                Err(_) => {
                                    self.status = "Could not read the local audit response".into()
                                }
                            }
                        }
                        TaskKind::WebCheck => {
                            match serde_json::from_str::<WebCheckResult>(&output) {
                                Ok(result) => {
                                    self.status =
                                        format!("Web-Check: {} modules", result.modules.len());
                                    self.webcheck_results = Some(result);
                                }
                                Err(error) => self
                                    .log
                                    .push_str(&format!("Web-Check: {error}\n{output}\n")),
                            }
                        }
                        TaskKind::DomainRecon => {
                            match serde_json::from_str::<DomainReconResult>(&output) {
                                Ok(result) => {
                                    self.status = format!(
                                        "Domain: {} names, {} assets",
                                        result.subdomains.len(),
                                        result.assets.len()
                                    );
                                    self.domain_results = Some(result);
                                }
                                Err(error) => self
                                    .log
                                    .push_str(&format!("Domain OSINT: {error}\n{output}\n")),
                            }
                        }
                        TaskKind::Maigret => match serde_json::from_str::<MaigretResult>(&output) {
                            Ok(result) => {
                                self.status = format!("Maigret: {} profiles", result.rows.len());
                                self.maigret_results = Some(result);
                            }
                            Err(error) => {
                                self.log.push_str(&format!("Maigret: {error}\n{output}\n"))
                            }
                        },
                        TaskKind::GithubEmail => {
                            match serde_json::from_str::<GithubEmailResult>(&output) {
                                Ok(result) => {
                                    self.status = if result.status == "found" {
                                        "GitHub: public email found".into()
                                    } else {
                                        format!("GitHub: {}", result.status)
                                    };
                                    self.github_email_results = Some(result);
                                }
                                Err(error) => self
                                    .log
                                    .push_str(&format!("GitHub Email Hunter: {error}\n{output}\n")),
                            }
                        }
                        TaskKind::TikTokProfile => {
                            match serde_json::from_str::<TikTokResult>(&output) {
                                Ok(result) => {
                                    self.status = format!("TikTok: {}", result.username);
                                    self.tiktok_results = Some(result);
                                }
                                Err(error) => self
                                    .log
                                    .push_str(&format!("TikTok Scraper: {error}\n{output}\n")),
                            }
                        }
                        TaskKind::OnionSearch => {
                            match serde_json::from_str::<OnionResult>(&output) {
                                Ok(result) => {
                                    self.status =
                                        format!("OnionSearch: {} links", result.rows.len());
                                    self.onion_results = Some(result);
                                }
                                Err(error) => self
                                    .log
                                    .push_str(&format!("OnionSearch: {error}\n{output}\n")),
                            }
                        }
                        TaskKind::TwoGis => match serde_json::from_str::<TwoGisResult>(&output) {
                            Ok(result) => {
                                self.status = format!("2GIS: {} businesses", result.rows.len());
                                self.log.push_str(&format!(
                                    "2GIS: {} new, {} updated, {} new emails.\n",
                                    result.new, result.updated, result.new_emails
                                ));
                                self.two_gis_results = Some(result);
                            }
                            Err(error) => self.log.push_str(&format!("2GIS: {error}\n{output}\n")),
                        },
                        TaskKind::ContactSearch => {
                            match serde_json::from_str::<ContactSearchResult>(&output) {
                                Ok(result) => {
                                    self.contacts = result.rows;
                                    self.contact_candidates = result.candidates;
                                    self.contact_errors = result.errors;
                                    self.contact_searched = true;
                                    self.new_contacts = result.counts[0];
                                    self.mail_status = if result.needs_domain {
                                        None
                                    } else {
                                        Some(result.mail)
                                    };
                                    self.status = if result.needs_domain {
                                        format!(
                                            "Company sites found: {} · choose one",
                                            self.contact_candidates.len()
                                        )
                                    } else {
                                        format!(
                                            "Published addresses found: {}",
                                            self.contacts
                                                .iter()
                                                .filter(|row| row.verification == "published")
                                                .count()
                                        )
                                    };
                                    self.log.push_str(&format!(
                                        "Addresses found: {}; new: {}\n",
                                        self.contacts.len(),
                                        self.new_contacts
                                    ));
                                }
                                Err(error) => self.log.push_str(&format!(
                                    "Could not read contact search results: {error}\n{output}\n"
                                )),
                            }
                        }
                        TaskKind::EmailSend => {
                            self.log.push_str(&output);
                            self.smtp_password.clear();
                        }
                    }
                }
                Err(error) => {
                    if matches!(event.kind, TaskKind::Archives) {
                        self.archives.accept(&error);
                        self.status = self.archives.error.clone();
                        continue;
                    }
                    if matches!(event.kind, TaskKind::Wireless) {
                        self.wireless.accept(&error);
                        self.status = self.wireless.error.clone();
                        if self.wireless.error.is_empty() {
                            self.wireless.error="Wireless collection could not finish. Check dependencies and selected inputs.".into();
                        }
                        continue;
                    }
                    if matches!(event.kind, TaskKind::LocalAudit) {
                        self.local_audit_result =
                            serde_json::from_str::<LocalAuditResult>(&error).ok();
                        self.status = self
                            .local_audit_result
                            .as_ref()
                            .map_or(
                                "Local audit could not finish",
                                LocalAuditResult::status_label,
                            )
                            .into();
                        self.log.push_str("Local source audit did not finish. Review the audit card; no raw tool output was logged.\n");
                        continue;
                    }
                    if matches!(event.kind, TaskKind::AiCheck) {
                        self.ai_check = serde_json::from_str::<AiCheckResult>(&error).ok();
                        self.status = "AI provider check failed".into();
                        continue;
                    }
                    if matches!(event.kind, TaskKind::AiModels) {
                        self.ai_models_error = error.trim().to_owned();
                        self.status = "Model list unavailable".into();
                        continue;
                    }
                    self.status = format!("Error: {}", event.label);
                    if matches!(event.kind, TaskKind::Library) { self.library.error = error.trim().to_owned(); }
                    if matches!(event.kind, TaskKind::Browser) { self.browser.error = error.trim().to_owned(); }
                    if matches!(event.kind, TaskKind::Statistics) {
                        self.statistics.error = error.trim().to_owned();
                    }
                    if matches!(event.kind, TaskKind::Enrichment) {
                        self.enrichment.error = error.trim().to_owned();
                        self.diagram.error = self.enrichment.error.clone();
                    }
                    if matches!(event.kind, TaskKind::WorkspaceGraph) {
                        self.diagram.error = error.trim().to_owned();
                    }
                    if matches!(event.kind, TaskKind::ContactSearch) {
                        self.contact_errors = vec![error.trim().to_owned()];
                        self.contact_searched = true;
                    }
                    self.log.push_str(&error);
                    if !error.ends_with('\n') {
                        self.log.push('\n');
                    }
                }
            }
        }
    }

    fn dossier_page(&mut self, ui: &mut egui::Ui) {
        workspace_hero(
            ui,
            "👤",
            "Evidence Dossier",
            "Autonomous multi-source research across public search engines, archives, and registries.",
            Some(("OSINT CORE", theme::COLOR_INFO)),
        );
        card(ui, |ui| {
            ui.label(egui::RichText::new("Name, username, or website").strong());
            let field = ui.horizontal(|ui| {
                let clear_needed = !self.dossier_query.is_empty();
                let width = if clear_needed {
                    (ui.available_width() - 44.0).max(100.0)
                } else {
                    ui.available_width()
                };
                let f = ui.add_sized(
                    [width, 48.0],
                    egui::TextEdit::singleline(&mut self.dossier_query)
                        .hint_text("Name, @username, domain, email, phone or IP address")
                        .margin(egui::vec2(12.0, 12.0)),
                );
                if clear_needed {
                    if ui
                        .add_sized(
                            [36.0, 48.0],
                            egui::Button::new(
                                egui::RichText::new("✖")
                                    .size(13.0)
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .fill(egui::Color32::from_rgb(20, 26, 38))
                            .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(6)),
                        )
                        .on_hover_text("Clear query")
                        .clicked()
                    {
                        self.dossier_query.clear();
                    }
                }
                f
            }).inner;
            ui.add_space(8.0);
            let enter = enter_submitted(ui, &field);
            let click = primary_button(
                ui,
                "Create dossier",
                !self.busy && !self.dossier_query.trim().is_empty(),
            )
            .on_disabled_hover_text(if self.busy {
                "Research is running."
            } else {
                "Enter a research target first."
            })
            .clicked();
            if !self.busy && !self.dossier_query.trim().is_empty() && (enter || click) {
                self.start_dossier();
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Searches public sources. Matches are leads, not proof of identity.",
                )
                .color(ui.visuals().weak_text_color())
                .small(),
            );
            if self.dossier_kind == "auto"
                && !self.dossier_query.starts_with('@')
                && self
                    .dossier_query
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "_-".contains(ch))
                && self.dossier_query.len() >= 2
            {
                ui.label(
                    egui::RichText::new(
                        "Searching a handle? Add @ or choose Username in Search settings.",
                    )
                    .color(ui.visuals().weak_text_color())
                    .small(),
                );
            }
            ui.label(
                egui::RichText::new(if self.dossier_ai {
                    "The final AI answer uses the query language and cites collected sources."
                } else {
                    "AI answer is off. Enable it in Search settings to analyze collected sources."
                })
                .color(ui.visuals().weak_text_color())
                .small(),
            );
            ui.add_space(8.0);
            egui::CollapsingHeader::new("Search settings")
                .default_open(false)
                .open(self.ui_smoke.as_ref().map(|_| std::env::args().any(|a| a == "--smoke-expanded")))
                .show(ui, |ui| {
                    ui.set_max_width(ui.available_width().min(720.0));
                    let half_width = ((ui.available_width() - 12.0) / 2.0).clamp(170.0, 300.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Input type").strong());
                            egui::ComboBox::from_id_salt("dossier-kind")
                                .width(half_width)
                                .selected_text(match self.dossier_kind.as_str() {
                                    "person" => "Person", "username" => "Username", "domain" => "Domain",
                                    "email" => "Email", "ip" => "IP address", "phone" => "Phone",
                                    _ => "Detect automatically",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.dossier_kind, "auto".into(), "Detect automatically");
                                    ui.selectable_value(&mut self.dossier_kind, "person".into(), "Person");
                                    ui.selectable_value(&mut self.dossier_kind, "username".into(), "Username");
                                    ui.selectable_value(&mut self.dossier_kind, "domain".into(), "Domain");
                                    ui.selectable_value(&mut self.dossier_kind, "email".into(), "Email");
                                    ui.selectable_value(&mut self.dossier_kind, "ip".into(), "IP address");
                                    ui.selectable_value(&mut self.dossier_kind, "phone".into(), "Phone");
                                });
                            });
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Research focus").strong());
                            egui::ComboBox::from_id_salt("dossier-scope")
                                .width(half_width)
                                .selected_text(match self.dossier_scope.as_str() {
                                    "email" => "Published email", "domain" => "Domain and equipment", "profiles" => "Public profiles", _ => "Full research",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.dossier_scope, "full".into(), "Full research");
                                    ui.selectable_value(&mut self.dossier_scope, "email".into(), "Published email");
                                    ui.selectable_value(&mut self.dossier_scope, "domain".into(), "Domain and equipment");
                                    ui.selectable_value(&mut self.dossier_scope, "profiles".into(), "Public profiles");
                                });
                            });
                    });
                    ui.add_space(18.0);
                    ui.label(egui::RichText::new("Collection depth").strong());
                    ui.horizontal_wrapped(|ui| {
                        ui.selectable_value(&mut self.dossier_coverage, "quick".into(), "Quick");
                        ui.selectable_value(&mut self.dossier_coverage, "deep".into(), "Deep");
                    });
                    ui.label(egui::RichText::new("Quick uses shorter time limits and fewer sites. Deep checks more sites and keeps up to 40 source pages; blocked sources remain visible.").color(ui.visuals().weak_text_color()).small());
                    ui.checkbox(&mut self.dossier_capture, "Read and archive source pages and public Telegram posts");
                    ui.checkbox(&mut self.dossier_careers, "Discover company career pages, ATS vacancies and published contacts");
                    ui.checkbox(&mut self.dossier_domain_card, "Build structured DNS/registration card and indexed DNS history");
                    ui.checkbox(&mut self.dossier_archives, "Search historical URLs with Wayback, Common Crawl and waymore");
                    if ui.button("Archive dates, filters and selected snapshots…").clicked() {
                        self.archives.domain=self.dossier_query.clone();self.page=Page::Archives;
                    }
                    ui.label(egui::RichText::new("These collectors apply to domain targets. They preserve association sources, partial results and missing-key states.").small().color(ui.visuals().weak_text_color()));
                    ui.label("Obsidian vault · optional local folder");
                    ui.add(egui::TextEdit::singleline(&mut self.dossier_vault).hint_text("Creates a versioned export; existing notes stay intact").desired_width(f32::INFINITY));
                    ui.checkbox(&mut self.dossier_extra, "Run installed engines for this target");
                    ui.label(egui::RichText::new("Domain: theHarvester and Web-Check. Username: profile tools and Instaloader. Email: GHunt after login. Phone: PhoneInfoga. IP: indexed service lookups.").color(ui.visuals().weak_text_color()).small());
                    egui::CollapsingHeader::new("PhoneInfoga · phone research").default_open(self.dossier_kind == "phone").show(ui, |ui| {
                        if self.ui_smoke.is_some() && std::env::args().any(|a| a == "--smoke-phone") { ui.scroll_to_cursor(Some(egui::Align::TOP)); }
                        ui.label("Enter an international number in the research field, for example +12025550123.");
                        ui.label("Number plan, search queries, Google CSE, Numverify and supported OVH ranges. Results go to the evidence dossier.");
                        ui.horizontal_wrapped(|ui| {
                            if ui.add_enabled(!self.busy, egui::Button::new("Run PhoneInfoga")).clicked() { self.start_phone(false); }
                            if ui.add_enabled(!self.busy, egui::Button::new("Local analysis only")).clicked() { self.start_phone(true); }
                        });
                        ui.label(egui::RichText::new("Local analysis makes no external requests. Generated queries are not search results. Number-plan metadata does not establish subscriber identity or current location.").small().color(ui.visuals().weak_text_color()));
                        ui.label("Optional APIs: NUMVERIFY_API_KEY, GOOGLE_API_KEY and GOOGLECSE_CX in osint-keys.env.");
                    });
                    if ui.small_button("Set up Google login for GHunt").clicked() {
                        open_url(&self.backend.script.with_file_name("ghunt-login.bat").to_string_lossy());
                    }
                    ui.add_space(12.0);
                    egui::CollapsingHeader::new("Business directories and maps").show(ui, |ui| {
                        ui.label("2GIS city slug, for example moscow");
                        ui.add(egui::TextEdit::singleline(&mut self.dossier_city).hint_text("Optional").desired_width(f32::INFINITY));
                        ui.label("Business name or category");
                        ui.add(egui::TextEdit::singleline(&mut self.dossier_business).hint_text("Uses the research query when empty").desired_width(f32::INFINITY));
                        ui.label("OpenStreetMap administrative area name");
                        ui.add(egui::TextEdit::singleline(&mut self.dossier_map_location).hint_text("For example Berlin").desired_width(f32::INFINITY));
                        ui.label(egui::RichText::new("Matches public business/map objects by name. Set a location to include these collectors in the dossier.").small().color(ui.visuals().weak_text_color()));
                    });
                    egui::CollapsingHeader::new("Selected local files").show(ui, |ui| {
                        if ui.button("Add Chrome crawler page exports…").clicked() {
                            if let Some(paths) = rfd::FileDialog::new().add_filter("Chrome crawler FindAll exports", &["json"]).pick_files() {
                                wireless::append_files(&mut self.dossier_browser, paths);
                            }
                        }
                        ui.label("Chrome crawler exports, one path per line (up to 10)");
                        ui.add(egui::TextEdit::multiline(&mut self.dossier_browser).desired_rows(2).desired_width(f32::INFINITY)
                            .hint_text("Choose JSON files saved with Export page to FindAll"));
                        ui.label(egui::RichText::new("Adds selected browser observations to this dossier without fetching their links. Review private page content before AI analysis.").small().color(ui.visuals().weak_text_color()));
                        ui.label("File paths, one per line");
                        ui.add(egui::TextEdit::multiline(&mut self.dossier_metadata).desired_rows(3).desired_width(f32::INFINITY).hint_text("Photo, PDF, or Office document"));
                        ui.label(egui::RichText::new("Reads embedded metadata and SHA-256 from up to 10 files (50 MB each). Only the files you select are read.").small().color(ui.visuals().weak_text_color()));
                        if ui.button("Add wireless telemetry files…").clicked() {
                            if let Some(paths) = wireless::pick_files() {wireless::append_files(&mut self.dossier_wireless,paths);}
                        }
                        ui.label("Wireless telemetry paths, one per line");
                        ui.add(egui::TextEdit::multiline(&mut self.dossier_wireless).desired_rows(2).desired_width(f32::INFINITY)
                            .hint_text("WireTapper / field CSV, JSON, KML, GeoJSON, SQLite or XLSX"));
                        ui.label(egui::RichText::new("Imports selected observations as candidate evidence. Device ownership is not inferred from a nearby signal.").small().color(ui.visuals().weak_text_color()));
                    });
                    ui.add_space(12.0);
                    ui.checkbox(&mut self.dossier_spiderfoot, "Run SpiderFoot with this search");
                    ui.label(egui::RichText::new("A short passive SpiderFoot set runs inside this dossier and stops after 2 minutes. Events with a page URL are listed with the other evidence.")
                        .color(ui.visuals().weak_text_color()).small());
                    ui.add_space(12.0);
                    ui.add_enabled(self.dossier_scope == "full",
                        egui::Checkbox::new(&mut self.dossier_onion, "Search the onion index (starts local Tor)"));
                    if self.dossier_scope != "full" {
                        ui.label(egui::RichText::new("Onion search runs only with Full research.").color(ui.visuals().weak_text_color()).small());
                    }
                    ui.label(egui::RichText::new("Onion engines use the configured Tor route. First connection can take several minutes. Each engine reports its own connection, block, or parser errors.")
                        .color(ui.visuals().weak_text_color()).small());
                    ui.add_space(18.0);
                    ui.checkbox(&mut self.dossier_ai, "Generate a final AI answer");
                    ui.add_enabled(self.dossier_ai, egui::Checkbox::new(&mut self.dossier_ai_investigate, "Let AI request additional source checks"));
                    ui.label(egui::RichText::new("AI can request bounded checks for this target, then explains up to 80 linked evidence items in the query language. Requests and source failures are saved.")
                        .color(ui.visuals().weak_text_color()).small());
                    ui.add_space(12.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Provider").strong());
                            ui.add_enabled_ui(!self.busy, |ui| {
                                let previous = self.ai_provider.clone();
                                egui::ComboBox::from_id_salt("ai-provider")
                                    .width(half_width)
                                    .selected_text(ai_provider_info(&self.ai_provider).unwrap_or("Choose provider"))
                                    .show_ui(ui, |ui| {
                                        for (id, label) in AI_PROVIDERS {
                                            ui.selectable_value(&mut self.ai_provider, (*id).into(), *label);
                                        }
                                    });
                                if self.ai_provider != previous {
                                    self.ai_model.clear();
                                    self.ai_key.clear();
                                    self.ai_account_id.clear();
                                    self.invalidate_ai_catalog();
                                }
                            });
                        });
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Model").strong());
                            ui.add_enabled_ui(!self.busy, |ui| {
                                if self.ai_models.is_empty() {
                                    if ui.add_sized([half_width, 34.0], egui::TextEdit::singleline(&mut self.ai_model)
                                        .hint_text("Test connection to load models")).changed() { self.ai_check = None; }
                                } else {
                                    egui::ComboBox::from_id_salt("ai-model")
                                        .width(half_width)
                                        .selected_text(if self.ai_model.is_empty() { "Choose available model" } else { &self.ai_model })
                                        .show_ui(ui, |ui| {
                                            ui.add_sized([half_width - 24.0, 30.0],
                                                egui::TextEdit::singleline(&mut self.ai_model_filter).hint_text("Filter models"));
                                            let filter = self.ai_model_filter.trim().to_lowercase();
                                            egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                                                for model in self.ai_models.iter().filter(|model|
                                                    model.to_lowercase().contains(&filter)).take(100) {
                                                    if ui.selectable_value(&mut self.ai_model, model.clone(), model).clicked() {
                                                        self.ai_check = None;
                                                    }
                                                }
                                            });
                                        });
                                }
                            });
                            });
                    });
                    if self.ai_provider == "cloudflare" {
                        ui.label("Cloudflare account ID");
                        if ui.add_enabled_ui(!self.busy, |ui| ui.add_sized([ui.available_width().min(612.0), 34.0],
                            egui::TextEdit::singleline(&mut self.ai_account_id).hint_text("32-character account ID")))
                            .inner.changed() {
                            self.invalidate_ai_catalog();
                            self.ai_model.clear();
                        }
                    }
                    if self.ai_provider == "gemini" {
                        ui.label("Local Antigravity gateway URL");
                        if ui.add_enabled_ui(!self.busy, |ui| ui.add_sized([ui.available_width().min(612.0), 34.0],
                            egui::TextEdit::singleline(&mut self.ai_gateway_url)
                                .hint_text("http://127.0.0.1:8045/v1/chat/completions"))).inner.changed() {
                            self.invalidate_ai_catalog();
                            self.ai_model.clear();
                        }
                    }
                    if ai_needs_key(&self.ai_provider) || self.ai_provider == "gemini" {
                        ui.label(if self.ai_provider == "cloudflare" { "Cloudflare API token" }
                            else if self.ai_provider == "gemini" { "Gateway key (optional)" }
                            else { "API key" });
                        if ui.add_enabled_ui(!self.busy, |ui| ui.add_sized([ui.available_width().min(612.0), 34.0],
                            egui::TextEdit::singleline(&mut self.ai_key)
                                .password(true).hint_text("Kept only in this window's memory"))).inner.changed() {
                            self.invalidate_ai_catalog();
                            self.ai_model.clear();
                        }
                    } else {
                        ui.label(egui::RichText::new("Uses the installed CLI and its existing login. No API key required.")
                            .small().color(ui.visuals().weak_text_color()));
                    }
                    let ready = !self.busy && self.ai_config_ready();
                    if self.dossier_ai && !self.ai_config_ready() {
                        ui.colored_label(ui.visuals().warn_fg_color, self.ai_config_hint());
                    }
                    ui.add_space(8.0);
                    if ui.add_enabled(!self.busy && self.ai_connection_ready(),
                        egui::Button::new("Test connection · load models")).clicked() {
                        self.load_ai_models();
                    }
                    if !self.ai_models.is_empty() {
                        ui.label(egui::RichText::new(format!("{} models returned by provider. Choose one, then verify it.",
                            self.ai_models.len())).color(ui.visuals().weak_text_color()).small());
                    }
                    if !self.ai_models_error.is_empty() {
                        ui.colored_label(ui.visuals().warn_fg_color, &self.ai_models_error);
                        if self.ai_models.is_empty() {
                            ui.label(egui::RichText::new("Enter a model ID manually, then verify it. Manual IDs are unverified until the probe succeeds.")
                                .color(ui.visuals().weak_text_color()).small());
                        }
                    }
                    if ui.add_enabled(ready, egui::Button::new("Verify selected model")).clicked() {
                        self.check_ai_provider();
                    }
                    if let Some(check) = &self.ai_check {
                        if check.status == "ok" {
                            ui.colored_label(ui.visuals().hyperlink_color, "Provider connected. No dossier data was sent during this check.");
                        } else {
                            ui.colored_label(ui.visuals().warn_fg_color,
                                if check.error.is_empty() { "Provider check failed" } else { check.error.as_str() });
                        }
                    } else {
                        ui.label(egui::RichText::new("Credentials are not saved to disk. Provider verification sends only a short probe.")
                            .small().color(ui.visuals().weak_text_color()));
                    }
                });
        });
        if self.busy && self.dossier_progress.stage.len() > 0 {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Spinner::new()
                            .size(17.0)
                            .color(ui.visuals().hyperlink_color),
                    );
                    ui.label(egui::RichText::new("Research in progress").strong());
                    ui.label(
                        egui::RichText::new(format!("{}%", self.dossier_progress.percent.min(100)))
                            .color(ui.visuals().hyperlink_color)
                            .strong(),
                    );
                });
                ui.add(
                    egui::ProgressBar::new(self.dossier_progress.percent.min(100) as f32 / 100.0)
                        .desired_width(ui.available_width()),
                );
                if !self.dossier_progress.detail.is_empty() {
                    ui.label(egui::RichText::new(&self.dossier_progress.detail).strong());
                }
                if self.dossier_progress.total > 0 {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} of {} tasks finished",
                            self.dossier_progress.completed, self.dossier_progress.total
                        ))
                        .color(ui.visuals().weak_text_color()),
                    );
                }
                for check in self.dossier_checks.iter().rev().take(6) {
                    let color = if ["error", "partial", "blocked", "timeout"]
                        .contains(&check.state.as_str())
                    {
                        ui.visuals().warn_fg_color
                    } else {
                        ui.visuals().weak_text_color()
                    };
                    ui.label(
                        egui::RichText::new(format!("{} · {}", check.source, check.state))
                            .color(color)
                            .small(),
                    )
                    .on_hover_text(&check.detail);
                }
            });
        }
        if self.dossier_results.is_none() && !self.busy && self.dossier_checks.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("⚡").size(14.0));
                    ui.label(egui::RichText::new("Investigation Archetypes").strong().color(egui::Color32::WHITE));
                    ui.label(
                        egui::RichText::new("· Pre-configured research profiles for rapid reconnaissance")
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                });
                ui.add_space(10.0);
                let templates = [
                    ("👤", "Key Person", "Alex Rivera", "Investigate handles, public mentions, and identity leads", "person"),
                    ("🏢", "Organization", "example.org", "Analyze domain records, WHOIS history, and DNS infrastructure", "domain"),
                    ("🌐", "Host / IPv4", "198.51.100.1", "Scan routing, ASNs, open services, and hostnames", "ip"),
                    ("📞", "Telephony", "+12025550123", "Parse carrier details, international codes, and format", "phone"),
                ];
                let card_width = ((ui.available_width() - ui.spacing().item_spacing.x) / 2.0 - 26.0).max(180.0);
                egui::Grid::new("dossier-presets").num_columns(2).show(ui, |ui| {
                    for (index, (icon, label, sample, desc, kind)) in templates.into_iter().enumerate() {
                        let res = egui::Frame::new()
                            .fill(egui::Color32::from_rgb(16, 21, 30))
                            .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(6))
                            .inner_margin(egui::Margin::symmetric(12, 10))
                            .show(ui, |ui| ui.vertical(|ui| {
                                ui.set_width(card_width);
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(icon).size(15.0));
                                    ui.label(egui::RichText::new(label).strong().color(theme::COLOR_INFO));
                                });
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(sample).monospace().size(12.0).color(egui::Color32::WHITE));
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(desc).size(11.0).color(ui.visuals().weak_text_color()));
                            }));
                        if res.response.interact(egui::Sense::click()).clicked() {
                            self.dossier_query = sample.into();
                            self.dossier_kind = kind.into();
                            self.show_toast(&format!("Template loaded: {label}"));
                        }
                        if index % 2 == 1 { ui.end_row(); }
                    }
                });
            });
        }
        if let Some(result) = self.dossier_results.clone() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🎯").size(14.0));
                    ui.label(egui::RichText::new("INTELLIGENCE DOSSIER").strong().color(theme::COLOR_INFO));
                    ui.label(egui::RichText::new("·").color(ui.visuals().weak_text_color()));
                    ui.label(egui::RichText::new(&result.query).strong().color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new(format!("({})", result.kind)).small().color(ui.visuals().weak_text_color()));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !result.report_json.is_empty() && ui.small_button("📄 JSON").clicked() {
                            open_url(&result.report_json);
                        }
                        if !result.report_csv.is_empty() && ui.small_button("📊 CSV").clicked() {
                            open_url(&result.report_csv);
                        }
                        if let Some(path) = result.exported_paths["markdown"].as_str() {
                            if ui.small_button("📝 MD").clicked() {
                                open_url(path);
                            }
                        }
                        if let Some(path) = result.exported_paths["obsidian_index"].as_str() {
                            if ui.small_button("🔮 Obsidian").clicked() {
                                open_url(path);
                            }
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    let total_findings = result.sections.get("findings").and_then(|v| v.as_array()).map_or(0, Vec::len);
                    bento_chip(ui, "📑", "FINDINGS", &format!("{total_findings}"), theme::COLOR_INFO);
                    if result.quality_report.is_object() {
                        let metrics = &result.quality_report["metrics"];
                        let passed = metrics["citation_checks_passed"].as_u64().unwrap_or(0);
                        let total = metrics["claims_checked"].as_u64().unwrap_or(0);
                        let color = if passed == total && total > 0 { theme::COLOR_SUCCESS } else { theme::COLOR_WARN };
                        bento_chip(ui, "✓", "CITATIONS", &format!("{passed}/{total}"), color);
                    }
                    let elapsed = result.diagnostics.get("elapsed_seconds")
                        .and_then(|v| v.as_f64())
                        .map(|s| format!("{s:.1}s"))
                        .unwrap_or_else(|| self.dossier_coverage.clone());
                    bento_chip(ui, "⏱", "RUNTIME", &elapsed, theme::COLOR_WARN);
                });
            });
            ui.add_space(12.0);
            card(ui, |ui| {
                ui.heading("Research answer");
                let analysis = result.ai_analysis.as_object();
                let answer = analysis
                    .and_then(|item| item.get("answer"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                if !answer.is_empty() {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(answer).size(18.0));
                } else {
                    let state = analysis
                        .and_then(|item| item.get("status"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let message = match state {
                        "unconfigured" => {
                            "Sources were saved. Check provider settings and connection to generate the answer."
                        }
                        "no_evidence" => {
                            "No source-linked evidence was found for an AI answer. Check the source warnings below."
                        }
                        "no_conclusions" => {
                            "The AI returned no supported conclusions. Collected matches remain available below."
                        }
                        "error" => {
                            "The AI provider could not analyze this dossier. Check its settings and try again."
                        }
                        _ => "Sources were saved. Add an AI provider to generate a sourced answer.",
                    };
                    ui.label(egui::RichText::new(message).color(ui.visuals().weak_text_color()));
                    if let Some(error) = analysis
                        .and_then(|item| item.get("error"))
                        .and_then(|value| value.as_str())
                        .filter(|value| !value.is_empty())
                    {
                        ui.colored_label(ui.visuals().warn_fg_color, error);
                    }
                }
                if let Some(analysis) = analysis {
                    if let Some(count) = analysis
                        .get("evidence_count")
                        .and_then(|value| value.as_u64())
                    {
                        ui.label(egui::RichText::new(format!("{count} linked evidence items checked · identity claims require independent verification"))
                            .color(ui.visuals().weak_text_color()).small());
                    }
                    if let Some(claims) = analysis.get("claims").and_then(|value| value.as_array())
                    {
                        if !claims.is_empty() {
                            egui::CollapsingHeader::new(format!(
                                "Supporting quotes and links · {}",
                                claims.len()
                            ))
                            .default_open(false)
                            .show(ui, |ui| {
                                for claim in claims {
                                    dossier_row(
                                        ui,
                                        claim["statement"].as_str().unwrap_or(""),
                                        claim["quote"].as_str().unwrap_or(""),
                                        claim["category"].as_str().unwrap_or("AI claim"),
                                        claim["source_url"].as_str().unwrap_or(""),
                                        "AI interpretation · check the cited source",
                                    );
                                }
                            });
                        }
                    }
                }
                if !self.busy
                    && !result.report_json.is_empty()
                    && ui.button("Analyze saved dossier").clicked()
                {
                    self.analyze_saved_dossier();
                }
            });
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.heading(format!("Dossier · {}", result.query));
                ui.label(
                    egui::RichText::new(format!("{} · {}", result.kind, result.scope))
                        .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if !result.report_json.is_empty() && ui.button("Open dossier JSON").clicked() {
                        open_url(&result.report_json);
                    }
                    if !result.report_csv.is_empty() && ui.button("Open table CSV").clicked() {
                        open_url(&result.report_csv);
                    }
                    if !result.report_json.is_empty() && ui.button("Statistical analysis").clicked() {
                        self.statistics.path = result.report_json.clone();
                        self.page = Page::Statistics;
                    }
                });
                if result.report_json.is_empty() {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        "The report file was not returned by the search.",
                    );
                }
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);
                ui.heading("Relationship graph");
                let nodes = result.relationship_graph["nodes"]
                    .as_array()
                    .map_or(0, Vec::len);
                let edges = result.relationship_graph["edges"]
                    .as_array()
                    .map_or(0, Vec::len);
                let graph_path = result.exported_paths["graph_html"]
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .unwrap_or(&result.graph_path);
                let graph_json = result.exported_paths["graph_json"]
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .unwrap_or(&result.graph_json_path);
                let bloodhound_path = result.exported_paths["bloodhound_graph"]
                    .as_str()
                    .filter(|path| !path.is_empty())
                    .unwrap_or(&result.bloodhound_graph_path);
                if !graph_path.is_empty() {
                    ui.label(format!("{nodes} nodes · {edges} connections"));
                    ui.label(egui::RichText::new("Explore collected pages, profiles, contacts, and infrastructure. Filter the graph, select a node, and inspect its evidence.").color(ui.visuals().weak_text_color()));
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        if primary_button(ui, "Open interactive graph", true).clicked() {
                            self.open_workspace_diagram();
                        }
                        if !graph_json.is_empty() && ui.button("Open graph JSON").clicked() {
                            open_url(graph_json);
                        }
                        if !bloodhound_path.is_empty()
                            && ui.button("Open BloodHound export").clicked()
                        {
                            open_url(bloodhound_path);
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Observed links and unverified matches are marked separately. A shared handle or mention does not establish identity or ownership.").small().color(ui.visuals().weak_text_color()));
                    egui::CollapsingHeader::new("About the BloodHound export").show(ui, |ui| {
                        ui.label("The OpenGraph file contains this dossier's public-source relationships. Import it into a BloodHound version supporting OpenGraph.");
                        ui.label(egui::RichText::new("This graph contains no Active Directory collection or privilege escalation paths.").color(ui.visuals().weak_text_color()));
                    });
                } else {
                    ui.label(
                        egui::RichText::new(
                            "Build a graph from the evidence already saved in this dossier.",
                        )
                        .color(ui.visuals().weak_text_color()),
                    );
                    if primary_button(
                        ui,
                        "Build relationship graph",
                        !self.busy && !result.report_json.is_empty(),
                    )
                    .on_disabled_hover_text(
                        "Wait for the current operation and save the dossier first.",
                    )
                    .clicked()
                    {
                        self.build_saved_graph();
                    }
                }
                ui.add_space(12.0);
                ui.separator();
                let web_checks: Vec<_> = result
                    .source_checks
                    .iter()
                    .filter(|check| {
                        [
                            "google",
                            "yandex",
                            "bing",
                            "duckduckgo",
                            "yahoo",
                            "brave",
                            "mojeek",
                            "web",
                            "wikipedia",
                            "news",
                            "github",
                        ]
                        .contains(&check["source"].as_str().unwrap_or(""))
                    })
                    .collect();
                if !web_checks.is_empty()
                    && web_checks.iter().all(|check| {
                        ["error", "blocked", "timeout", "unavailable"]
                            .contains(&check["state"].as_str().unwrap_or(""))
                    })
                {
                    ui.colored_label(ui.visuals().warn_fg_color,
                        "All web sources failed in this run. Check network/DNS access and retry; an empty dossier is not evidence of absence.");
                }
                if result.quality_report.is_object() {
                    let quality = &result.quality_report;
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Evidence checks").strong());
                    let metrics = &quality["metrics"];
                    ui.label(format!(
                        "{} of {} AI claims passed citation checks · {} sources with coverage gaps",
                        metrics["citation_checks_passed"].as_u64().unwrap_or(0),
                        metrics["claims_checked"].as_u64().unwrap_or(0),
                        quality["coverage"]["sources_with_gaps"]
                            .as_u64()
                            .unwrap_or(0)
                    ));
                    if quality["status"].as_str() == Some("invariant_failures") {
                        ui.colored_label(ui.visuals().warn_fg_color,
                            "Citation or attribution checks failed. Review the flagged claims before using the answer.");
                    }
                    ui.label(egui::RichText::new("Checks verify citations and collection coverage. Identity and factual conclusions require review.")
                        .small().color(ui.visuals().weak_text_color()));
                    if let Some(issues) = quality["diagnostics"].as_array() {
                        if !issues.is_empty() {
                            egui::CollapsingHeader::new(format!(
                                "Review notes · {}",
                                metrics["diagnostic_count"].as_u64().unwrap_or(0)
                            ))
                            .show(ui, |ui| {
                                for issue in issues {
                                    let code = issue["code"]
                                        .as_str()
                                        .unwrap_or("review needed")
                                        .replace('_', " ");
                                    let location = issue["claim_index"]
                                        .as_u64()
                                        .map(|index| format!(" · claim {index}"))
                                        .or_else(|| {
                                            issue["check_index"]
                                                .as_u64()
                                                .map(|index| format!(" · source check {index}"))
                                        })
                                        .unwrap_or_default();
                                    ui.label(format!("{code}{location}"));
                                }
                            });
                        }
                    }
                }
                if result.diagnostics.is_object() {
                    egui::CollapsingHeader::new("Collection diagnostics").show(ui, |ui| {
                        ui.label(format!("{:.1} seconds · {} HTTP requests · {} retries · {} failed requests",
                            result.diagnostics["elapsed_seconds"].as_f64().unwrap_or(0.0),
                            result.diagnostics["network_requests"].as_u64().unwrap_or(0),
                            result.diagnostics["network_retries"].as_u64().unwrap_or(0),
                            result.diagnostics["network_failures"].as_u64().unwrap_or(0)));
                        ui.label(egui::RichText::new("External tools may use separate transports. The trace excludes request bodies, headers and query strings.")
                            .small().color(ui.visuals().weak_text_color()));
                        if let Some(path) = result.diagnostics["trace_path"].as_str() {
                            if ui.small_button("Open diagnostic trace").clicked() { open_url(path); }
                        }
                    });
                }
                ui.add_space(12.0);
                ui.heading("History and notes");
                ui.horizontal_wrapped(|ui| {
                    if let Some(path) = result.exported_paths["markdown"].as_str() {
                        if ui.button("Open Markdown dossier").clicked() {
                            open_url(path);
                        }
                    }
                    if let Some(path) = result.exported_paths["obsidian_index"].as_str() {
                        if ui.button("Open Obsidian index").clicked() {
                            open_url(path);
                        }
                    }
                    if ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new("Compare history / export notes"),
                        )
                        .clicked()
                    {
                        self.export_saved_dossier();
                    }
                });
                render_history(ui, &result.history);
                render_dossier_sections(ui, &result.sections);
                if !result.artifacts.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "Saved evidence files · {}",
                        result.artifacts.len()
                    ))
                    .show(ui, |ui| {
                        for artifact in &result.artifacts {
                            let path = artifact["path"]
                                .as_str()
                                .or_else(|| artifact.as_str())
                                .unwrap_or("");
                            let name = artifact["name"].as_str().unwrap_or_else(|| {
                                path.rsplit(['/', '\\']).next().unwrap_or("Evidence file")
                            });
                            ui.horizontal_wrapped(|ui| {
                                ui.label(name);
                                if !path.is_empty() && ui.small_button("Open file").clicked() {
                                    open_url(path);
                                }
                            });
                            if let Some(hash) = artifact["sha256"].as_str() {
                                ui.label(
                                    egui::RichText::new(format!("SHA-256 {hash}"))
                                        .small()
                                        .color(ui.visuals().weak_text_color()),
                                );
                            }
                        }
                    });
                }
                if let Some(trace) = result.ai_investigation.as_object() {
                    egui::CollapsingHeader::new("AI collection activity").show(ui, |ui| {
                        ui.label(format!(
                            "Status: {}",
                            trace
                                .get("status")
                                .and_then(|item| item.as_str())
                                .unwrap_or("unknown")
                        ));
                        for key in ["requests", "trace", "errors", "limits"] {
                            if let Some(value) = trace.get(key) {
                                ui.label(format!("{}: {}", key, value));
                            }
                        }
                    });
                }
                if !result.source_checks.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "Source checks · {}",
                        result.source_checks.len()
                    ))
                    .show(ui, |ui| {
                        for check in &result.source_checks {
                            let state = check["state"].as_str().unwrap_or("");
                            let detail = if let Some(seconds) = check["elapsed_seconds"].as_f64() {
                                format!(
                                    "{} · {:.1} s",
                                    check["detail"].as_str().unwrap_or(""),
                                    seconds
                                )
                            } else {
                                check["detail"].as_str().unwrap_or("").to_string()
                            };
                            dossier_row(
                                ui,
                                check["source"].as_str().unwrap_or("Source"),
                                &detail,
                                "",
                                "",
                                state,
                            );
                        }
                    });
                } else if !self.dossier_checks.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "Source checks · {}",
                        self.dossier_checks.len()
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        if !result.include_onion {
                            ui.label(
                                egui::RichText::new("Onion index was not selected for this run.")
                                    .color(ui.visuals().weak_text_color())
                                    .small(),
                            );
                            ui.add_space(6.0);
                        }
                        for check in &self.dossier_checks {
                            let detail = check
                                .detail
                                .strip_prefix(&format!("{}: ", check.source))
                                .unwrap_or(&check.detail);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(&check.source).strong());
                                ui.label(egui::RichText::new(&check.state).color(
                                    if check.state == "error" {
                                        ui.visuals().warn_fg_color
                                    } else {
                                        ui.visuals().weak_text_color()
                                    },
                                ));
                                ui.label(detail);
                            });
                        }
                    });
                }
                if !result.errors.is_empty() {
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new(format!(
                        "Source warnings · {}",
                        result.errors.len()
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        for error in &result.errors {
                            ui.colored_label(ui.visuals().warn_fg_color, error);
                        }
                    });
                }
            });
        }
    }

    fn search_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            workspace_hero(
                ui,
                "💼",
                "Jobs and Projects",
                "Search jobs, GitHub developer projects, and published work contacts by profession.",
                None,
            );
            card(ui, |ui| {
                ui.label(egui::RichText::new("Profession or skill").strong());
                let wide = ui.available_width() >= 700.0;
                let mut enter = false;
                let mut click = false;
                if wide {
                    let field_width = (ui.available_width() - 340.0).max(220.0);
                    ui.horizontal(|ui| {
                        let field = ui.add_sized([field_width, 42.0], egui::TextEdit::singleline(&mut self.keywords)
                            .hint_text("For example: photographer, accountant, Python backend"));
                        enter = enter_submitted(ui, &field);
                        if !self.keywords.is_empty() && ui.button("✖").on_hover_text("Clear search input").clicked() {
                            self.keywords.clear();
                        }
                        click = primary_button(ui, "Search", !self.busy).clicked();
                        kbd_badge(ui, "↵ Enter");
                    });
                } else {
                    ui.horizontal(|ui| {
                        let field_width = if self.keywords.is_empty() {
                            ui.available_width()
                        } else {
                            (ui.available_width() - 36.0).max(160.0)
                        };
                        let field = ui.add_sized([field_width, 42.0], egui::TextEdit::singleline(&mut self.keywords)
                            .hint_text("For example: photographer, accountant, Python backend"));
                        enter = enter_submitted(ui, &field);
                        if !self.keywords.is_empty() && ui.button("✖").on_hover_text("Clear search input").clicked() {
                            self.keywords.clear();
                        }
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        click = primary_button(ui, "Search", !self.busy).clicked();
                        kbd_badge(ui, "↵ Enter");
                    });
                }
                if !self.busy && (enter || click) { self.start_scan(); }
                egui::CollapsingHeader::new("Job sources · edit")
                    .default_open(false).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            for (name, active) in &mut self.sources {
                                ui.checkbox(active, name.as_str());
                            }
                        });
                    });
                ui.label(egui::RichText::new("Contacts are shown only with a link to their source.").small().color(ui.visuals().weak_text_color()));
            });

            if self.search_results.is_none() && !self.busy {
                ui.add_space(14.0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("💼").size(14.0));
                        ui.label(egui::RichText::new("Role Archetypes").strong().color(egui::Color32::WHITE));
                        ui.label(
                            egui::RichText::new("· 1-click discovery presets")
                                .size(12.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    });
                    ui.add_space(8.0);
                    let presets = [
                        ("💻", "Backend Engineer", "Python backend API", "FastAPI, PostgreSQL, microservices"),
                        ("🛡", "Security Analyst", "SOC incident response", "SIEM triage, threat hunting, alerts"),
                        ("🔍", "OSINT Specialist", "OSINT threat analyst", "Public records, intelligence, recon"),
                        ("📊", "Data Engineer", "data pipeline ETL", "Kafka, Spark, analytics workflows"),
                    ];
                    let card_width = ((ui.available_width() - ui.spacing().item_spacing.x) / 2.0 - 26.0).max(180.0);
                    egui::Grid::new("search-presets").num_columns(2).show(ui, |ui| {
                        for (index, (icon, label, sample, desc)) in presets.into_iter().enumerate() {
                            let res = egui::Frame::new()
                                .fill(egui::Color32::from_rgb(16, 21, 30))
                                .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                                .corner_radius(egui::CornerRadius::same(6))
                                .inner_margin(egui::Margin::symmetric(12, 10))
                                .show(ui, |ui| ui.vertical(|ui| {
                                    ui.set_width(card_width);
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(icon).size(14.0));
                                        ui.label(egui::RichText::new(label).strong().color(theme::COLOR_INFO));
                                    });
                                    ui.add_space(2.0);
                                    ui.label(egui::RichText::new(sample).monospace().size(12.0).color(egui::Color32::WHITE));
                                    ui.add_space(2.0);
                                    ui.label(egui::RichText::new(desc).size(11.0).color(ui.visuals().weak_text_color()));
                                }));
                            if res.response.interact(egui::Sense::click()).clicked() {
                                self.keywords = sample.into();
                                self.show_toast(&format!("Role selected: {label}"));
                            }
                            if index % 2 == 1 { ui.end_row(); }
                        }
                    });
                });
            }

            if let Some(results) = self.search_results.clone() {
                ui.add_space(16.0);
                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        bento_chip(ui, "💼", "JOBS", &format!("{}", results.jobs.len()), theme::COLOR_INFO);
                        bento_chip(ui, "💻", "PROJECTS", &format!("{}", results.projects.len()), theme::COLOR_SUCCESS);
                        bento_chip(ui, "🌐", "WEB PAGES", &format!("{}", results.web_results.len()), theme::COLOR_WARN);
                        bento_chip(ui, "✉", "EMAILS", &format!("{}", results.contacts.len()), theme::COLOR_ACCENT);
                    });
                });
                ui.add_space(8.0);
                if !results.web_results.is_empty() { card(ui, |ui| {
                    ui.label(egui::RichText::new(format!("WEB SEARCH · {}", results.web_results.len())).color(ui.visuals().hyperlink_color).strong());
                    ui.label(egui::RichText::new("These are matching web pages, not verified job postings. Each link opens the source.").small().color(ui.visuals().weak_text_color()));
                    if !results.web_search_error.is_empty() {
                        ui.label(egui::RichText::new(&results.web_search_error).small().color(ui.visuals().weak_text_color()));
                    }
                    egui::ScrollArea::vertical().max_height(190.0).show(ui, |ui| {
                            for result in &results.web_results {
                                ui.separator();
                                ui.horizontal_wrapped(|ui| {
                                    ui.hyperlink_to(egui::RichText::new(&result.title).strong(), result.url.clone());
                                    if result.url.starts_with("https://") && ui.add_enabled(!self.busy,
                                        egui::Button::new("Parse page").small()).clicked() {
                                        self.parse_osint_page(result.url.clone(), results.query.clone());
                                    }
                                    if result.url.starts_with("https://") && ui.small_button("Browser research").clicked() {
                                        self.browser.url = result.url.clone();
                                        self.browser.question = results.query.clone();
                                        self.page = Page::Browser;
                                    }
                                });
                                ui.label(egui::RichText::new(&result.source).small().color(ui.visuals().hyperlink_color));
                                if !result.snippet.is_empty() {
                                    ui.label(egui::RichText::new(&result.snippet).small().color(ui.visuals().weak_text_color()));
                                }
                            }
                    });
                    ui.horizontal_wrapped(|ui| {
                        for link in &results.web_links {
                            ui.hyperlink_to(&link.label, link.url.clone());
                        }
                    });
                }); }
                if let Some(page) = self.parsed_page.clone().filter(|page| page.query == results.query) {
                    ui.add_space(8.0);
                    card(ui, |ui| {
                        ui.label(egui::RichText::new(format!("EMAILS ON PAGE · {}", page.emails.len())).color(ui.visuals().hyperlink_color).strong());
                        ui.hyperlink_to(&page.title, page.url.clone());
                        if page.emails.is_empty() { ui.label("No published email addresses on this page."); }
                        for email in &page.emails { ui.hyperlink_to(email, format!("mailto:{email}")); }
                    });
                }
                if results.jobs.is_empty() {
                    ui.label(egui::RichText::new("No jobs found in sources that responded.").color(ui.visuals().weak_text_color()));
                } else { card(ui, |ui| {
                    egui::CollapsingHeader::new(format!("Jobs · {}", results.jobs.len()))
                        .default_open(true)
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                                for job in &results.jobs {
                                    egui::Frame::new()
                                        .fill(egui::Color32::from_rgb(16, 21, 30))
                                        .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                                        .corner_radius(egui::CornerRadius::same(6))
                                        .inner_margin(egui::Margin::symmetric(10, 8))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(egui::RichText::new("💼").size(13.0));
                                                ui.hyperlink_to(
                                                    egui::RichText::new(format!("{} — {}", job.title, job.company)).strong().color(egui::Color32::WHITE),
                                                    job.url.clone(),
                                                );
                                                if job.remote {
                                                    egui::Frame::new()
                                                        .fill(egui::Color32::from_rgb(16, 32, 24))
                                                        .stroke(egui::Stroke::new(1.0, theme::COLOR_SUCCESS.gamma_multiply(0.5)))
                                                        .corner_radius(egui::CornerRadius::same(4))
                                                        .inner_margin(egui::Margin::symmetric(5, 1))
                                                        .show(ui, |ui| {
                                                            ui.label(egui::RichText::new("REMOTE").size(9.5).color(theme::COLOR_SUCCESS).strong());
                                                        });
                                                }
                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    if ui.small_button("📋 Copy link").clicked() {
                                                        ui.ctx().copy_text(job.url.clone());
                                                        ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Job link copied".to_owned()));
                                                    }
                                                    if ui.small_button("Open ↗").clicked() {
                                                        open_url(&job.url);
                                                    }
                                                });
                                            });
                                            ui.add_space(2.0);
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(egui::RichText::new(format!("{} · {}", job.source, job.location)).small().color(ui.visuals().weak_text_color()));
                                                if !job.found_emails.is_empty() {
                                                    ui.label(egui::RichText::new("·").color(ui.visuals().weak_text_color()));
                                                    ui.label(egui::RichText::new(format!("✉ {}", job.found_emails)).small().color(theme::COLOR_INFO));
                                                    if ui.small_button("📋 Copy email").clicked() {
                                                        ui.ctx().copy_text(job.found_emails.clone());
                                                        ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Email copied to clipboard".to_owned()));
                                                    }
                                                }
                                            });
                                        });
                                    ui.add_space(4.0);
                                }
                            });
                        });
                }); }
                if !results.source_errors.is_empty() {
                    egui::CollapsingHeader::new("Unavailable job sources")
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Some sites rejected requests from this network. Check the web results above.").small().color(ui.visuals().weak_text_color()));
                            for error in results.source_errors.lines() {
                                ui.label(egui::RichText::new(error.trim()).small().color(ui.visuals().weak_text_color()));
                            }
                        });
                }
                ui.add_space(8.0);
                if !results.projects.is_empty() || !results.project_error.is_empty() { card(ui, |ui| {
                    egui::CollapsingHeader::new(format!("GitHub projects · {}", results.projects.len()))
                        .default_open(results.jobs.is_empty() && !results.projects.is_empty())
                        .show(ui, |ui| {
                            if !results.project_error.is_empty() {
                                ui.colored_label(ui.visuals().warn_fg_color, format!("GitHub: {}", results.project_error));
                            }
                            if results.projects.is_empty() && results.project_error.is_empty() {
                                ui.label("No projects found for this query.");
                            }
                            egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                                for project in &results.projects {
                                    ui.separator();
                                    ui.hyperlink_to(egui::RichText::new(format!("{} · ★ {}", project.name, project.stars)).strong(), project.url.clone());
                                    ui.label(egui::RichText::new(format!("{} · {}", project.language, project.description)).small().color(ui.visuals().weak_text_color()));
                                }
                            });
                        });
                }); } else {
                    ui.label(egui::RichText::new("No GitHub projects found for this query.").color(ui.visuals().weak_text_color()));
                }
                if results.web_results.is_empty() {
                    let web_label = if results.web_search_error.is_empty() {
                        "No web pages found · search in browser"
                    } else {
                        "Automatic web search unavailable · search in browser"
                    };
                    egui::CollapsingHeader::new(web_label)
                        .default_open(false).show(ui, |ui| {
                            if !results.web_search_error.is_empty() {
                                ui.label(egui::RichText::new(&results.web_search_error).small().color(ui.visuals().weak_text_color()));
                            }
                            ui.horizontal_wrapped(|ui| {
                                for link in &results.web_links { ui.hyperlink_to(&link.label, link.url.clone()); }
                            });
                        });
                }
                ui.add_space(8.0);
                if !results.contacts.is_empty() { card(ui, |ui| {
                    egui::CollapsingHeader::new(format!("Contacts in postings · {}", results.contacts.len()))
                        .default_open(true)
                        .show(ui, |ui| {
                            for contact in &results.contacts {
                                ui.horizontal_wrapped(|ui| {
                                    ui.hyperlink_to(&contact.email, format!("mailto:{}", contact.email));
                                    ui.label(format!("{} · {}", contact.company, contact.source));
                                    if !contact.job_url.is_empty() {
                                        ui.hyperlink_to("source", contact.job_url.clone());
                                    }
                                });
                            }
                            if !results.company_links.is_empty() {
                                egui::CollapsingHeader::new("Find company contacts").show(ui, |ui| {
                                    for link in &results.company_links {
                                        ui.hyperlink_to(&link.label, link.url.clone());
                                    }
                                });
                            }
                        });
                }); } else {
                    ui.label(egui::RichText::new("No published emails in the jobs found.").color(ui.visuals().weak_text_color()));
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Find email on a company site →").clicked() {
                        self.page = Page::Contacts;
                    }
                });
            }
        });
    }

    fn osint_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            workspace_hero(
                ui,
                "🌐",
                "Web & Open Source Search",
                "Unified query across multi-engine web indexes, news, and Tor onion search.",
                Some(("MULTI-SOURCE", theme::COLOR_INFO)),
            );
            card(ui, |ui| {
                ui.label(egui::RichText::new("Query, domain, or @username").strong());
                let mut enter = false;
                ui.horizontal(|ui| {
                    let field_width = if self.osint_query.is_empty() {
                        ui.available_width()
                    } else {
                        (ui.available_width() - 36.0).max(120.0)
                    };
                    let field = ui.add_sized([field_width, 42.0], egui::TextEdit::singleline(&mut self.osint_query)
                        .hint_text("For example: example.org · @username · photographer New York"));
                    enter = enter_submitted(ui, &field);
                    if !self.osint_query.is_empty() && ui.button("✖").on_hover_text("Clear search input").clicked() {
                        self.osint_query.clear();
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.radio_value(&mut self.osint_email_only, false, "Full search");
                    ui.radio_value(&mut self.osint_email_only, true, "Published emails only");
                });
                if self.osint_email_only {
                    ui.label(egui::RichText::new("A domain scans a company site; a username checks public GitHub commits. Each email includes its source.").small().color(ui.visuals().weak_text_color()));
                } else {
                    egui::CollapsingHeader::new("More options: domain, username, and sources")
                        .default_open(false).show(ui, |ui| {
                        ui.label("Organization domain · optional");
                        let field = ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.osint_domain)
                            .hint_text("example.org"));
                        enter |= enter_submitted(ui, &field);
                        ui.label("Username · optional");
                        let field = ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.osint_username)
                            .hint_text("username"));
                        enter |= enter_submitted(ui, &field);
                        ui.checkbox(&mut self.osint_onion, "Also search with Tor (OnionSearch)");
                        ui.label("Search engines");
                        ui.horizontal_wrapped(|ui| {
                            for (name, active) in &mut self.osint_sources {
                                let label = match name.as_str() {
                                    "google" => "Google", "yandex" => "Yandex", "bing" => "Bing",
                                    "duckduckgo" => "DuckDuckGo", "yahoo" => "Yahoo", "brave" => "Brave", "mojeek" => "Mojeek",
                                    "web" => "Bing RSS",
                                    "wikipedia" => "Wikipedia", "news" => "News", "github" => "GitHub",
                                    "public" => "Telegram and public sites",
                                    _ => name.as_str(),
                                };
                                ui.checkbox(active, label);
                            }
                        });
                    });
                }
                ui.horizontal(|ui| {
                    let click = primary_button(ui, "Search", !self.busy).clicked();
                    kbd_badge(ui, "↵ Enter");
                    if !self.busy && (enter || click) {
                        self.start_osint();
                    }
                    if ui.add_enabled(!self.busy, egui::Button::new("Open saved results")).clicked() {
                        self.load_osint_history();
                    }
                });
            });
            if let Some(results) = self.osint_results.clone() {
                ui.add_space(12.0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let count = if results.mode == "email" { results.emails.len() } else { results.results.len() };
                        let label = if results.mode == "email" { "EMAIL" } else { "RESULTS" };
                        ui.label(egui::RichText::new(format!("{label} · {count}")).color(ui.visuals().hyperlink_color).strong());
                        ui.label(egui::RichText::new(&results.query).color(ui.visuals().weak_text_color()));
                    });
                    let responding = results.statuses.iter().filter(|s| s.error.is_empty() && matches!(s.state.as_str(), "" | "ok" | "empty")).count();
                    ui.label(egui::RichText::new(format!("{responding} of {} source checks responded · {} need attention", results.statuses.len(), results.statuses.len() - responding)).small().weak());
                    ui.add_space(6.0);
                    ui.horizontal_wrapped(|ui| {
                        for status in &results.statuses {
                            let ok = status.error.is_empty() && matches!(status.state.as_str(), "" | "ok" | "empty");
                            let (dot, dot_color, bg) = if ok {
                                if status.count > 0 {
                                    ("●", theme::COLOR_SUCCESS, egui::Color32::from_rgb(16, 28, 24))
                                } else {
                                    ("○", theme::COLOR_INFO, egui::Color32::from_rgb(16, 24, 34))
                                }
                            } else if status.state == "blocked" || status.error.contains("blocked") {
                                ("✖", theme::COLOR_ERROR, egui::Color32::from_rgb(32, 18, 22))
                            } else {
                                ("⚠", theme::COLOR_WARN, egui::Color32::from_rgb(32, 26, 18))
                            };
                            let chip = egui::Frame::new()
                                .fill(bg)
                                .stroke(egui::Stroke::new(1.0, dot_color.gamma_multiply(0.4)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 3))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(dot).size(10.0).color(dot_color).strong());
                                        ui.label(egui::RichText::new(&status.source).size(11.0).color(egui::Color32::WHITE));
                                        if status.count > 0 {
                                            ui.label(egui::RichText::new(format!("({})", status.count)).monospace().size(10.5).color(dot_color));
                                        }
                                    });
                                });
                            let hover_text = if !status.detail.is_empty() {
                                format!("{}: {}", status.source, status.detail)
                            } else if !status.error.is_empty() {
                                format!("{}: {}", status.source, status.error)
                            } else {
                                format!("{}: {} hits", status.source, status.count)
                            };
                            chip.response.on_hover_text(hover_text);
                        }
                    });
                    ui.add_space(8.0);
                    egui::CollapsingHeader::new("Source checks").show(ui, |ui| {
                      egui::Grid::new("osint-source-checks").num_columns(3).max_col_width(ui.available_width() * 0.45).spacing([16.0, 8.0]).striped(true).show(ui, |ui| {
                        for status in &results.statuses {
                            let ok = status.error.is_empty() && matches!(status.state.as_str(), "" | "ok" | "empty");
                            ui.label(egui::RichText::new(&status.source).small());
                            let state = if status.state.is_empty() { if ok { if status.count == 0 { "empty" } else { "ok" } } else { "error" } } else { &status.state };
                            ui.label(egui::RichText::new(state).small().color(if ok { ui.visuals().text_color() } else { ui.visuals().warn_fg_color }))
                                .on_hover_text(if !status.detail.is_empty() { &status.detail } else if !status.error.is_empty() { &status.error } else { "Source responded" });
                            ui.label(egui::RichText::new(status.count.to_string()).small());
                            ui.end_row();
                        }
                      });
                    });
                    if results.results.is_empty() && results.emails.is_empty() {
                        ui.label("No matches returned. Unavailable sources could not be checked; see Source checks.");
                    }
                    egui::ScrollArea::vertical().max_height(460.0).show(ui, |ui| {
                        for row in &results.results {
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.hyperlink_to(egui::RichText::new(&row.title).strong(), row.url.clone());
                                if ui.button("Open source ↗").clicked() {
                                    ui.ctx().open_url(egui::OpenUrl::new_tab(&row.url));
                                }
                                if ui.small_button("📋 Copy link").clicked() {
                                    ui.ctx().copy_text(row.url.clone());
                                    ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Link copied to clipboard".to_owned()));
                                }
                                if row.url.starts_with("https://") && ui.add_enabled(!self.busy,
                                    egui::Button::new("Parse page").small()).clicked() {
                                    self.parse_osint_page(row.url.clone(), results.query.clone());
                                }
                                if row.url.starts_with("https://") && ui.small_button("Browser research").clicked() {
                                    self.browser.url = row.url.clone();
                                    self.browser.question = results.query.clone();
                                    self.page = Page::Browser;
                                }
                            });
                            ui.label(egui::RichText::new(format!("{} · {} · {}", row.source, category_label(&row.category), row.seen_at)).small().color(ui.visuals().hyperlink_color));
                            if !row.snippet.is_empty() {
                                ui.label(egui::RichText::new(&row.snippet).small().color(ui.visuals().weak_text_color()));
                            }
                        }
                    });
                    if !results.errors.is_empty() {
                        egui::CollapsingHeader::new(format!("Source availability · {} issues", results.errors.len()))
                            .default_open(self.ui_smoke.is_some())
                            .show(ui, |ui| {
                                if self.ui_smoke.is_some() { ui.scroll_to_cursor(Some(egui::Align::TOP)); }
                                ui.label("Results from responding sources remain available. Restricted sources do not count as empty results.");
                                for error in &results.errors {
                                    let (source, detail) = error.split_once(':').unwrap_or(("Source", error));
                                    ui.label(egui::RichText::new(format!("{source}: {}", source_access_help(source, detail))).color(ui.visuals().warn_fg_color));
                                }
                                egui::CollapsingHeader::new("Technical details").show(ui, |ui| {
                                    for error in &results.errors { ui.add(egui::Label::new(error).wrap()); }
                                });
                            });
                    }
                    if let Some(domain) = &results.domain {
                        ui.separator();
                        ui.label(egui::RichText::new("DOMAIN · DNS/RDAP").color(ui.visuals().hyperlink_color).strong());
                        let name = domain["domain"].as_str().unwrap_or("");
                        let alive = domain["alive"].as_bool().unwrap_or(false);
                        let age = domain["age_years"].as_f64().map(|n| format!("{n:.1} years")).unwrap_or("unknown".into());
                        let mx = domain["mx"].as_array().map_or(0, Vec::len);
                        ui.label(format!("{name} · DNS {} · MX {} · age {}", yes_no(alive), mx, age));
                        ui.label(egui::RichText::new("MX records show mail configuration, not whether a specific address exists.").small().color(ui.visuals().weak_text_color()));
                    }
                });
                if !results.integrations.is_empty() {
                    ui.add_space(10.0);
                    card(ui, |ui| {
                        ui.label(egui::RichText::new("INTEGRATED TOOLS").color(ui.visuals().hyperlink_color).strong());
                        for (provider, integration) in &results.integrations {
                            let name = match provider.as_str() {
                                "domain_recon" => "Domain · Shodan / DNS / Web-Check",
                                "web_check" => "Web-Check · all modules",
                                "github_email" => "GitHub Email Hunter",
                                "company_site" => "Published emails on company site",
                                "maigret" => "Maigret · profiles",
                                "tiktok" => "TikTok Scraper · profile",
                                "onion" => "OnionSearch · Tor",
                                _ => provider.as_str(),
                            };
                            egui::CollapsingHeader::new(format!("{} · {}", name,
                                integration_state(integration)))
                                .show(ui, |ui| {
                                    if !integration.error.is_empty() {
                                        ui.colored_label(ui.visuals().warn_fg_color, &integration.error);
                                    }
                                    let data = &integration.data;
                                    if let Some(email) = data["email"].as_str().filter(|s| !s.is_empty()) {
                                        ui.label(format!("Published email: {email}"));
                                        if let Some(url) = data["source_url"].as_str() { ui.hyperlink_to("Source commit", url.trim_end_matches(".patch")); }
                                    }
                                    if let Some(assets) = data["assets"].as_array() {
                                        ui.label(format!("Assets: {}", assets.len()));
                                        for asset in assets.iter().take(30) {
                                            ui.label(format!("{}:{} · {}", asset["ip"].as_str().unwrap_or(""),
                                                asset["port"].as_str().unwrap_or(""), asset["provider"].as_str().unwrap_or("")));
                                        }
                                    }
                                    if let Some(modules) = data["modules"].as_array() {
                                        ui.label(format!("Modules: {}", modules.len()));
                                        for module in modules {
                                            ui.label(format!("{} · {}", module["name"].as_str().unwrap_or(""),
                                                module["status"].as_str().unwrap_or("")));
                                        }
                                    }
                                    if let Some(rows) = data["rows"].as_array() {
                                        ui.label(format!("Matches: {}", rows.len()));
                                        if provider == "spiderfoot" && rows.is_empty() {
                                            ui.label(egui::RichText::new("No linked public pages collected. The input event is not a match.").small().weak());
                                        }
                                    }
                                    if let Some(url) = data["url"].as_str().filter(|s| s.starts_with("https://")) { ui.hyperlink_to("Profile", url); }
                                    if let Some(report) = data["report"].as_str().filter(|s| !s.is_empty()) {
                                        if ui.button("Full report").clicked() { open_url(report); }
                                    }
                                });
                        }
                    });
                }
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new(format!("SAVED PAGES · {}", results.pages.len())).color(ui.visuals().hyperlink_color).strong());
                    ui.label(egui::RichText::new("The HTML copy and SHA-256 record the page as fetched; a search snippet alone is not verified.").small().color(ui.visuals().weak_text_color()));
                    for page in &results.pages {
                        ui.separator();
                        ui.hyperlink_to(&page.title, page.url.clone());
                        ui.label(egui::RichText::new(format!("{} · SHA-256 {}", page.observed_at, page.html_sha256)).small().color(ui.visuals().weak_text_color()));
                        if !page.excerpt.is_empty() { ui.label(&page.excerpt); }
                        if ui.button("Open HTML as text").clicked() { open_url(&page.snapshot); }
                    }
                });
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new(format!("PUBLISHED EMAILS · {}", results.emails.len())).color(ui.visuals().hyperlink_color).strong());
                    if results.emails.is_empty() {
                        ui.label(egui::RichText::new(if results.mode == "email" {
                            "No address found on the checked public pages or GitHub commits. Check the source status above."
                        } else {
                            "Select 'Parse page' for a result. An address appears only if it is published on that page."
                        }).small().color(ui.visuals().weak_text_color()));
                    }
                    for entry in &results.emails {
                        ui.horizontal_wrapped(|ui| {
                            ui.hyperlink_to(&entry.email, format!("mailto:{}", entry.email));
                            ui.hyperlink_to("source", entry.url.clone());
                        });
                    }
                });
                if let Some(page) = self.parsed_page.clone() {
                    ui.add_space(10.0);
                    card(ui, |ui| {
                        ui.label(egui::RichText::new("PARSED PAGE").color(ui.visuals().hyperlink_color).strong());
                        ui.hyperlink_to(&page.title, page.url.clone());
                        ui.label(egui::RichText::new(&page.excerpt).small().color(ui.visuals().weak_text_color()));
                        if page.emails.is_empty() { ui.label("No published emails on this page."); }
                        for email in &page.emails { ui.hyperlink_to(email, format!("mailto:{email}")); }
                        ui.label(egui::RichText::new(format!("{} · SHA-256 {}", page.observed_at, page.html_sha256)).small().color(ui.visuals().weak_text_color()));
                        if ui.button("Open HTML as text").clicked() { open_url(&page.snapshot); }
                    });
                }
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new("MORE SEARCH OPTIONS").color(ui.visuals().hyperlink_color).strong());
                    ui.label(egui::RichText::new("These links open searches in your browser; their results are not counted above.").small().color(ui.visuals().weak_text_color()));
                    ui.horizontal_wrapped(|ui| {
                        for link in &results.links { ui.hyperlink_to(&link.label, link.url.clone()); }
                    });
                    ui.label(egui::RichText::new("Results and parsed pages accumulate in the workspace diagram. Use Open diagram in the sidebar.").small().weak());
                });
            }
        });
    }

    fn tools_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            workspace_hero(
                ui,
                "🛠",
                "OSINT Arsenal & External Tools",
                "Integrated scanners: Web-Check, Domain Recon, Maigret, PhoneInfoga, TikTok, and 2GIS.",
                Some(("ARSENAL", theme::COLOR_INFO)),
            );
            let categories = [
                (0, "All"),
                (1, "🌐 Network & Web"),
                (2, "👤 Identity & Social"),
                (3, "🏢 Business & Local"),
                (4, "🔒 Auditing & Leaks"),
                (5, "📚 Tool Catalog"),
            ];
            let mut current_cat: usize = ui.data_mut(|d| d.get_temp(egui::Id::new("tools_category_filter")).unwrap_or(0));
            ui.horizontal_wrapped(|ui| {
                for (id, label) in categories {
                    let is_selected = current_cat == id;
                    let fill = if is_selected { theme::BG_ACTIVE_PILL } else { theme::BG_CARD };
                    let stroke = if is_selected {
                        egui::Stroke::new(1.0, ui.visuals().hyperlink_color)
                    } else {
                        egui::Stroke::new(1.0, theme::BORDER_CARD)
                    };
                    let text_color = if is_selected {
                        egui::Color32::WHITE
                    } else {
                        ui.visuals().weak_text_color()
                    };
                    let resp = egui::Frame::new()
                        .fill(fill)
                        .stroke(stroke)
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(10, 5))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(label).size(12.0).strong().color(text_color))
                        });
                    if resp.response.interact(egui::Sense::click()).clicked() {
                        current_cat = id;
                        ui.data_mut(|d| d.insert_temp(egui::Id::new("tools_category_filter"), id));
                    }
                }
            });
            ui.add_space(8.0);
            if current_cat == 0 || current_cat == 1 {
                card(ui, |ui| {
                    ui.label(egui::RichText::new("CHROME CRAWLER · BROWSER EVIDENCE").color(ui.visuals().hyperlink_color).strong());
                    ui.label("Collect dynamic public pages directly in Browser research, or import a page JSON exported from the bundled Chrome extension.");
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Open Browser research").clicked() { self.page = Page::Browser; }
                        if ui.button("Open extension folder").clicked() {
                            if let Some(root) = self.backend.script.parent() {
                                open_output(&root.join("third_party").join("chrome-crawler"));
                            }
                        }
                        if ui.add_enabled(!self.busy, egui::Button::new("Import page JSON")).clicked() {
                            if let Some(path) = rfd::FileDialog::new().add_filter("Chrome crawler FindAll export", &["json"]).pick_file() {
                                self.dossier_checks.clear();
                                self.page = Page::Dossier;
                                self.launch(vec![(vec!["browser-import".into(), "--file".into(), path.to_string_lossy().into_owned()], None)], TaskKind::Dossier, "Chrome crawler import".into());
                            }
                        }
                    });
                });
                ui.add_space(10.0);
            }
            if current_cat == 0 || current_cat == 5 {
                let mut flow_action = None;
                card(ui, |ui| { flow_action = self.enrichment.show(ui, self.busy); });
                if let Some(action) = flow_action {
                    match action {
                        enrichment::Action::Run(args) => self.launch(vec![(args, None)], TaskKind::Enrichment, "Enrichment flow".into()),
                        enrichment::Action::Diagram(path, query) => {
                            self.diagram.requested_query = query;
                            self.diagram.load(std::path::Path::new(&path));
                            self.page = Page::Diagram;
                        }
                    }
                }
                ui.add_space(10.0);
            }
            if current_cat == 0 || current_cat == 4 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("LOCAL SOURCE AUDIT · GITLEAKS").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_WARN.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_WARN.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("AUDIT").size(10.0).strong().color(theme::COLOR_WARN));
                                });
                        });
                    });
                    ui.label(egui::RichText::new("Audit a directory you explicitly choose. This action runs separately from OSINT research.").small().color(ui.visuals().weak_text_color()));
                    ui.label("Local source directory");
                    let mut enter = false;
                    ui.horizontal(|ui| {
                        let clear_w = if self.local_audit_path.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - clear_w, 38.0], egui::TextEdit::singleline(&mut self.local_audit_path)
                            .hint_text("Full path to your source directory"));
                        enter = enter_submitted(ui, &field);
                        if !self.local_audit_path.is_empty() && ui.button("✖").on_hover_text("Clear directory path").clicked() {
                            self.local_audit_path.clear();
                        }
                    });
                    ui.add_enabled(!self.busy, egui::Checkbox::new(&mut self.local_audit_history, "Audit Git history instead of working files"));
                    ui.horizontal_wrapped(|ui| {
                        let enabled = !self.busy && !self.local_audit_path.trim().is_empty();
                        let click = primary_button(ui, "Audit chosen folder", enabled).clicked();
                        if enabled && (enter || click) { self.run_local_audit(false); }
                        if ui.add_enabled(!self.busy, egui::Button::new("Install official Gitleaks")).clicked() {
                            self.run_local_audit(true);
                        }
                    });
                    ui.label(egui::RichText::new("Reports contain candidate counts and file/line metadata. Secret values and matches are excluded; tokens are never validated.").small().color(ui.visuals().weak_text_color()));
                    if let Some(result) = &self.local_audit_result {
                        ui.separator();
                        ui.label(egui::RichText::new(result.status_label()).strong());
                        if result.status != "installed" {
                            let scope = if result.scope == "git_history" { "Git history" } else { "Selected local files" };
                            ui.label(format!("{} · {} candidate finding(s)", scope, result.findings.len()));
                        }
                        if result.truncated { ui.label("The report contains a bounded subset of findings."); }
                        if !result.report.is_empty() && ui.button("Open redacted audit report").clicked() {
                            open_url(&result.report);
                        }
                    }
                });
                ui.add_space(10.0);
            }
            let mut selected_listing_email: Option<PersonContact> = None;
            let mut selected_business_site: Option<(String, String)> = None;
            if current_cat == 0 || current_cat == 3 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("2GIS · BUSINESS DIRECTORY").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_SUCCESS.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_SUCCESS.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("DIRECTORY").size(10.0).strong().color(theme::COLOR_SUCCESS));
                                });
                        });
                    });
                    ui.label(egui::RichText::new("Find business listings, addresses, phones, websites, and published emails. Requires Google Chrome.").small().color(ui.visuals().weak_text_color()));
                    let mut enter = false;
                    ui.horizontal(|ui| {
                        let clear_w = if self.two_gis_query.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - clear_w, 38.0], egui::TextEdit::singleline(&mut self.two_gis_query)
                            .hint_text("Business name or category, for example photo studio"));
                        enter = enter_submitted(ui, &field);
                        if !self.two_gis_query.is_empty() && ui.button("✖").on_hover_text("Clear search").clicked() {
                            self.two_gis_query.clear();
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label("City");
                        ui.add_sized([180.0, 34.0], egui::TextEdit::singleline(&mut self.two_gis_city).hint_text("moscow"));
                        ui.label("Max results");
                        ui.add_sized([70.0, 34.0], egui::TextEdit::singleline(&mut self.two_gis_limit));
                        let click = primary_button(ui, "Search 2GIS", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_two_gis(); }
                    });
                    if let Some(result) = self.two_gis_results.clone() {
                        ui.label(format!("{} businesses · {} new · {} updated · {} new emails", result.rows.len(), result.new, result.updated, result.new_emails));
                        ui.horizontal(|ui| {
                            if !result.csv.is_empty() && ui.button("CSV").clicked() { open_url(&result.csv); }
                            if !result.json.is_empty() && ui.button("JSON").clicked() { open_url(&result.json); }
                            if !result.xlsx.is_empty() && ui.button("XLSX").clicked() { open_url(&result.xlsx); }
                            if ui.button("Raw 2GIS JSON").clicked() { open_url(&result.raw); }
                        });
                        egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                            for row in &result.rows {
                                ui.separator();
                                ui.hyperlink_to(egui::RichText::new(&row.name).strong(), row.url.clone());
                                ui.label(format!("{} · {}", row.city, row.address));
                                if !row.categories.is_empty() { ui.label(row.categories.join(", ")); }
                                for phone in &row.phones { ui.label(format!("Phone: {phone}")); }
                                for email in &row.emails {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("Published email: {email}"));
                                        if ui.button("Use in Contacts").clicked() {
                                            selected_listing_email = Some(PersonContact {
                                                email: email.clone(), company: row.name.clone(),
                                                domain: email.split('@').nth(1).unwrap_or("").to_owned(),
                                                full_name: String::new(), position: String::new(),
                                                verification: "published".into(), evidence: vec![row.url.clone()],
                                            });
                                        }
                                    });
                                }
                                for website in &row.websites {
                                    ui.horizontal(|ui| {
                                        ui.hyperlink_to(website, website.clone());
                                        if let Some(host) = website_host(website) {
                                            if ui.add_enabled(!self.busy, egui::Button::new("Find site emails")).clicked() {
                                                selected_business_site = Some((row.name.clone(), host.to_owned()));
                                            }
                                        }
                                    });
                                }
                            }
                        });
                    }
                });
                ui.add_space(10.0);
            }
            if let Some(contact) = selected_listing_email {
                self.company = contact.company.clone();
                self.contacts = vec![contact];
                self.contact_candidates.clear();
                self.contact_errors.clear();
                self.contact_searched = true;
                self.selected_contact = None;
                self.select_contact(0);
                self.page = Page::Contacts;
            }
            if let Some((company, host)) = selected_business_site {
                self.company = company;
                self.domain = host;
                self.page = Page::Contacts;
                self.search_contacts();
            }
            if current_cat == 0 || current_cat == 1 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("DOMAIN · PASSIVE OSINT").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_INFO.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("PASSIVE DNS").size(10.0).strong().color(theme::COLOR_INFO));
                                });
                        });
                    });
                    let mut enter = false;
                    ui.horizontal(|ui| {
                        let clear_w = if self.tool_domain.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.tool_domain).hint_text("example.org"));
                        enter = enter_submitted(ui, &field);
                        if !self.tool_domain.is_empty() && ui.button("✖").on_hover_text("Clear domain").clicked() {
                            self.tool_domain.clear();
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        let click = primary_button(ui, "Research domain", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_domain_recon(); }
                        if ui.add_enabled(!self.busy, egui::Button::new("Detailed Web-Check")).clicked() { self.run_web_check(); }
                    });
                    ui.label(egui::RichText::new("Certificates, DNS/IP, Shodan InternetDB, website technologies, and web search work without keys. Full Shodan, Censys, ZoomEye, and SecurityTrails APIs use osint-keys.env.").small().color(ui.visuals().weak_text_color()));
                    if let Some(result) = &self.domain_results {
                        ui.separator();
                        ui.label(format!("{} · {} names · {} services · {} web pages",
                            result.domain, result.subdomains.len(), result.assets.len(), result.web_results.len()));
                        if result.truncated { ui.colored_label(ui.visuals().warn_fg_color, "DNS was resolved for the first 100 names; the full list is in the report."); }
                        let mx = result.dns["mx"].as_array().map_or(0, Vec::len);
                        ui.label(format!("MX: {mx} · sources and errors are shown below"));
                        egui::CollapsingHeader::new("Sources and status").default_open(true).show(ui, |ui| {
                            for source in &result.statuses {
                                ui.label(format!("{} · {} · {} {}", source.name, source.state, source.count, source.detail));
                            }
                        });
                        egui::CollapsingHeader::new(format!("Subdomains · {}", result.subdomains.len())).show(ui, |ui| {
                            egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                                for row in &result.subdomains {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(egui::RichText::new(&row.name).strong());
                                        ui.label(format!("{} · {}", row.ips.join(", "), row.sources.join(", ")));
                                    });
                                }
                            });
                        });
                        egui::CollapsingHeader::new(format!("Shodan / Censys / ZoomEye · {}", result.assets.len())).show(ui, |ui| {
                            ui.label(egui::RichText::new("A service was found on an IP currently resolved from this domain. A shared IP may host other sites.").small().color(ui.visuals().weak_text_color()));
                            egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                                for row in &result.assets {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.hyperlink_to(format!("{} · {}:{}", row.provider, row.ip, row.port), row.url.clone());
                                        ui.label(&row.product);
                                    });
                                }
                            });
                        });
                        egui::CollapsingHeader::new(format!("Web pages · {}", result.web_results.len())).show(ui, |ui| {
                            for row in &result.web_results { ui.hyperlink_to(&row.title, row.url.clone()); }
                        });
                        egui::CollapsingHeader::new(format!("Website technologies · {}", result.technologies.len())).show(ui, |ui| {
                            for row in &result.technologies {
                                ui.label(format!("{} {} · confidence {}%", row.name, row.version, row.confidence));
                            }
                        });
                        egui::CollapsingHeader::new(format!("Website scripts · {}", result.script_sources.len())).show(ui, |ui| {
                            for url in &result.script_sources { ui.hyperlink_to(url, url.clone()); }
                        });
                        ui.horizontal(|ui| {
                            if ui.button("JSON").clicked() { open_url(&result.report); }
                            if ui.button("CSV").clicked() { open_url(&result.csv); }
                        });
                    }
                    if let Some(result) = &self.webcheck_results {
                        ui.label(format!("{} · completed {} · skipped {} · errors {}",
                            result.domain, result.counts.ok, result.counts.skipped, result.counts.error));
                        ui.horizontal(|ui| {
                            ui.hyperlink_to("Open Web-Check", result.url.clone());
                            if ui.button("Full JSON").clicked() { open_url(&result.report); }
                        });
                        egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
                            for module in &result.modules {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(egui::RichText::new(format!("{} · {}", module.name, module.status))
                                        .color(if module.status == "ok" { ui.visuals().hyperlink_color } else { ui.visuals().weak_text_color() }));
                                    if !module.detail.is_empty() { ui.label(&module.detail); }
                                });
                            }
                        });
                    }
                });
                ui.add_space(10.0);
            }
            if current_cat == 0 || current_cat == 2 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("MAIGRET · PUBLIC USER PROFILES").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_SUCCESS.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_SUCCESS.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("IDENTITY").size(10.0).strong().color(theme::COLOR_SUCCESS));
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        let clear_w = if self.tool_username.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - 245.0 - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.tool_username).hint_text("madnessbrains"));
                        let enter = enter_submitted(ui, &field);
                        if !self.tool_username.is_empty() && ui.button("✖").on_hover_text("Clear username").clicked() {
                            self.tool_username.clear();
                        }
                        let click = primary_button(ui, "Find profiles", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_maigret(); }
                    });
                    if let Some(result) = &self.maigret_results {
                        ui.label(format!("{} · {} profiles", result.username, result.rows.len()));
                        for warning in &result.warnings { ui.colored_label(ui.visuals().warn_fg_color, warning); }
                        if result.rows.is_empty() && result.warnings.is_empty() {
                            ui.label("No matches in the sources checked.");
                        }
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            for row in &result.rows { ui.hyperlink_to(&row.site, row.url.clone()); }
                        });
                        if ui.button("Full JSON").clicked() { open_url(&result.report); }
                    }
                });
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("GITHUB EMAIL HUNTER · COMMIT AUTHOR EMAIL").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(egui::Color32::from_rgb(167, 139, 250).gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(167, 139, 250).gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("GITHUB").size(10.0).strong().color(egui::Color32::from_rgb(167, 139, 250)));
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        let clear_w = if self.tool_username.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - 245.0 - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.tool_username).hint_text("GitHub username"));
                        let enter = enter_submitted(ui, &field);
                        if !self.tool_username.is_empty() && ui.button("✖").on_hover_text("Clear username").clicked() {
                            self.tool_username.clear();
                        }
                        let click = primary_button(ui, "Find email", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_github_email(); }
                    });
                    ui.label(egui::RichText::new("Checks public commits linked to this GitHub account; each result links to its commit. GitHub API limits apply without a token.").small().color(ui.visuals().weak_text_color()));
                    if let Some(result) = &self.github_email_results {
                        if result.status == "found" {
                            ui.label(format!("{} · {} · {}", result.username, result.repository, result.email));
                            ui.hyperlink_to("Open source commit", result.source_url.trim_end_matches(".patch"));
                        } else if result.status == "not_found" {
                            ui.label("No published email found in the commits checked.");
                        } else {
                            ui.colored_label(ui.visuals().warn_fg_color, "GitHub API did not allow the check to finish.");
                        }
                        for error in &result.errors { ui.colored_label(ui.visuals().warn_fg_color, error); }
                        if ui.button("JSON report").clicked() { open_url(&result.report); }
                    }
                });
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("TIKTOK SCRAPER · PUBLIC PROFILE").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(egui::Color32::from_rgb(251, 191, 36).gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(251, 191, 36).gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("TIKTOK").size(10.0).strong().color(egui::Color32::from_rgb(251, 191, 36)));
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        let clear_w = if self.tool_username.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - 245.0 - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.tool_username).hint_text("TikTok username"));
                        let enter = enter_submitted(ui, &field);
                        if !self.tool_username.is_empty() && ui.button("✖").on_hover_text("Clear username").clicked() {
                            self.tool_username.clear();
                        }
                        let click = primary_button(ui, "Check profile", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_tiktok_profile(); }
                    });
                    if let Some(result) = &self.tiktok_results {
                        ui.hyperlink_to(format!("{} · @{}", result.name, result.username), result.url.clone());
                        ui.label(egui::RichText::new(&result.source).small().color(ui.visuals().weak_text_color()));
                        if !result.bio.is_empty() { ui.label(&result.bio); }
                        ui.label(format!("Followers: {} · Videos: {}", result.stats["followerCount"], result.stats["videoCount"]));
                        if ui.button("JSON report").clicked() { open_url(&result.report); }
                    }
                });
                ui.add_space(10.0);
            }
            if current_cat == 0 || current_cat == 4 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("ONIONSEARCH · PUBLIC ONION INDEXES").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_WARN.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_WARN.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("DARKNET").size(10.0).strong().color(theme::COLOR_WARN));
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        let clear_w = if self.onion_query.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - 245.0 - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.onion_query).hint_text("topic or organization"));
                        let enter = enter_submitted(ui, &field);
                        if !self.onion_query.is_empty() && ui.button("✖").on_hover_text("Clear query").clicked() {
                            self.onion_query.clear();
                        }
                        let click = primary_button(ui, "Search with Tor", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.run_onion_search(); }
                    });
                    ui.label(egui::RichText::new("Requires Tor SOCKS on 9050/9150; queries Ahmia, OnionLand, and Tordex. Search is limited to one page per index.").small().color(ui.visuals().weak_text_color()));
                    if let Some(result) = &self.onion_results {
                        ui.label(format!("{} · {} links", result.proxy, result.rows.len()));
                        for warning in &result.warnings { ui.colored_label(ui.visuals().warn_fg_color, warning); }
                        egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                            for row in &result.rows { ui.hyperlink_to(format!("{} · {}", row.engine, row.title), row.url.clone()); }
                        });
                        if ui.button("CSV report").clicked() { open_url(&result.report); }
                    }
                });
                ui.add_space(10.0);
            }
            if current_cat == 0 || current_cat == 5 {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("OSINT ARSENAL · SOURCE TOOL CATALOG").color(ui.visuals().hyperlink_color).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            egui::Frame::new()
                                .fill(theme::COLOR_INFO.gamma_multiply(0.15))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("CATALOG").size(10.0).strong().color(theme::COLOR_INFO));
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        let clear_w = if self.tool_query.is_empty() { 0.0 } else { 32.0 };
                        let field = ui.add_sized([ui.available_width() - 245.0 - clear_w, 38.0],
                            egui::TextEdit::singleline(&mut self.tool_query).hint_text("email, geo, onion, username…"));
                        let enter = enter_submitted(ui, &field);
                        if !self.tool_query.is_empty() && ui.button("✖").on_hover_text("Clear catalog query").clicked() {
                            self.tool_query.clear();
                        }
                        let click = primary_button(ui, "Find tool", !self.busy).clicked();
                        if !self.busy && (enter || click) { self.search_tool_catalog(0); }
                    });
                    if let Some(result) = self.catalog_results.clone() {
                        ui.label(format!("Matched {} of {} · entries {}–{}",
                            result.matched, result.total, result.offset + usize::from(!result.rows.is_empty()), result.offset + result.rows.len()));
                        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                            for row in &result.rows {
                                ui.separator();
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(&row.name).strong());
                                    if !row.action.is_empty() && ui.add_enabled(!self.busy, egui::Button::new("Run")).clicked() {
                                        match row.action.as_str() {
                                            "maigret" => self.run_maigret(),
                                            "web-check" => self.run_web_check(),
                                            "domain-recon" => self.run_domain_recon(),
                                            "onion-search" => self.run_onion_search(),
                                            "tiktok-profile" => self.run_tiktok_profile(),
                                            _ => {},
                                        }
                                    }
                                });
                                ui.label(egui::RichText::new(format!("{} · {} · {}", row.id, row.category, row.method)).small().color(ui.visuals().hyperlink_color));
                                if !row.description.is_empty() { ui.label(&row.description); }
                            }
                        });
                        ui.horizontal(|ui| {
                            if result.offset > 0 && ui.add_enabled(!self.busy, egui::Button::new("← Back")).clicked() {
                                self.search_tool_catalog(result.offset.saturating_sub(100));
                            }
                            if result.offset + result.rows.len() < result.matched &&
                                ui.add_enabled(!self.busy, egui::Button::new("Next →")).clicked() {
                                self.search_tool_catalog(result.offset + 100);
                            }
                        });
                    }
                    ui.label(egui::RichText::new("Run is available for tools integrated with FindAll. Other Arsenal entries describe external programs.").small().color(ui.visuals().weak_text_color()));
                });
            }
        });
    }

    fn contacts_page(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            workspace_hero(
                ui,
                "📇",
                "Contacts & Email Discovery",
                "Find published addresses and direct contacts verified on public company pages.",
                None,
            );
            card(ui, |ui| {
                ui.label(egui::RichText::new("FIND COMPANY CONTACTS").color(ui.visuals().hyperlink_color).strong());
                ui.add_space(8.0);
                ui.label("Company or domain");
                let mut enter = false;
                ui.horizontal(|ui| {
                    let clear_w = if self.company.is_empty() { 0.0 } else { 32.0 };
                    let field = ui.add_sized([ui.available_width() - clear_w, 38.0], egui::TextEdit::singleline(&mut self.company).hint_text("For example: web3tech or example.org"));
                    enter = enter_submitted(ui, &field);
                    if !self.company.is_empty() && ui.button("✖").on_hover_text("Clear company").clicked() {
                        self.company.clear();
                    }
                });
                ui.label("Website domain · if known");
                ui.horizontal(|ui| {
                    let clear_w = if self.domain.is_empty() { 0.0 } else { 32.0 };
                    let field = ui.add_sized([ui.available_width() - clear_w, 38.0], egui::TextEdit::singleline(&mut self.domain).hint_text("Optional"));
                    enter |= enter_submitted(ui, &field);
                    if !self.domain.is_empty() && ui.button("✖").on_hover_text("Clear domain").clicked() {
                        self.domain.clear();
                    }
                });
                ui.label("Employee name · optional");
                ui.horizontal(|ui| {
                    let clear_w = if self.employee_name.is_empty() { 0.0 } else { 32.0 };
                    let field = ui.add_sized([ui.available_width() - clear_w, 38.0], egui::TextEdit::singleline(&mut self.employee_name).hint_text("For address guesses only"));
                    enter |= enter_submitted(ui, &field);
                    if !self.employee_name.is_empty() && ui.button("✖").on_hover_text("Clear employee name").clicked() {
                        self.employee_name.clear();
                    }
                });
                ui.add_space(10.0);
                let action = if self.domain.trim().is_empty() { "Find company site" } else { "Find published emails" };
                let click = primary_button(ui, action, !self.busy).clicked();
                if !self.busy && (enter || click) {
                    self.search_contacts();
                }
                ui.label(egui::RichText::new("Without a domain, we show candidate sites. Select one to search for addresses.").small().color(ui.visuals().weak_text_color()));
            });
            ui.add_space(12.0);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("RESULTS").color(ui.visuals().hyperlink_color).strong());
                    if !self.contacts.is_empty() {
                        let count = self.contacts.len();
                        ui.label(
                            egui::RichText::new(format!("({count} contacts)"))
                                .size(12.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("📋 Copy all emails").on_hover_text("Copy all emails to clipboard separated by semicolon").clicked() {
                                let all_emails: Vec<String> = self.contacts.iter().map(|c| c.email.clone()).collect();
                                let joined = all_emails.join("; ");
                                ui.ctx().copy_text(joined);
                                ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), format!("✓ Copied {count} email(s) to clipboard")));
                            }
                        });
                    }
                    if let Some(mail) = &self.mail_status {
                        ui.label(egui::RichText::new(format!("MX {}   SPF {}   DMARC {}", yes_no(!mail.mx.is_empty()), yes_no(!mail.spf.is_empty()), yes_no(!mail.dmarc.is_empty()))).color(ui.visuals().weak_text_color()));
                    }
                });
                ui.separator();
                for candidate in self.contact_candidates.clone() {
                    ui.horizontal_wrapped(|ui| {
                        ui.hyperlink_to(&candidate.domain, candidate.url.clone());
                        ui.label(egui::RichText::new(format!("{} · {}", candidate.title, candidate.source)).small().color(ui.visuals().weak_text_color()));
                        if ui.add_enabled(!self.busy, egui::Button::new("Select and find emails")).clicked() {
                            self.domain = candidate.domain;
                            self.search_contacts();
                        }
                    });
                }
                if !self.contact_errors.is_empty() {
                    egui::CollapsingHeader::new(format!("Source errors · {}", self.contact_errors.len()))
                        .default_open(true)
                        .show(ui, |ui| { for error in &self.contact_errors { ui.label(error); } });
                }
                if self.contacts.is_empty() {
                    ui.add_space(8.0);
                    let message = if !self.contact_searched {
                        "Enter a company or domain to start searching."
                    } else if !self.contact_candidates.is_empty() {
                        "Select a company site to check for published emails."
                    } else if !self.contact_errors.is_empty() {
                        "The check did not finish. See the error above or choose another domain."
                    } else if self.mail_status.is_some() {
                        "No published emails found on the pages checked."
                    } else {
                        "No company sites found by responding search engines. Enter a domain manually."
                    };
                    ui.label(egui::RichText::new(message).color(ui.visuals().weak_text_color()));
                    ui.add_space(8.0);
                }
                let mut picked = None;
                egui::ScrollArea::vertical().max_height(170.0).show(ui, |ui| {
                    for (index, contact) in self.contacts.iter().enumerate() {
                        let published = contact.verification == "published";
                        ui.horizontal(|ui| {
                            if ui.selectable_label(self.selected_contact == Some(index), &contact.email).clicked() { picked = Some(index); }
                            ui.label(&contact.company);
                            ui.label(egui::RichText::new(if published { "Published" } else { "Guess" }).color(if published { ui.visuals().hyperlink_color } else { ui.visuals().warn_fg_color }));
                        });
                    }
                });
                if let Some(index) = picked { self.select_contact(index); }
            });
            if let Some(index) = self.selected_contact {
                if let Some(contact) = self.contacts.get(index).cloned() {
                    ui.add_space(12.0);
                    card(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("SOURCE").color(ui.visuals().hyperlink_color).strong());
                            ui.label(egui::RichText::new(contact.domain.clone()).color(ui.visuals().weak_text_color()));
                            if let Some(url) = contact.evidence.first() {
                                if ui.link("Open page").clicked() { open_url(url); }
                            }
                            if ui.link("Web-Check ↗").clicked() { open_url("https://web-check.as93.net/"); }
                        });
                        if contact.verification != "published" || contact.evidence.is_empty() {
                            ui.colored_label(ui.visuals().warn_fg_color, "This address is a pattern-based guess. Sending is unavailable.");
                        } else {
                            ui.separator();
                            ui.label(egui::RichText::new(format!("EMAIL TO {}", contact.email.to_uppercase())).color(ui.visuals().hyperlink_color).strong());
                            ui.label("SMTP server");
                            ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.smtp_host));
                            ui.horizontal(|ui| {
                                ui.label("Port");
                                ui.add_sized([90.0, 30.0], egui::TextEdit::singleline(&mut self.smtp_port));
                                ui.label("Security");
                                egui::ComboBox::from_id_salt("smtp-security").selected_text(&self.smtp_security).show_ui(ui, |ui| {
                                    ui.selectable_value(&mut self.smtp_security, "STARTTLS".to_owned(), "STARTTLS");
                                    ui.selectable_value(&mut self.smtp_security, "SSL".to_owned(), "SSL");
                                });
                            });
                            ui.label("Sender email");
                            ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.sender_email));
                            ui.label("Sender name");
                            ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.sender_name));
                            ui.label("SMTP username");
                            ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.smtp_user));
                            ui.label("App password");
                            ui.add_sized([ui.available_width(), 34.0], egui::TextEdit::singleline(&mut self.smtp_password).password(true));
                            ui.label(egui::RichText::new("The password stays in this window's memory. You will confirm before sending.").small().color(ui.visuals().weak_text_color()));
                            ui.add_space(7.0);
                            ui.label("Subject");
                            ui.add_sized([ui.available_width(), 36.0], egui::TextEdit::singleline(&mut self.subject));
                            ui.add_space(5.0);
                            ui.label("Message");
                            ui.add_sized([ui.available_width(), 116.0], egui::TextEdit::multiline(&mut self.body));
                            ui.add_space(8.0);
                            if primary_button(ui, "Send one email…", !self.busy).clicked() { self.begin_send(); }
                        }
                    });
                }
            }
        });
    }

    fn send_confirmation(&mut self, ctx: &egui::Context) {
        if !self.ask_send {
            return;
        }
        let recipient = self
            .selected_contact
            .and_then(|i| self.contacts.get(i))
            .map(|c| c.email.clone())
            .unwrap_or_default();
        let mut confirm = false;
        let mut cancel = false;
        egui::Window::new("Confirm email")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!("Send one email to {recipient}?"))
                    .on_hover_text("Check the linked public source and review your message.");
                ui.horizontal(|ui| {
                    if ui.button("Send one email").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        if confirm {
            self.send_confirmed();
        }
        if cancel {
            self.ask_send = false;
        }
    }
}

impl JobFindApp {
    fn open_workspace_diagram(&mut self) {
        self.diagram.requested_query = self.osint_query.trim().to_owned();
        self.page = Page::Diagram;
        self.launch(
            vec![(self.base_args("workspace-graph"), None)],
            TaskKind::WorkspaceGraph,
            "Workspace diagram".into(),
        );
    }

    fn navigate(&mut self, ui: &mut egui::Ui, page: Page) -> bool {
        let selected = self.page == page;
        let icon = page.icon();
        let label = page.label();

        let (bg, stroke, text_color) = if selected {
            (
                theme::BG_ACTIVE_PILL,
                egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.5)),
                egui::Color32::WHITE,
            )
        } else {
            (
                egui::Color32::TRANSPARENT,
                egui::Stroke::NONE,
                ui.visuals().text_color(),
            )
        };

        let text = egui::RichText::new(format!("{icon}  {label}")).color(text_color);
        let text = if selected { text.strong() } else { text };

        let button = egui::Button::new(text)
            .fill(bg)
            .stroke(stroke)
            .corner_radius(egui::CornerRadius::same(6))
            .min_size(egui::vec2(ui.available_width(), theme::CONTROL_HEIGHT));

        let clicked = ui.add(button).clicked();
        if clicked {
            self.page = page;
            if page == Page::Network && !self.busy {
                self.run_network("status");
            }
            if page == Page::Diagram && !self.busy {
                self.open_workspace_diagram();
            }
        }
        clicked
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("⬢")
                    .size(20.0)
                    .color(theme::COLOR_INFO)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("FindAll")
                    .size(20.0)
                    .color(egui::Color32::WHITE)
                    .strong(),
            );
        });
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("Public-source intelligence & discovery")
                .size(11.5)
                .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(14.0);
        self.navigation_groups(ui, false);
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "One diagram accumulates research across searches. Export evidence when needed.",
            )
            .small()
            .weak(),
        );
    }

    fn navigation_groups(&mut self, ui: &mut egui::Ui, close_on_navigation: bool) {
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            ui.visuals_mut().collapsing_header_frame = true;
            for (label, pages) in Page::GROUPS {
                let section_title = match label {
                    "Research" => "RESEARCH",
                    "Discovery" => "DISCOVERY",
                    "Workspace" => "WORKSPACE",
                    _ => label,
                };
                let header = egui::RichText::new(section_title)
                    .size(11.0)
                    .strong()
                    .color(ui.visuals().weak_text_color());
                egui::CollapsingHeader::new(header)
                    .id_salt(("navigation-group", label))
                    .default_open(pages.contains(&self.page) || label == "Workspace")
                    .show_unindented(ui, |ui| {
                        for &page in pages {
                            if self.navigate(ui, page) && close_on_navigation {
                                ui.close_kind(egui::UiKind::Menu);
                            }
                        }
                        if label == "Workspace" {
                            ui.add_space(6.0);
                            self.workspace_actions(ui);
                        }
                    });
                ui.add_space(4.0);
            }
        });
    }

    fn workspace_actions(&mut self, ui: &mut egui::Ui) {
        if ui
            .add_enabled(
                !self.busy,
                egui::Button::new(("🕸 Open diagram", egui::Atom::grow()))
                    .min_size(egui::vec2(ui.available_width(), theme::CONTROL_HEIGHT)),
            )
            .clicked()
        {
            self.open_workspace_diagram();
        }
        if ui
            .add_enabled(
                !self.busy,
                egui::Button::new(("📤 Export evidence", egui::Atom::grow()))
                    .min_size(egui::vec2(ui.available_width(), theme::CONTROL_HEIGHT)),
            )
            .clicked()
        {
            let mut args = self.base_args("workspace-graph");
            args.push("--export".into());
            self.launch(
                vec![(args, None)],
                TaskKind::WorkspaceGraph,
                "Export evidence".into(),
            );
        }
        if ui
            .add_sized(
                [ui.available_width(), theme::CONTROL_HEIGHT],
                egui::Button::new(("📁 Open results folder", egui::Atom::grow())),
            )
            .clicked()
        {
            open_output(&self.backend.output);
        }
    }

    fn render_command_palette(&mut self, ctx: &egui::Context) {
        if !self.command_palette_open {
            return;
        }
        let screen_rect = ctx.content_rect();
        let width = 560.0f32.min(screen_rect.width() - 32.0);
        let height = 380.0f32.min(screen_rect.height() - 64.0);
        let pos = egui::pos2(
            screen_rect.center().x - width / 2.0,
            (screen_rect.top() + 80.0).max(screen_rect.top() + 20.0),
        );

        let scrim_rect = ctx.content_rect();
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Middle,
            egui::Id::new("command-palette-scrim"),
        ));
        painter.rect_filled(scrim_rect, 0.0, egui::Color32::from_black_alpha(150));

        let mut close = false;
        let palette_rect = egui::Rect::from_min_size(pos, egui::vec2(width, height));
        if ctx.input(|i| i.pointer.button_clicked(egui::PointerButton::Primary)) {
            if let Some(click_pos) = ctx.input(|i| i.pointer.interact_pos()) {
                if !palette_rect.contains(click_pos) {
                    close = true;
                }
            }
        }

        let mut target_page = None;
        let mut run_action: Option<usize> = None;

        egui::Window::new("command-palette-window")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .fixed_pos(pos)
            .fixed_size(egui::vec2(width, height))
            .frame(
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(18, 23, 34))
                    .stroke(egui::Stroke::new(1.5, theme::COLOR_INFO))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(14, 12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🔍").size(15.0));
                    let input = ui.add(
                        egui::TextEdit::singleline(&mut self.command_palette_query)
                            .hint_text("Type workspace name or action… (Esc to exit)")
                            .desired_width(f32::INFINITY)
                            .margin(egui::vec2(8.0, 6.0)),
                    );
                    input.request_focus();
                });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(6.0);

                let query = self.command_palette_query.trim().to_lowercase();
                let pages: Vec<Page> = Page::ALL
                    .into_iter()
                    .filter(|p| {
                        query.is_empty()
                            || p.label().to_lowercase().contains(&query)
                            || p.slug().to_lowercase().contains(&query)
                            || p.group_name().to_lowercase().contains(&query)
                    })
                    .collect();

                let actions: [(&str, &str, &str); 4] = [
                    ("🕸", "Open relationship diagram", "Inspect multi-target intelligence graph"),
                    ("📁", "Open results folder", "View exported dossiers and reports on disk"),
                    ("⛶", "Toggle Fullscreen mode (F11)", "Maximize workspace canvas"),
                    ("📊", "Open statistical analyzer", "Run offline statistical intelligence"),
                ];
                let matching_actions: Vec<(usize, &(&str, &str, &str))> = actions
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, title, desc))| {
                        query.is_empty()
                            || title.to_lowercase().contains(&query)
                            || desc.to_lowercase().contains(&query)
                    })
                    .collect();

                let total_items = pages.len() + matching_actions.len();
                if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                    if total_items > 0 {
                        self.command_palette_selected = (self.command_palette_selected + 1) % total_items;
                    }
                }
                if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                    if total_items > 0 {
                        self.command_palette_selected = if self.command_palette_selected == 0 {
                            total_items - 1
                        } else {
                            self.command_palette_selected - 1
                        };
                    }
                }
                let enter = ctx.input(|i| i.key_pressed(egui::Key::Enter));

                egui::ScrollArea::vertical()
                    .max_height(height - 75.0)
                    .show(ui, |ui| {
                        let mut index = 0;
                        if !pages.is_empty() {
                            ui.label(
                                egui::RichText::new("WORKSPACES")
                                    .size(10.5)
                                    .strong()
                                    .color(theme::COLOR_INFO),
                            );
                            ui.add_space(2.0);
                            for page in pages {
                                let selected = self.command_palette_selected == index;
                                let bg = if selected {
                                    theme::BG_ACTIVE_PILL
                                } else {
                                    egui::Color32::TRANSPARENT
                                };
                                let stroke = if selected {
                                    egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.4))
                                } else {
                                    egui::Stroke::NONE
                                };
                                let res = egui::Frame::new()
                                    .fill(bg)
                                    .stroke(stroke)
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(page.icon()).size(14.0));
                                            ui.label(
                                                egui::RichText::new(page.label())
                                                    .strong()
                                                    .color(if selected {
                                                        egui::Color32::WHITE
                                                    } else {
                                                        ui.visuals().text_color()
                                                    }),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new(page.group_name())
                                                            .size(11.0)
                                                            .color(ui.visuals().weak_text_color()),
                                                    );
                                                },
                                            );
                                        });
                                    });
                                if res.response.interact(egui::Sense::click()).clicked()
                                    || (selected && enter)
                                {
                                    target_page = Some(page);
                                    close = true;
                                }
                                index += 1;
                            }
                            ui.add_space(8.0);
                        }

                        if !matching_actions.is_empty() {
                            ui.label(
                                egui::RichText::new("ACTIONS")
                                    .size(10.5)
                                    .strong()
                                    .color(theme::COLOR_SUCCESS),
                            );
                            ui.add_space(2.0);
                            for (action_id, (icon, title, desc)) in matching_actions {
                                let selected = self.command_palette_selected == index;
                                let bg = if selected {
                                    theme::BG_ACTIVE_PILL
                                } else {
                                    egui::Color32::TRANSPARENT
                                };
                                let stroke = if selected {
                                    egui::Stroke::new(1.0, theme::COLOR_SUCCESS.gamma_multiply(0.4))
                                } else {
                                    egui::Stroke::NONE
                                };
                                let res = egui::Frame::new()
                                    .fill(bg)
                                    .stroke(stroke)
                                    .corner_radius(egui::CornerRadius::same(6))
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(*icon).size(14.0));
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    egui::RichText::new(*title)
                                                        .strong()
                                                        .color(if selected {
                                                            egui::Color32::WHITE
                                                        } else {
                                                            ui.visuals().text_color()
                                                        }),
                                                );
                                                ui.label(
                                                    egui::RichText::new(*desc)
                                                        .size(11.0)
                                                        .color(ui.visuals().weak_text_color()),
                                                );
                                            });
                                        });
                                    });
                                if res.response.interact(egui::Sense::click()).clicked()
                                    || (selected && enter)
                                {
                                    run_action = Some(action_id);
                                    close = true;
                                }
                                index += 1;
                            }
                        }
                    });
            });

        if let Some(page) = target_page {
            self.page = page;
            if page == Page::Diagram {
                self.open_workspace_diagram();
            }
        }
        if let Some(action) = run_action {
            match action {
                0 => {
                    self.page = Page::Diagram;
                    self.open_workspace_diagram();
                    self.show_toast("Relationship diagram loaded");
                }
                1 => {
                    open_output(&self.backend.output);
                    self.show_toast("Results folder opened");
                }
                2 => {
                    self.diagram.full_screen = !self.diagram.full_screen;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.diagram.full_screen));
                    self.show_toast("Fullscreen toggled");
                }
                3 => {
                    self.page = Page::Statistics;
                    self.show_toast("Statistical intelligence opened");
                }
                _ => {}
            }
        }
        if close {
            self.command_palette_open = false;
        }
    }

    fn show_toast(&mut self, text: &str) {
        self.toast = Some((text.to_owned(), std::time::Instant::now()));
    }

    fn render_toast(&mut self, ctx: &egui::Context) {
        let Some((ref text, started)) = self.toast else {
            return;
        };
        let elapsed = started.elapsed().as_secs_f32();
        if elapsed > 2.5 {
            self.toast = None;
            return;
        }
        let alpha = if elapsed > 2.0 {
            ((2.5 - elapsed) * 2.0).clamp(0.0, 1.0)
        } else {
            (elapsed * 4.0).clamp(0.0, 1.0)
        };
        let screen_rect = ctx.content_rect();
        let pos = egui::pos2(
            (screen_rect.right() - 290.0).max(screen_rect.left() + 10.0),
            (screen_rect.bottom() - 48.0).max(screen_rect.top() + 10.0),
        );
        egui::Area::new(egui::Id::new("toast-area"))
            .fixed_pos(pos)
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(20, 28, 42).gamma_multiply(alpha))
                    .stroke(egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(alpha)))
                    .corner_radius(egui::CornerRadius::same(6))
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("✓")
                                    .size(13.0)
                                    .strong()
                                    .color(theme::COLOR_SUCCESS.gamma_multiply(alpha)),
                            );
                            ui.label(
                                egui::RichText::new(text)
                                    .size(12.0)
                                    .strong()
                                    .color(egui::Color32::WHITE.gamma_multiply(alpha)),
                            );
                        });
                    });
            });
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }
}

impl eframe::App for JobFindApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.receive_results();
        if let Some(msg) = ui.data_mut(|d| d.remove_temp::<String>(egui::Id::new("toast_pending"))) {
            self.show_toast(&msg);
        }
        if ui.input_mut(|i| {
            i.consume_key(egui::Modifiers::CTRL, egui::Key::K)
                || i.consume_key(egui::Modifiers::COMMAND, egui::Key::K)
        }) {
            self.command_palette_open = !self.command_palette_open;
            if self.command_palette_open {
                self.command_palette_query.clear();
                self.command_palette_selected = 0;
            }
        }
        if self.command_palette_open
            && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.command_palette_open = false;
        }
        if self.page == Page::Diagram {
            if ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::F11)) {
                self.diagram.full_screen = !self.diagram.full_screen;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.diagram.full_screen));
            }
            if self.diagram.full_screen
                && ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                self.diagram.full_screen = false;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
            }
            if self.diagram.full_screen {
                egui::CentralPanel::default().show(ui, |ui| {
                    if self.diagram.show(ui, self.busy) {
                        self.open_workspace_diagram();
                    }
                    if let Some(args) = self.diagram.pending_enrichment.take() {
                        self.launch(
                            vec![(args, None)],
                            TaskKind::Enrichment,
                            "Enrich selected entity".into(),
                        );
                    }
                });
                self.finish_ui_smoke(ui.ctx());
                if self.busy {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(100));
                }
                return;
            }
        }
        ui.painter()
            .rect_filled(ui.max_rect(), 0.0, ui.visuals().panel_fill);
        let wide = ui.available_width() >= theme::SIDEBAR_BREAKPOINT;
        if wide {
            egui::Panel::left("workspace-navigation")
                .default_size(theme::SIDEBAR_WIDTH)
                .min_size(184.0)
                .max_size(260.0)
                .resizable(true)
                .frame(
                    egui::Frame::new()
                        .fill(ui.visuals().faint_bg_color)
                        .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                        .inner_margin(16),
                )
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("navigation-scroll")
                        .show(ui, |ui| {
                            self.navigation(ui);
                        });
                });
        }
        egui::Panel::bottom("workspace-status")
            .frame(
                egui::Frame::new()
                    .fill(theme::BG_CARD)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                    .inner_margin(egui::Margin::symmetric(14, 6)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.busy {
                        ui.spinner();
                        ui.label(
                            egui::RichText::new("RUNNING")
                                .size(11.0)
                                .strong()
                                .color(theme::COLOR_INFO),
                        );
                        ui.label(
                            egui::RichText::new("·")
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    } else {
                        ui.label(egui::RichText::new("●").size(9.0).color(theme::COLOR_SUCCESS));
                        ui.label(
                            egui::RichText::new("READY")
                                .size(11.0)
                                .strong()
                                .color(theme::COLOR_SUCCESS),
                        );
                        ui.label(
                            egui::RichText::new("·")
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                    }
                    ui.label(
                        egui::RichText::new(&self.status)
                            .size(12.0)
                            .color(ui.visuals().text_color()),
                    );

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new("FindAll v0.1.0 · Public OSINT")
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                        ui.label(
                            egui::RichText::new("·")
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                        kbd_badge(ui, "Ctrl K");
                        ui.label(
                            egui::RichText::new("·")
                                .size(11.0)
                                .color(ui.visuals().weak_text_color()),
                        );
                        let db_size = std::fs::metadata(&self.backend.database)
                            .map(|m| {
                                let bytes = m.len();
                                if bytes >= 1_048_576 {
                                    format!("{:.1} MB", bytes as f64 / 1_048_576.0)
                                } else {
                                    format!("{} KB", bytes / 1024)
                                }
                            })
                            .unwrap_or_else(|_| "0 KB".to_string());
                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(16, 21, 30))
                            .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(format!("💾 jobfind.db · {db_size}"))
                                        .size(11.0)
                                        .color(theme::COLOR_SUCCESS),
                                );
                            });
                    });
                });
            });
        egui::Panel::top("workspace-toolbar")
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(ui, |ui| {
                let compact_toolbar = ui.available_width() < 760.0;
                ui.horizontal_wrapped(|ui| {
                    if !wide {
                        egui::menu::MenuButton::new(if compact_toolbar { "Navigate" } else { "FindAll / Navigate" })
                            .config(
                                egui::menu::MenuConfig::new()
                                    .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside),
                            )
                            .ui(ui, |ui| {
                                ui.set_width(220.0);
                                egui::ScrollArea::vertical()
                                    .max_height(ui.ctx().content_rect().height() - 100.0)
                                    .show(ui, |ui| self.navigation_groups(ui, true));
                            });
                        ui.add_space(8.0);
                    }
                    if !compact_toolbar {
                    ui.label(
                        egui::RichText::new("Workspace")
                            .size(12.5)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.label(
                        egui::RichText::new("›")
                            .size(12.5)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.label(
                        egui::RichText::new(self.page.group_name())
                            .size(12.5)
                            .color(ui.visuals().weak_text_color()),
                    );
                    ui.label(
                        egui::RichText::new("›")
                            .size(12.5)
                            .color(ui.visuals().weak_text_color()),
                    );
                    }
                    ui.label(
                        egui::RichText::new(format!("{} {}", self.page.icon(), self.page.label()))
                            .size(13.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    );
                    ui.add_space(14.0);
                    let search_pill = egui::Frame::new()
                        .fill(egui::Color32::from_rgb(16, 21, 30))
                        .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                        .corner_radius(egui::CornerRadius::same(6))
                        .inner_margin(egui::Margin::symmetric(10, 4))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("🔍").size(12.0));
                                ui.label(
                                    egui::RichText::new(if compact_toolbar { "Search" } else { "Search actions & views…" })
                                        .size(11.5)
                                        .color(ui.visuals().weak_text_color()),
                                );
                                ui.add_space(6.0);
                                kbd_badge(ui, "Ctrl K");
                            });
                        });
                    if search_pill.response.interact(egui::Sense::click()).clicked() {
                        self.command_palette_open = true;
                        self.command_palette_query.clear();
                        self.command_palette_selected = 0;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if !compact_toolbar {
                        if let Some(path) = self
                            .dossier_results
                            .as_ref()
                            .map(|r| &r.report_json)
                            .filter(|p| !p.is_empty())
                        {
                            if ui.button("📄 Latest dossier ↗").clicked() {
                                open_url(path);
                            }
                            ui.add_space(6.0);
                        }

                        let active_target = if !self.dossier_query.trim().is_empty() {
                            Some(self.dossier_query.trim().to_string())
                        } else if !self.osint_query.trim().is_empty() {
                            Some(self.osint_query.trim().to_string())
                        } else if !self.domain.trim().is_empty() {
                            Some(self.domain.trim().to_string())
                        } else {
                            None
                        };

                        if let Some(target) = active_target {
                            egui::Frame::new()
                                .fill(egui::Color32::from_rgb(18, 24, 36))
                                .stroke(egui::Stroke::new(1.0, theme::COLOR_INFO.gamma_multiply(0.5)))
                                .corner_radius(egui::CornerRadius::same(6))
                                .inner_margin(egui::Margin::symmetric(8, 3))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("🎯").size(11.0));
                                        ui.label(
                                            egui::RichText::new("TARGET:")
                                                .size(10.0)
                                                .strong()
                                                .color(theme::COLOR_INFO),
                                        );
                                        let display_target = if target.chars().count() > 22 {
                                            format!("{}…", target.chars().take(22).collect::<String>())
                                        } else {
                                            target.clone()
                                        };
                                        ui.label(
                                            egui::RichText::new(display_target)
                                                .monospace()
                                                .size(11.0)
                                                .strong()
                                                .color(egui::Color32::WHITE),
                                        );
                                        if self.page != Page::Diagram && ui.small_button("🕸").on_hover_text("Pivot target to Diagram").clicked() {
                                            self.open_workspace_diagram();
                                        }
                                        if self.page != Page::Dossier && ui.small_button("👤").on_hover_text("Open target Dossier").clicked() {
                                            self.page = Page::Dossier;
                                        }
                                    });
                                });
                            ui.add_space(6.0);
                        }

                        }
                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(16, 22, 32))
                            .stroke(egui::Stroke::new(1.0, theme::BORDER_CARD))
                            .corner_radius(egui::CornerRadius::same(12))
                            .inner_margin(egui::Margin::symmetric(10, 4))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        egui::RichText::new("●")
                                            .size(9.0)
                                            .color(theme::COLOR_SUCCESS),
                                    );
                                    ui.label(
                                        egui::RichText::new("READY")
                                            .size(10.5)
                                            .strong()
                                            .color(theme::COLOR_SUCCESS),
                                    );
                                });
                            });
                    });
                });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .inner_margin(theme::GUTTER),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("workspace-content", self.page.slug()))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let available = ui.available_width().min(theme::CONTENT_WIDTH);
                        ui.set_width(available);
                        match self.page {
                            Page::Browser => {
                                let ready = self.ai_config_ready();
                                if let Some(args) = self.browser.show(ui, self.busy, ready) {
                                    self.browser.error.clear();
                                    self.launch(vec![(args, None)], TaskKind::Browser, "Browser research".into());
                                }
                                if std::mem::take(&mut self.browser.configure_ai) { self.page = Page::Dossier; }
                                if std::mem::take(&mut self.browser.open_library) {
                                    self.library.question = self.browser.result.as_ref().and_then(|r| r["query"].as_str()).unwrap_or(&self.browser.question).into();
                                    self.page = Page::Library;
                                }
                                if std::mem::take(&mut self.browser.open_dossier) {
                                    if let Some(result) = self.browser.result.as_ref().and_then(|value| serde_json::from_value::<DossierResult>(value.clone()).ok()) {
                                        self.dossier_query = result.query.clone();
                                        self.dossier_results = Some(result);
                                        self.page = Page::Dossier;
                                    } else { self.browser.error = "Saved dossier could not be opened. Use its retained JSON and CSV.".into(); }
                                }
                            }
                            Page::Library => {
                                let ready = self.ai_config_ready();
                                if let Some((args, input)) = self.library.show(ui, self.busy, ready) {
                                    self.library.error.clear();
                                    self.launch(vec![(args, input)], TaskKind::Library, "Evidence library".into());
                                }
                                if std::mem::take(&mut self.library.configure_ai) { self.page = Page::Dossier; }
                                if let Some(path) = self.library.open_dossier.take() {
                                    let loaded = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice::<DossierResult>(&bytes).ok());
                                    if let Some(result) = loaded {
                                        self.dossier_query = result.query.clone();
                                        self.dossier_results = Some(result);
                                        self.page = Page::Dossier;
                                    } else { self.library.error = "Saved dossier could not be opened; use its retained snapshot.".into(); }
                                }
                            }
                            Page::Dossier => self.dossier_page(ui),
                            Page::Search => self.search_page(ui),
                            Page::Osint => self.osint_page(ui),
                            Page::Tools => self.tools_page(ui),
                            Page::Contacts => self.contacts_page(ui),
                            Page::Network => self.network_page(ui),
                            Page::Wireless => self.wireless_page(ui),
                            Page::Archives => self.archives_page(ui),
                            Page::Statistics => {
                                let examples = self.backend.script.with_file_name("examples").join("statistics");
                                if self.statistics.show(ui, self.busy, &examples) {
                                    self.statistics.error.clear();
                                    let args = analytics::arguments(self.statistics.path.trim());
                                    self.launch(vec![(args, None)], TaskKind::Statistics, "Statistical analysis".into());
                                }
                                if std::mem::take(&mut self.statistics.setup_requested) {
                                    self.statistics.error.clear();
                                    self.launch(vec![(vec!["statistics".into(), "--install-model".into()], None)], TaskKind::Statistics, "Install pinned BERT model".into());
                                }
                                if std::mem::take(&mut self.statistics.open_requested) {
                                    let loaded = self.statistics.result.clone().and_then(|r| serde_json::from_value::<DossierResult>(r).ok());
                                    if let Some(result) = loaded {
                                        self.dossier_query = result.query.clone();
                                        self.dossier_results = Some(result);
                                        self.page = Page::Dossier;
                                        self.status = "Statistical dossier loaded. Review calculations or run AI analysis.".into();
                                    } else {
                                        self.statistics.error = "Could not load the analysis dossier; run analysis again.".into();
                                    }
                                }
                            }
                            Page::Diagram => {
                                if self.diagram.show(ui, self.busy) {
                                    self.open_workspace_diagram();
                                }
                                if let Some(args) = self.diagram.pending_enrichment.take() {
                                    self.launch(
                                        vec![(args, None)],
                                        TaskKind::Enrichment,
                                        "Enrich selected entity".into(),
                                    );
                                }
                            }
                        }
                        ui.add_space(24.0);
                        egui::CollapsingHeader::new("Activity log")
                            .default_open(false)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.log)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(4)
                                        .interactive(false),
                                );
                            });
                        if let Some(smoke) = self.ui_smoke.as_mut() {
                            smoke.horizontal_overflow =
                                (ui.min_rect().width() - available).max(0.0);
                        }
                    });
            });
        self.send_confirmation(ui.ctx());
        self.finish_ui_smoke(ui.ctx());
        self.render_command_palette(ui.ctx());
        self.render_toast(ui.ctx());
        if self.busy {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn source_access_help(source: &str, detail: &str) -> &'static str {
    let detail = detail.to_lowercase();
    if source == "public" {
        "Some platforms could not be searched. Direct public-source results are retained; see Source checks for each platform."
    } else if detail.contains("captcha") || detail.contains("human verification") {
        "The provider requires human verification. Automated collection stopped; use a configured official API where available."
    } else if detail.contains("429") {
        "The provider is limiting requests. Use the responding sources and retry later, or configure its official API where available."
    } else if detail.contains("unrelated") {
        "The index returned unrelated links. They were excluded to avoid false matches."
    } else if detail.contains("202") || detail.contains("403") {
        "Automated access was restricted. Use responding sources; this response does not prove that no matches exist."
    } else if detail.contains("timeout") || detail.contains("timed out") {
        "The source did not respond in time. Other collected results were retained."
    } else {
        "The source could not complete this search. Inspect Technical details for the reported cause."
    }
}

#[cfg(test)]
mod navigation_tests {
    #[test]
    fn access_messages_explain_restrictions_without_claiming_empty_results() {
        assert!(super::source_access_help("google", "HTTP 429").contains("limiting requests"));
        assert!(super::source_access_help("bing", "unrelated entries").contains("excluded"));
        assert!(super::source_access_help("yandex", "CAPTCHA").contains("verification"));
        assert!(super::source_access_help("public", "HTTP 202").contains("retained"));
    }
    #[test]
    fn timed_out_integration_never_appears_completed() {
        let mut integration = super::OsintIntegration {
            status: "ok".into(),
            error: "Time limit reached".into(),
            data: serde_json::json!({"timed_out": true, "event_count": 1, "rows": [], "emails": []}),
        };
        assert_eq!(
            super::integration_state(&integration),
            "timeout · no matches"
        );
        integration.data["rows"] = serde_json::json!([{"url": "https://example.org/page"}]);
        assert_eq!(
            super::integration_state(&integration),
            "partial · time limit"
        );
        integration.data["timed_out"] = serde_json::json!(false);
        assert_eq!(
            super::integration_state(&integration),
            "partial · source error"
        );
    }
    use super::Page;

    #[test]
    fn all_navigation_pages_round_trip_and_unknown_pages_are_rejected() {
        for page in Page::ALL {
            assert!(Page::from_slug(page.slug()) == Some(page));
            assert!(!page.label().is_empty());
        }
        assert!(Page::from_slug("unknown").is_none());
    }

    #[test]
    fn navigation_groups_include_each_page_once_without_repeating_the_group_label() {
        let grouped: Vec<_> = Page::GROUPS
            .iter()
            .flat_map(|(_, pages)| pages.iter())
            .collect();
        assert_eq!(grouped.len(), Page::ALL.len());
        for page in Page::ALL {
            assert_eq!(grouped.iter().filter(|&&&p| p == page).count(), 1);
        }
        for (label, pages) in Page::GROUPS {
            assert!(pages.iter().all(|page| page.label() != label));
        }
    }

    #[test]
    fn public_source_checks_without_error_field_do_not_hide_search_results() {
        let result: super::OsintResults = serde_json::from_value(serde_json::json!({
            "query": "Ada Lovelace", "results": [], "errors": [], "links": [],
            "domain": null, "csv": "test.csv", "report": "test.json",
            "statuses": [
                {"source": "Public pages t.me", "state": "blocked", "count": 0, "detail": "HTTP 202"},
                {"name": "Telegram public web", "state": "ok", "count": 8}
            ]
        })).unwrap();
        assert_eq!(result.statuses[0].state, "blocked");
        assert_eq!(result.statuses[0].detail, "HTTP 202");
        assert!(result.statuses[1].error.is_empty());
        assert_eq!(result.statuses[1].source, "Telegram public web");
        assert_eq!(result.statuses[1].count, 8);
    }
}

fn category_label(category: &str) -> &str {
    match category {
        "Веб" => "Web",
        "Репозитории" => "Repositories",
        "Профили" => "Profiles",
        "Публичный профиль" => "Public profile",
        "Новости" => "News",
        "Энциклопедия" => "Encyclopedia",
        "Архив" => "Archive",
        "Сообщения об утечках" => "Breach notices",
        "Onion-индекс" => "Onion index",
        _ => category,
    }
}

fn website_host(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#', ':']).next()?;
    host.contains('.').then_some(host)
}

fn open_url(url: &str) {
    #[cfg(windows)]
    {
        let _ = Command::new("explorer.exe").arg(url).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}

fn open_output(path: &PathBuf) {
    let _ = std::fs::create_dir_all(path);
    #[cfg(windows)]
    {
        let _ = Command::new("explorer.exe").arg(path).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("xdg-open").arg(path).spawn();
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let value = |flag: &str| args.windows(2).find(|p| p[0] == flag).map(|p| p[1].clone());
    let initial_page = value("--page").and_then(|s| Page::from_slug(&s));
    let archives_smoke = value("--smoke-archives");
    let layout_smoke = value("--smoke-layout");
    let statistics_smoke = value("--smoke-statistics");
    let library_smoke = value("--smoke-library");
    let browser_smoke = value("--smoke-browser");
    let browser_url_smoke = value("--smoke-browser-url");
    let library_import_smoke = value("--smoke-library-import");
    let library_ask_smoke = value("--smoke-library-ask");
    let phone_smoke = args.iter().any(|a| a == "--smoke-phone");
    let osint_smoke = value("--smoke-osint");
    let diagram_smoke = value("--smoke-graph");
    let smoke_file = value("--smoke-wireless");
    let smoke_output = value("--smoke-output").map(PathBuf::from);
    let smoke_scale = value("--smoke-scale")
        .and_then(|s| s.parse::<f32>().ok())
        .filter(|n| n.is_finite() && (0.75..=2.0).contains(n))
        .unwrap_or(1.0);
    let size = if value("--smoke-size").as_deref() == Some("minimum") {
        [900.0, 680.0]
    } else {
        [1240.0, 820.0]
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FindAll — Public-source research")
            .with_inner_size(size)
            .with_min_inner_size([900.0, 680.0])
            .with_position([100.0, 70.0]),
        ..Default::default()
    };
    eframe::run_native(
        "FindAll",
        options,
        Box::new(move |cc| {
            let mut app = JobFindApp::new(cc);
            if let Some(page) = initial_page {
                app.page = page;
                if page == Page::Diagram {
                    app.open_workspace_diagram();
                }
            }
            if let (Some(page), Some(output)) = (layout_smoke, smoke_output.clone()) {
                std::fs::create_dir_all(&output)?;
                app.backend.output = output.clone();
                app.backend.database = output.join("synthetic-smoke.db");
                cc.egui_ctx.set_zoom_factor(smoke_scale);
                app.page = Page::from_slug(&page).unwrap_or(Page::Dossier);
                if app.page == Page::Browser {
                    if let Some(path) = browser_smoke {
                        let result: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
                        app.browser.url = result["browser_research"]["url"].as_str().unwrap_or("").into();
                        app.browser.question = result["query"].as_str().unwrap_or("").into();
                        app.browser.result = Some(result);
                    }
                }
                if app.page == Page::Library {
                    if let Some(path) = library_smoke {
                        let result: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
                        app.library.question = result["question"].as_str().unwrap_or("").into();
                        app.library.result = Some(result);
                    }
                }
                if app.page == Page::Statistics {
                    if let Some(path) = statistics_smoke {
                        let result: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                        app.statistics.path = result["artifacts"].as_array().and_then(|rows| rows.iter().find(|r| r["kind"] == "analysis_input"))
                            .and_then(|r| r["path"].as_str()).unwrap_or("").into();
                        app.statistics.result = Some(result);
                    }
                }
                app.ui_smoke = Some(UiSmoke {
                    output,
                    frames: 0,
                    requested: false,
                    started: std::time::Instant::now(),
                    form_only: true,
                    horizontal_overflow: 0.0,
                });
                if app.page == Page::Browser {
                    if let Some(url) = browser_url_smoke {
                        app.browser.url = url.clone();
                        app.ui_smoke.as_mut().unwrap().form_only = false;
                        app.launch(vec![(browser::arguments(&url, "", 1, 50, false), None)], TaskKind::Browser, "Browser research smoke".into());
                    }
                }
                if app.page == Page::Dossier && phone_smoke {
                    app.dossier_query = "+12025550123".into();
                    app.dossier_kind = "phone".into();
                    app.dossier_ai = false;
                    app.ui_smoke.as_mut().unwrap().form_only = false;
                    app.start_phone(true);
                }
                if app.page == Page::Library {
                    if let Some(path) = library_import_smoke {
                        app.library.files = path.clone();
                        app.library.roots = app.backend.output.join("dossiers").to_string_lossy().into_owned();
                        let mut command = library::arguments("pdf", "", &app.library.roots);
                        command.extend(["--file".into(), path]);
                        app.ui_smoke.as_mut().unwrap().form_only = false;
                        app.launch(vec![(command, None)], TaskKind::Library, "Synthetic PDF import".into());
                    }
                    if let Some(question) = library_ask_smoke {
                        app.library.question = question;
                        app.library.roots = app.backend.output.join("dossiers").to_string_lossy().into_owned();
                        let command = library::arguments("ask", &app.library.question, &app.library.roots);
                        app.ui_smoke.as_mut().unwrap().form_only = false;
                        app.launch(vec![(command, None)], TaskKind::Library, "Synthetic library AI question".into());
                    }
                }
            } else if let (Some(file), Some(output)) = (archives_smoke, smoke_output.clone()) {
                std::fs::create_dir_all(&output)?;
                app.backend.output = output.clone();
                app.backend.database = output.join("synthetic-smoke.db");
                app.archives.offline_import(file);
                cc.egui_ctx.set_zoom_factor(smoke_scale);
                app.page = Page::Archives;
                app.ui_smoke = Some(UiSmoke {
                    output,
                    frames: 0,
                    requested: false,
                    started: std::time::Instant::now(),
                    form_only: false,
                    horizontal_overflow: 0.0,
                });
                app.start_archives();
            } else if let (Some(file), Some(output)) = (smoke_file, smoke_output) {
                std::fs::create_dir_all(&output)?;
                app.backend.output = output.clone();
                app.backend.database = output.join("synthetic-smoke.db");
                app.wireless.files = file;
                cc.egui_ctx.set_zoom_factor(smoke_scale);
                app.page = Page::Wireless;
                app.ui_smoke = Some(UiSmoke {
                    output,
                    frames: 0,
                    requested: false,
                    started: std::time::Instant::now(),
                    form_only: false,
                    horizontal_overflow: 0.0,
                });
                app.start_wireless();
            }
            if let Some(path) = osint_smoke {
                let result: OsintResults = serde_json::from_str(&std::fs::read_to_string(path)?)?;
                app.osint_query = result.query.clone();
                app.osint_results = Some(result);
                app.page = Page::Osint;
                if let Some(smoke) = app.ui_smoke.as_mut() {
                    smoke.form_only = false;
                }
            }
            if let Some(path) = diagram_smoke {
                app.diagram.load(std::path::Path::new(&path));
                if let Some(selected) = value("--smoke-node") {
                    app.diagram.select_value(&selected);
                }
                app.page = Page::Diagram;
            }
            Ok(Box::new(app))
        }),
    )
}
