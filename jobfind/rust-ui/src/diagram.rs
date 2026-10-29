use eframe::egui::{self, Pos2, Vec2};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

#[derive(Default, Deserialize)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}
#[derive(Deserialize)]
pub struct Node {
    id: String,
    kind: String,
    label: String,
    #[serde(default)]
    properties: BTreeMap<String, serde_json::Value>,
}
#[derive(Deserialize)]
pub struct Edge {
    source: String,
    target: String,
    kind: String,
    label: String,
    certainty: String,
    #[serde(default)]
    source_urls: Vec<String>,
    #[serde(default)]
    evidence_hashes: Vec<String>,
}

pub fn read(path: &Path) -> Result<Graph, String> {
    if std::fs::metadata(path)
        .map_err(|e| format!("Could not read diagram: {e}"))?
        .len()
        > 30_000_000
    {
        return Err(
            "Diagram exceeds the 30 MB display limit. Export evidence to inspect it.".into(),
        );
    }
    let html = std::fs::read_to_string(path).map_err(|e| format!("Could not read diagram: {e}"))?;
    parse(&html)
}

fn parse(html: &str) -> Result<Graph, String> {
    let marker = "<script id=\"graph-data\" type=\"application/json\">";
    let data = html
        .split_once(marker)
        .and_then(|(_, rest)| rest.split_once("</script>"))
        .map(|(data, _)| data)
        .ok_or("Diagram has no recognized evidence data. Refresh the diagram.")?;
    let graph: Graph =
        serde_json::from_str(data).map_err(|e| format!("Invalid diagram data: {e}"))?;
    let ids: BTreeSet<_> = graph.nodes.iter().map(|node| &node.id).collect();
    if ids.len() != graph.nodes.len()
        || graph
            .edges
            .iter()
            .any(|edge| !ids.contains(&edge.source) || !ids.contains(&edge.target))
    {
        return Err("Diagram contains duplicate nodes or missing relationship endpoints.".into());
    }
    Ok(graph)
}

#[derive(Default)]
pub struct Workspace {
    pub graph: Option<Graph>,
    pub error: String,
    pub full_screen: bool,
    pub requested_query: String,
    pub pending_enrichment: Option<Vec<String>>,
    enrichment_selection: usize,
    query: String,
    scope: BTreeSet<String>,
    positions: BTreeMap<String, Pos2>,
    filter: String,
    hidden: BTreeSet<String>,
    selected: String,
    neighborhood: bool,
    path_start: String,
    path: BTreeSet<String>,
    zoom: f32,
    pan: Vec2,
    dragging: Option<String>,
    fit: bool,
    canvas_size: Vec2,
}

impl Workspace {
    pub fn select_value(&mut self, value: &str) {
        if let Some(node) = self.graph.as_ref().and_then(|graph| {
            graph
                .nodes
                .iter()
                .find(|node| node.properties.get("value").and_then(|v| v.as_str()) == Some(value))
        }) {
            self.selected = node.id.clone();
        }
    }

    pub fn load(&mut self, path: &Path) {
        match read(path) {
            Ok(graph) => {
                self.query = graph
                    .nodes
                    .iter()
                    .filter(|n| n.kind == "Query" && n.label != "FindAll workspace")
                    .max_by_key(|n| {
                        (
                            !self.requested_query.is_empty() && n.label == self.requested_query,
                            n.properties
                                .get("observed_at")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                        )
                    })
                    .map(|n| n.id.clone())
                    .unwrap_or_default();
                self.arrange(&graph);
                self.graph = Some(graph);
                self.error.clear();
                self.selected.clear();
                self.path_start.clear();
                self.path.clear();
                self.fit = true;
            }
            Err(error) => self.error = error,
        }
    }

    fn arrange(&mut self, graph: &Graph) {
        self.scope = query_scope(graph, &self.query);
        self.positions.clear();
        let mut pages: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| n.kind == "Page" && self.scope.contains(&n.id))
            .collect();
        let host = |id: &str| {
            graph
                .edges
                .iter()
                .find(|e| e.source == id && e.kind == "UrlHost")
                .map(|e| e.target.as_str())
                .unwrap_or("")
        };
        pages.sort_by_key(|n| (host(&n.id), n.label.as_str()));
        let mut hosts: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
        for node in pages {
            hosts
                .entry(host(&node.id).to_owned())
                .or_default()
                .push(node);
        }
        let sector = std::f32::consts::TAU / hosts.len().max(1) as f32;
        for (group, (id, nodes)) in hosts.into_iter().enumerate() {
            let angle = group as f32 * sector;
            self.positions
                .insert(id, Pos2::new(angle.cos() * 650.0, angle.sin() * 650.0));
            for (index, node) in nodes.iter().enumerate() {
                let count = (nodes.len() - index / 8 * 8).min(8);
                let offset = ((index % 8) as f32 - (count - 1) as f32 / 2.0) / 8.0 * sector * 0.8;
                let radius = 300.0 + (index / 8) as f32 * 36.0;
                self.positions.insert(
                    node.id.clone(),
                    Pos2::new(
                        (angle + offset).cos() * radius,
                        (angle + offset).sin() * radius,
                    ),
                );
            }
        }
        let other: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| {
                self.scope.contains(&n.id)
                    && n.id != self.query
                    && !self.positions.contains_key(&n.id)
            })
            .collect();
        for (i, node) in other.iter().enumerate() {
            let angle = i as f32 * std::f32::consts::TAU / other.len().max(1) as f32;
            let radius = if node.kind == "Query" { 100.0 } else { 260.0 };
            self.positions.insert(
                node.id.clone(),
                Pos2::new(angle.cos() * radius, angle.sin() * radius),
            );
        }
        if !self.query.is_empty() {
            self.positions.insert(self.query.clone(), Pos2::ZERO);
        }
        self.selected.clear();
        self.path.clear();
        self.path_start.clear();
        self.fit = true;
    }

    fn visible(&self, node: &Node, graph: &Graph) -> bool {
        if !self.scope.contains(&node.id) {
            return false;
        }
        if self.hidden.contains(&node.kind) {
            return false;
        }
        let text = format!(
            "{} {} {}",
            node.label,
            node.kind,
            serde_json::to_string(&node.properties).unwrap_or_default()
        )
        .to_lowercase();
        if !text.contains(&self.filter.to_lowercase()) {
            return false;
        }
        !self.neighborhood
            || self.selected.is_empty()
            || node.id == self.selected
            || graph.edges.iter().any(|edge| {
                edge.source == self.selected && edge.target == node.id
                    || edge.target == self.selected && edge.source == node.id
            })
    }

    pub fn show(&mut self, ui: &mut egui::Ui, busy: bool) -> bool {
        let compact = ui.available_width() < 820.0;
        if !self.full_screen {
            crate::workspace_hero(
                ui,
                "🕸",
                "Evidence Relationship Graph",
                "Interactive topological graph of discovered entities, connections, and evidence provenance.",
                Some(("TOPOLOGY", crate::theme::COLOR_INFO)),
            );
        }
        let mut refresh = false;
        crate::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                refresh = ui
                    .add_enabled(!busy, egui::Button::new("Refresh diagram"))
                    .clicked();
                if ui
                    .button(if self.full_screen {
                        "Exit full screen (Esc)"
                    } else {
                        "Full screen (F11)"
                    })
                    .clicked()
                {
                    self.full_screen = !self.full_screen;
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.full_screen));
                    self.fit = true;
                }
                if ui.button("Fit graph").clicked() {
                    self.fit = true;
                }
                if !compact && ui.button("Zoom in").clicked() {
                    self.zoom = (self.zoom * 1.25).clamp(0.05, 8.0);
                }
                if !compact && ui.button("Zoom out").clicked() {
                    self.zoom = (self.zoom / 1.25).clamp(0.05, 8.0);
                }
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                let zoom_pct = (self.zoom * 100.0).round() as u32;
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(16, 21, 30))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 48, 64)))
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(6, 2))
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(format!("Zoom: {zoom_pct}%"))
                                .monospace()
                                .size(11.0)
                                .color(egui::Color32::WHITE),
                        );
                    });
                ui.add_space(6.0);
                let legend = [
                    ("Query", egui::Color32::from_rgb(56, 189, 248)),
                    ("Person", egui::Color32::from_rgb(52, 211, 153)),
                    ("Domain", egui::Color32::from_rgb(167, 139, 250)),
                    ("Contact", egui::Color32::from_rgb(251, 191, 36)),
                    ("Page", egui::Color32::from_rgb(148, 163, 184)),
                ];
                for (label, color) in legend {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("●").size(10.0).color(color));
                        ui.label(egui::RichText::new(label).size(11.0).color(ui.visuals().weak_text_color()));
                    });
                    ui.add_space(4.0);
                }
            });
        });
        if !self.error.is_empty() {
            ui.colored_label(ui.visuals().error_fg_color, &self.error);
        }
        let Some(graph) = self.graph.take() else {
            ui.label(if busy {
                "Loading collected evidence…"
            } else {
                "No diagram loaded. Choose Refresh diagram to load collected evidence."
            });
            return refresh;
        };
        let previous = self.query.clone();
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_label("Research query")
                .selected_text(
                    graph
                        .nodes
                        .iter()
                        .find(|n| n.id == self.query)
                        .map_or("All saved searches", |n| n.label.as_str()),
                )
                .width(260.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.query, String::new(), "All saved searches");
                    for node in graph
                        .nodes
                        .iter()
                        .filter(|n| n.kind == "Query" && n.label != "FindAll workspace")
                    {
                        ui.selectable_value(&mut self.query, node.id.clone(), &node.label);
                    }
                });
            if !compact {
                ui.label(
                    egui::RichText::new("Matches are candidates, not verified identity links.")
                        .small()
                        .weak(),
                );
            }
        });
        if previous != self.query {
            self.arrange(&graph);
        }
        egui::CollapsingHeader::new("Filters and node selection")
            .id_salt(("diagram-filters", self.full_screen))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .hint_text("Filter labels and values")
                            .desired_width(210.0),
                    );
                    if !self.filter.is_empty() && ui.small_button("✖").on_hover_text("Clear filter").clicked() {
                        self.filter.clear();
                    }
                    if ui.button("Reset filters").clicked() {
                        self.filter.clear();
                        self.hidden.clear();
                        self.clear_path();
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    for kind in graph
                        .nodes
                        .iter()
                        .map(|node| &node.kind)
                        .collect::<BTreeSet<_>>()
                    {
                        let mut active = !self.hidden.contains(kind);
                        if ui.checkbox(&mut active, kind).changed() {
                            if active {
                                self.hidden.remove(kind);
                            } else {
                                self.hidden.insert(kind.clone());
                            }
                        }
                    }
                    ui.checkbox(&mut self.neighborhood, "Selected neighborhood");
                });
                egui::ComboBox::from_label("Select node")
                    .selected_text(
                        graph
                            .nodes
                            .iter()
                            .find(|n| n.id == self.selected)
                            .map_or("Choose a node", |n| n.label.as_str()),
                    )
                    .width(230.0)
                    .show_ui(ui, |ui| {
                        for node in graph
                            .nodes
                            .iter()
                            .filter(|n| self.visible(n, &graph))
                            .collect::<Vec<_>>()
                        {
                            ui.selectable_value(&mut self.selected, node.id.clone(), &node.label);
                        }
                    });
            });
        ui.label(
            egui::RichText::new("Solid: observed · Dashed: candidate · Dotted: interpretation")
                .small()
                .weak(),
        );
        if self.full_screen {
            self.canvas(ui, &graph);
            if !self.selected.is_empty() {
                egui::Window::new("Selected evidence")
                    .default_width(300.0)
                    .default_pos(ui.ctx().content_rect().right_top() + egui::vec2(-340.0, 150.0))
                    .show(ui.ctx(), |ui| self.inspect(ui, &graph, busy));
            }
        } else if ui.available_width() >= 820.0 {
            ui.horizontal_top(|ui| {
                let width = ui.available_width();
                ui.allocate_ui_with_layout(
                    egui::vec2(width - 296.0, 500.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| self.canvas(ui, &graph),
                );
                ui.allocate_ui_with_layout(
                    egui::vec2(280.0, 500.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| self.inspect(ui, &graph, busy),
                );
            });
        } else {
            self.canvas(ui, &graph);
            self.inspect(ui, &graph, busy);
        }
        self.graph = Some(graph);
        refresh
    }

    fn canvas(&mut self, ui: &mut egui::Ui, graph: &Graph) {
        let size = egui::vec2(
            ui.available_width(),
            (ui.clip_rect().bottom() - ui.cursor().top() - 34.0).max(100.0),
        );
        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click_and_drag());
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                egui::WidgetType::Button,
                true,
                "Evidence diagram canvas; use Select node for keyboard navigation",
            )
        });
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 8.0, ui.visuals().extreme_bg_color);
        {
            let dot_spacing = 28.0;
            let dot_color = egui::Color32::from_rgba_unmultiplied(86, 104, 128, 30);
            let offset_x = (self.pan.x % dot_spacing + dot_spacing) % dot_spacing;
            let offset_y = (self.pan.y % dot_spacing + dot_spacing) % dot_spacing;
            let mut x = rect.left() + offset_x;
            while x < rect.right() {
                let mut y = rect.top() + offset_y;
                while y < rect.bottom() {
                    painter.circle_filled(egui::pos2(x, y), 1.0, dot_color);
                    y += dot_spacing;
                }
                x += dot_spacing;
            }
        }
        if self.fit || (size - self.canvas_size).length_sq() > 1.0 {
            let extent = self
                .positions
                .iter()
                .filter(|(id, _)| {
                    graph
                        .nodes
                        .iter()
                        .any(|n| &n.id == *id && self.visible(n, graph))
                })
                .map(|(_, p)| p.x.abs().max(p.y.abs()))
                .fold(100.0, f32::max);
            self.zoom =
                ((rect.width().min(rect.height()) - 45.0) / (extent * 2.0)).clamp(0.05, 8.0);
            self.pan = Vec2::ZERO;
            self.fit = false;
        }
        self.canvas_size = size;
        if response.hovered() {
            let scroll = ui.input_mut(|i| {
                let delta = i.smooth_scroll_delta.y;
                i.smooth_scroll_delta.y = 0.0;
                delta
            });
            if scroll != 0.0 {
                let previous = self.zoom;
                self.zoom = (self.zoom * (scroll * 0.002).exp()).clamp(0.05, 8.0);
                if let Some(pointer) = response.hover_pos() {
                    self.pan = pointer
                        - rect.center()
                        - (pointer - rect.center() - self.pan) * (self.zoom / previous);
                }
            }
        }
        let visible: BTreeSet<_> = graph
            .nodes
            .iter()
            .filter(|n| self.visible(n, graph))
            .map(|n| n.id.as_str())
            .collect();
        let screen =
            |point: Pos2, zoom: f32, pan: Vec2| rect.center() + pan + point.to_vec2() * zoom;
        let hit = response.interact_pointer_pos().and_then(|pointer| {
            graph
                .nodes
                .iter()
                .filter(|n| visible.contains(n.id.as_str()))
                .filter_map(|node| {
                    self.positions.get(&node.id).map(|p| {
                        (
                            &node.id,
                            screen(*p, self.zoom, self.pan).distance_sq(pointer),
                        )
                    })
                })
                .filter(|(_, distance)| *distance < 144.0)
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(id, _)| id.clone())
        });
        if response.drag_started() {
            self.dragging = hit.clone();
        }
        if response.dragged() {
            let delta = response.drag_delta();
            if let Some(point) = self
                .dragging
                .as_ref()
                .and_then(|id| self.positions.get_mut(id))
            {
                *point += delta / self.zoom;
            } else {
                self.pan += delta;
            }
        }
        if response.drag_stopped() {
            self.dragging = None;
        }
        if response.clicked() {
            self.selected = hit.unwrap_or_default();
        }
        if response.has_focus() {
            let direction = ui.input(|i| {
                egui::vec2(
                    (i.key_down(egui::Key::ArrowRight) as u8 as f32)
                        - (i.key_down(egui::Key::ArrowLeft) as u8 as f32),
                    (i.key_down(egui::Key::ArrowDown) as u8 as f32)
                        - (i.key_down(egui::Key::ArrowUp) as u8 as f32),
                )
            });
            self.pan += direction * 5.0;
        }
        let mut relationships = 0;
        for edge in &graph.edges {
            if !visible.contains(edge.source.as_str()) || !visible.contains(edge.target.as_str()) {
                continue;
            }
            relationships += 1;
            let a = screen(self.positions[&edge.source], self.zoom, self.pan);
            let b = screen(self.positions[&edge.target], self.zoom, self.pan);
            let highlighted = self.path.contains(&edge.source) && self.path.contains(&edge.target);
            let active =
                highlighted || edge.source == self.selected || edge.target == self.selected;
            let color = if highlighted {
                ui.visuals().selection.bg_fill
            } else if edge.certainty == "candidate" {
                ui.visuals().warn_fg_color
            } else {
                ui.visuals().weak_text_color()
            };
            let color = if active {
                color
            } else {
                color.gamma_multiply(0.16)
            };
            let stroke = egui::Stroke::new(if active { 1.8 } else { 0.6 }, color);
            if edge.certainty == "observed" || highlighted {
                painter.line_segment([a, b], stroke);
            } else {
                let dash = if edge.certainty == "candidate" {
                    6.0
                } else {
                    2.0
                };
                let length = a.distance(b);
                let direction = (b - a).normalized();
                for index in 0..(length / (dash + 5.0)).ceil() as usize {
                    let offset = index as f32 * (dash + 5.0);
                    painter.line_segment(
                        [
                            a + direction * offset,
                            a + direction * (offset + dash).min(length),
                        ],
                        stroke,
                    );
                }
            }
        }
        let mut labels = Vec::<egui::Rect>::new();
        let mut displayed: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| visible.contains(n.id.as_str()))
            .collect();
        displayed.sort_by_key(|n| (n.id != self.selected, n.kind != "Query", n.kind != "Domain"));
        for node in displayed {
            let point = screen(self.positions[&node.id], self.zoom, self.pan);
            let node_color = match node.kind.to_lowercase().as_str() {
                "query" => egui::Color32::from_rgb(56, 189, 248),
                "person" | "contact" => egui::Color32::from_rgb(52, 211, 153),
                "domain" | "host" => egui::Color32::from_rgb(167, 139, 250),
                "email" | "phone" => egui::Color32::from_rgb(251, 191, 36),
                "page" => ui.visuals().weak_text_color(),
                _ => ui.visuals().hyperlink_color,
            };
            let radius = if node.kind == "Query" { 10.0 } else { 6.0 };
            if self.selected == node.id {
                painter.circle_filled(
                    point,
                    radius + 6.0,
                    node_color.gamma_multiply(0.28),
                );
                painter.circle_stroke(
                    point,
                    radius + 3.5,
                    egui::Stroke::new(1.8, egui::Color32::WHITE),
                );
            }
            painter.circle_filled(point, radius, node_color);
            if node.kind == "Query" {
                painter.circle_stroke(point, radius, egui::Stroke::new(1.2, egui::Color32::WHITE));
            }
            if self.selected == node.id || matches!(node.kind.as_str(), "Query" | "Domain") {
                let label: String = node.label.chars().take(42).collect();
                let right = point.x > rect.center().x;
                let galley = painter.layout_no_wrap(
                    label,
                    egui::FontId::proportional(12.0),
                    ui.visuals().text_color(),
                );
                let position = point
                    + egui::vec2(
                        if right { -13.0 - galley.size().x } else { 13.0 },
                        -10.0 - galley.size().y,
                    );
                let bounds = egui::Rect::from_min_size(position, galley.size());
                if self.selected == node.id
                    || (rect.contains_rect(bounds) && !labels.iter().any(|r| r.intersects(bounds)))
                {
                    painter.galley(position, galley, ui.visuals().text_color());
                    labels.push(bounds.expand(2.0));
                }
            }
        }
        ui.label(
            egui::RichText::new(format!(
                "{} of {} nodes · {relationships} relationships · Scroll to zoom · Drag to move",
                visible.len(),
                graph.nodes.len()
            ))
            .small()
            .weak(),
        );
    }

    fn inspect(&mut self, ui: &mut egui::Ui, graph: &Graph, busy: bool) {
        ui.set_max_width(ui.available_width());
        let Some(node) = graph.nodes.iter().find(|n| n.id == self.selected) else {
            ui.label("Select a node to inspect its sources, quotation and relationships.");
            return;
        };
        crate::card(ui, |ui| {
            let (color, icon) = match node.kind.as_str() {
                "Query" => (egui::Color32::from_rgb(56, 189, 248), "🎯"),
                "Person" => (egui::Color32::from_rgb(52, 211, 153), "👤"),
                "Domain" => (egui::Color32::from_rgb(167, 139, 250), "🌐"),
                "Contact" => (egui::Color32::from_rgb(251, 191, 36), "✉"),
                _ => (egui::Color32::from_rgb(148, 163, 184), "📑"),
            };
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(icon).size(15.0));
                ui.heading(&node.label);
            });
            ui.horizontal(|ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(20, 26, 38))
                    .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(6, 2))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(&node.kind).size(11.0).strong().color(color));
                    });
                if ui.small_button("📋 Copy label").clicked() {
                    ui.ctx().copy_text(node.label.clone());
                    ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Node label copied".to_owned()));
                }
                if let Some(val) = node.properties.get("value").and_then(|v| v.as_str()) {
                    if val != node.label && ui.small_button("📋 Copy value").clicked() {
                        ui.ctx().copy_text(val.to_owned());
                        ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Node value copied".to_owned()));
                    }
                }
            });
            let kind = crate::enrichment::node_kind(&node.kind);
            let options: Vec<_> = crate::enrichment::OPTIONS
                .iter()
                .enumerate()
                .filter(|(_, option)| option.1 == kind)
                .collect();
            if let Some((first, _)) = options.first() {
                if !options
                    .iter()
                    .any(|(index, _)| *index == self.enrichment_selection)
                {
                    self.enrichment_selection = *first;
                }
                egui::CollapsingHeader::new("Enrich selected entity").default_open(true).show(ui, |ui| {
                    egui::ComboBox::from_id_salt("selected-node-enricher")
                        .selected_text(crate::enrichment::OPTIONS[self.enrichment_selection].0)
                        .width(ui.available_width().min(270.0))
                        .show_ui(ui, |ui| {
                            for (index, option) in &options {
                                ui.selectable_value(&mut self.enrichment_selection, *index, option.0);
                            }
                        });
                    if ui.add_enabled(!busy, egui::Button::new("Run on selected node")).clicked() {
                        let value = node.properties.get("value").and_then(|v| v.as_str()).unwrap_or(&node.label);
                        self.pending_enrichment = Some(crate::enrichment::arguments(self.enrichment_selection, value, 20));
                    }
                    ui.label(egui::RichText::new("Selected entity only. New evidence joins this workspace; ownership remains unverified.").small().weak());
                });
            }
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                if ui.button("🚩 Set path start").clicked() {
                    self.path_start = node.id.clone();
                    self.path.clear();
                }
                if ui
                    .add_enabled(
                        !self.path_start.is_empty(),
                        egui::Button::new("⚡ Trace path"),
                    )
                    .clicked()
                {
                    self.path = connection_path(graph, &self.path_start, &node.id, &self.scope)
                        .into_iter()
                        .collect();
                }
                if ui
                    .button("✖ Clear path")
                    .on_hover_text("Clear the connection path and selected-node highlight")
                    .clicked()
                {
                    self.clear_path();
                }
            });
            if !self.path_start.is_empty() && self.path.is_empty() {
                ui.label(
                    "Select another node to inspect a path. Paths show evidence links, not ownership.",
                );
            }
            egui::ScrollArea::vertical()
                .id_salt("diagram-inspector")
                .max_height(420.0)
                .show(ui, |ui| {
                    for (key, value) in &node.properties {
                        ui.label(egui::RichText::new(key.replace('_', " ")).strong());
                        let text = value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value.to_string());
                        if key == "url" || key == "index_url" || key == "discovery_url" {
                            if text.starts_with("https://") || text.starts_with("http://") {
                                ui.hyperlink_to("Open source ↗", &text);
                            }
                        }
                        ui.add(egui::Label::new(text).wrap());
                    }
                    ui.separator();
                    ui.label(egui::RichText::new("Relationships and evidence").strong());
                    for edge in graph.edges.iter().filter(|e| {
                        (e.source == node.id || e.target == node.id)
                            && self.scope.contains(&e.source)
                            && self.scope.contains(&e.target)
                    }) {
                        let other = if edge.source == node.id {
                            &edge.target
                        } else {
                            &edge.source
                        };
                        let label = graph
                            .nodes
                            .iter()
                            .find(|n| &n.id == other)
                            .map_or(other.as_str(), |n| n.label.as_str());
                        if ui.selectable_label(false, label).clicked() {
                            self.selected = other.clone();
                        }
                        let (cert_icon, cert_color) = match edge.certainty.to_lowercase().as_str() {
                            "observed" => ("✓", crate::theme::COLOR_SUCCESS),
                            "candidate" => ("⚠", crate::theme::COLOR_WARN),
                            _ => ("ℹ", crate::theme::COLOR_INFO),
                        };
                        ui.horizontal_wrapped(|ui| {
                            egui::Frame::new()
                                .fill(egui::Color32::from_rgb(18, 24, 34))
                                .stroke(egui::Stroke::new(1.0, cert_color.gamma_multiply(0.4)))
                                .corner_radius(egui::CornerRadius::same(4))
                                .inner_margin(egui::Margin::symmetric(5, 1))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(format!("{cert_icon} {}", edge.certainty.to_uppercase())).size(9.5).color(cert_color).strong());
                                });
                            ui.label(egui::RichText::new(format!("{} · {}", edge.label, edge.kind)).small().color(ui.visuals().weak_text_color()));
                        });
                        for url in &edge.source_urls {
                            ui.horizontal_wrapped(|ui| {
                                if url.starts_with("http") {
                                    ui.hyperlink_to("Open source ↗", url);
                                }
                                if ui.small_button("📋 Copy URL").clicked() {
                                    ui.ctx().copy_text(url.clone());
                                    ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Source URL copied".to_owned()));
                                }
                            });
                        }
                        for hash in &edge.evidence_hashes {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(format!("SHA-256 {}", &hash[..hash.len().min(16)])).monospace().small().color(ui.visuals().weak_text_color()));
                                if ui.small_button("📋 Copy hash").clicked() {
                                    ui.ctx().copy_text(hash.clone());
                                    ui.data_mut(|d| d.insert_temp(egui::Id::new("toast_pending"), "Hash copied to clipboard".to_owned()));
                                }
                            });
                        }
                        ui.separator();
                    }
                });
        });
    }
    fn clear_path(&mut self) {
        self.path_start.clear();
        self.path.clear();
        self.selected.clear();
        self.neighborhood = false;
    }
}

fn query_scope(graph: &Graph, query: &str) -> BTreeSet<String> {
    if query.is_empty() {
        return graph.nodes.iter().map(|n| n.id.clone()).collect();
    }
    let mut ids = BTreeSet::from([query.to_owned()]);
    let mut pending = VecDeque::from([query.to_owned()]);
    while let Some(id) = pending.pop_front() {
        for edge in graph
            .edges
            .iter()
            .filter(|e| e.source == id && e.kind != "ResearchQuery")
        {
            if graph
                .nodes
                .iter()
                .any(|n| n.id == edge.target && n.kind != "Query")
                && ids.insert(edge.target.clone())
            {
                pending.push_back(edge.target.clone());
            }
        }
    }
    ids
}

fn connection_path(
    graph: &Graph,
    start: &str,
    end: &str,
    allowed: &BTreeSet<String>,
) -> Vec<String> {
    let mut parents = BTreeMap::from([(start.to_owned(), String::new())]);
    let mut pending = VecDeque::from([start.to_owned()]);
    while let Some(current) = pending.pop_front() {
        if current == end {
            let mut path = vec![current];
            while let Some(previous) = parents.get(path.last().unwrap()).filter(|p| !p.is_empty()) {
                path.push(previous.clone());
            }
            path.reverse();
            return path;
        }
        for edge in &graph.edges {
            let next = if edge.source == current {
                &edge.target
            } else if edge.target == current {
                &edge.source
            } else {
                continue;
            };
            if allowed.contains(next) && !parents.contains_key(next) {
                parents.insert(next.clone(), current.clone());
                pending.push_back(next.clone());
            }
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> String {
        format!(
            "<script id=\"graph-data\" type=\"application/json\">{}</script>",
            serde_json::json!({"nodes":[{"id":"q","kind":"Query","label":"Анна Ахматова"},{"id":"p","kind":"Page","label":"Poetry","properties":{"snippet":"Published quote"}},{"id":"d","kind":"Domain","label":"t.me"}],"edges":[{"source":"q","target":"p","kind":"SearchMatch","label":"query match","certainty":"candidate"},{"source":"p","target":"d","kind":"UrlHost","label":"URL host","certainty":"observed"}]})
        )
    }
    #[test]
    fn embedded_data_is_read_without_executing_html() {
        let graph = parse(&fixture()).unwrap();
        assert_eq!(graph.nodes[0].label, "Анна Ахматова");
        assert_eq!(graph.nodes[1].properties["snippet"], "Published quote");
        assert!(parse("<html>No graph</html>").is_err());
        assert!(parse(&fixture().replace("\"target\":\"d\"", "\"target\":\"missing\"")).is_err());
    }
    #[test]
    fn query_scope_does_not_cross_shared_domains_into_other_searches() {
        let mut graph = parse(&fixture()).unwrap();
        graph.nodes.push(Node {
            id: "other".into(),
            kind: "Query".into(),
            label: "Other search".into(),
            properties: BTreeMap::new(),
        });
        graph.edges.push(Edge {
            source: "other".into(),
            target: "d".into(),
            kind: "SearchMatch".into(),
            label: "candidate".into(),
            certainty: "candidate".into(),
            source_urls: vec![],
            evidence_hashes: vec![],
        });
        assert_eq!(
            query_scope(&graph, "q"),
            BTreeSet::from(["q".into(), "p".into(), "d".into()])
        );
        assert_eq!(query_scope(&graph, "").len(), 4);
        let mut workspace = Workspace::default();
        workspace.query = "q".into();
        workspace.arrange(&graph);
        assert_eq!(workspace.positions["q"], Pos2::ZERO);
        assert!(!workspace.positions.contains_key("other"));
    }
    #[test]
    fn clear_path_removes_selection_and_neighborhood_without_changing_evidence() {
        let graph = parse(&fixture()).unwrap();
        let mut workspace = Workspace::default();
        workspace.query = "q".into();
        workspace.arrange(&graph);
        workspace.graph = Some(graph);
        workspace.selected = "d".into();
        workspace.path_start = "q".into();
        workspace.path = BTreeSet::from(["q".into(), "p".into(), "d".into()]);
        workspace.neighborhood = true;
        let positions = workspace.positions.clone();
        let scope = workspace.scope.clone();
        workspace.clear_path();
        assert!(workspace.path_start.is_empty());
        assert!(workspace.path.is_empty());
        assert!(workspace.selected.is_empty());
        assert!(!workspace.neighborhood);
        assert_eq!(workspace.query, "q");
        assert_eq!(workspace.scope, scope);
        assert_eq!(workspace.positions, positions);
        assert_eq!(workspace.graph.as_ref().unwrap().nodes.len(), 3);
        assert_eq!(workspace.graph.as_ref().unwrap().edges.len(), 2);
    }
    #[test]
    fn inspector_does_not_offer_relationships_outside_selected_query() {
        let mut graph = parse(&fixture()).unwrap();
        graph.nodes.push(Node {
            id: "other".into(),
            kind: "Page".into(),
            label: "Unrelated saved result".into(),
            properties: BTreeMap::new(),
        });
        graph.edges.push(Edge {
            source: "other".into(),
            target: "d".into(),
            kind: "UrlHost".into(),
            label: "URL host".into(),
            certainty: "observed".into(),
            source_urls: vec![],
            evidence_hashes: vec![],
        });
        let mut workspace = Workspace {
            scope: query_scope(&graph, "q"),
            selected: "d".into(),
            ..Default::default()
        };
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            workspace.inspect(ui, &graph, false)
        });
        output.textures_delta.clear();
        let text: String = output
            .shapes
            .iter()
            .filter_map(|s| match &s.shape {
                egui::Shape::Text(t) => Some(t.galley.job.text.as_str()),
                _ => None,
            })
            .collect();
        assert!(text.contains("Poetry"));
        assert!(!text.contains("Unrelated saved result"));
        workspace.scope = query_scope(&graph, "");
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            workspace.inspect(ui, &graph, false)
        });
        output.textures_delta.clear();
        assert!(output.shapes.iter().any(|s| match &s.shape {
            egui::Shape::Text(t) => t.galley.job.text.contains("Unrelated saved result"),
            _ => false,
        }));
    }
    #[test]
    fn path_and_filters_preserve_evidence_semantics() {
        let graph = parse(&fixture()).unwrap();
        assert_eq!(
            connection_path(&graph, "q", "d", &query_scope(&graph, "q")),
            vec!["q", "p", "d"]
        );
        assert!(connection_path(&graph, "q", "missing", &query_scope(&graph, "q")).is_empty());
        let mut workspace = Workspace::default();
        workspace.scope = query_scope(&graph, "q");
        workspace.filter = "published quote".into();
        assert!(workspace.visible(&graph.nodes[1], &graph));
        assert!(!workspace.visible(&graph.nodes[0], &graph));
        workspace.hidden.insert("Page".into());
        assert!(!workspace.visible(&graph.nodes[1], &graph));
    }
}
