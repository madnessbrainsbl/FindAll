use eframe::egui::{self, Color32, Stroke};

pub const CONTENT_WIDTH: f32 = 1040.0;
pub const SIDEBAR_BREAKPOINT: f32 = 1000.0;
pub const SIDEBAR_WIDTH: f32 = 208.0;
pub const GUTTER: i8 = 24;
pub const CARD_PADDING: i8 = 20;
pub const CONTROL_HEIGHT: f32 = 36.0;
pub const ACTION_HEIGHT: f32 = 42.0;
pub const BODY_SIZE: f32 = 15.0;
pub const HEADING_SIZE: f32 = 28.0;
pub const SMALL_SIZE: f32 = 13.0;

#[allow(dead_code)]
pub const COLOR_SUCCESS: Color32 = Color32::from_rgb(52, 211, 153);
#[allow(dead_code)]
pub const COLOR_WARN: Color32 = Color32::from_rgb(251, 191, 36);
#[allow(dead_code)]
pub const COLOR_ERROR: Color32 = Color32::from_rgb(248, 113, 113);
#[allow(dead_code)]
pub const COLOR_INFO: Color32 = Color32::from_rgb(56, 189, 248);
#[allow(dead_code)]
pub const COLOR_ACCENT: Color32 = Color32::from_rgb(167, 139, 250);
#[allow(dead_code)]
pub const BORDER_CARD: Color32 = Color32::from_rgb(34, 42, 58);
#[allow(dead_code)]
pub const BG_CARD: Color32 = Color32::from_rgb(18, 22, 32);
#[allow(dead_code)]
pub const BG_ACTIVE_PILL: Color32 = Color32::from_rgb(24, 32, 48);

pub fn visuals() -> egui::Visuals {
    let mut v = egui::Visuals::dark();
    let (page, surface, input, hover, text, muted, border, accent, on_accent, link) = (
        Color32::from_rgb(12, 15, 22),       // Deep obsidian canvas #0c0f16
        Color32::from_rgb(20, 25, 36),       // Surface cards & panels #141924
        Color32::from_rgb(16, 20, 30),       // Input fields #10141e
        Color32::from_rgb(32, 40, 58),       // Hover highlight #20283a
        Color32::from_rgb(241, 245, 249),     // Primary crisp text #f1f5f9
        Color32::from_rgb(156, 171, 192),     // Muted secondary text #9cb0c0
        Color32::from_rgb(86, 104, 128),      // Hairline border #566880 (passes 3.0 contrast)
        Color32::from_rgb(56, 189, 248),      // Electric cyan / intel accent #38bdf8
        Color32::from_rgb(12, 18, 28),        // Deep contrast text on accent #0c121c
        Color32::from_rgb(56, 189, 248),      // Hyperlink & interactive cyan #38bdf8
    );
    v.panel_fill = page;
    v.window_fill = surface;
    v.faint_bg_color = surface;
    v.extreme_bg_color = input;
    v.code_bg_color = input;
    v.override_text_color = None;
    v.weak_text_color = Some(muted);
    v.hyperlink_color = link;
    v.selection.bg_fill = accent;
    v.selection.stroke = Stroke::new(1.0, on_accent);
    v.widgets.noninteractive.bg_fill = surface;
    v.widgets.noninteractive.weak_bg_fill = surface;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, text);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, hover);
    v.widgets.inactive.bg_fill = input;
    v.widgets.inactive.weak_bg_fill = surface;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, text);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, border);
    v.widgets.hovered.bg_fill = hover;
    v.widgets.hovered.weak_bg_fill = hover;
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, text);
    v.widgets.hovered.bg_stroke = Stroke::new(1.5, link);
    // egui also uses the active foreground for strong labels.
    v.widgets.active.bg_fill = hover;
    v.widgets.active.weak_bg_fill = hover;
    v.widgets.active.fg_stroke = Stroke::new(1.0, text);
    v.widgets.active.bg_stroke = Stroke::new(2.0, link);
    for widget in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::same(6);
    }
    v
}

pub fn install(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.set_visuals(visuals());
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (
                egui::TextStyle::Heading,
                egui::FontId::proportional(HEADING_SIZE),
            ),
            (egui::TextStyle::Body, egui::FontId::proportional(BODY_SIZE)),
            (
                egui::TextStyle::Button,
                egui::FontId::proportional(BODY_SIZE),
            ),
            (egui::TextStyle::Monospace, egui::FontId::monospace(14.0)),
            (
                egui::TextStyle::Small,
                egui::FontId::proportional(SMALL_SIZE),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.interact_size.y = CONTROL_HEIGHT;
        style.spacing.button_padding = egui::vec2(12.0, 8.0);
        style.spacing.scroll = egui::style::ScrollStyle::solid();
        style.animation_time = 0.0;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrast(a: Color32, b: Color32) -> f32 {
        let luminance = |color: Color32| {
            let rgb = [color.r(), color.g(), color.b()].map(|c| {
                let c = f32::from(c) / 255.0;
                if c <= 0.04045 {
                    c / 12.92
                } else {
                    ((c + 0.055) / 1.055).powf(2.4)
                }
            });
            rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722
        };
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    #[test]
    fn theme_has_readable_text_actions_and_controls() {
        let v = visuals();
        for bg in [
            v.panel_fill,
            v.faint_bg_color,
            v.extreme_bg_color,
            v.widgets.hovered.bg_fill,
        ] {
            for fg in [
                v.text_color(),
                v.strong_text_color(),
                v.weak_text_color(),
                v.hyperlink_color,
            ] {
                let ratio = contrast(fg, bg);
                assert!(ratio >= 4.5, "text contrast={ratio}");
            }
        }
        assert!(contrast(v.selection.stroke.color, v.selection.bg_fill) >= 4.5);
        assert!(contrast(v.widgets.inactive.bg_stroke.color, v.extreme_bg_color) >= 3.0);
        for widget in [v.widgets.inactive, v.widgets.hovered, v.widgets.active] {
            assert!(contrast(widget.fg_stroke.color, widget.bg_fill) >= 4.5);
        }
    }

    #[test]
    fn install_forces_the_product_theme() {
        let ctx = egui::Context::default();
        ctx.set_theme(egui::Theme::Light);
        install(&ctx);
        assert_eq!(ctx.theme(), egui::Theme::Dark);
        assert_eq!(
            ctx.style_of(egui::Theme::Dark).visuals.panel_fill,
            visuals().panel_fill
        );
    }
}
