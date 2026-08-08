use super::*;

pub(super) fn next_scope(scope: DirectionScope) -> DirectionScope {
    match scope {
        DirectionScope::Downstream => DirectionScope::Upstream,
        DirectionScope::Upstream => DirectionScope::Both,
        DirectionScope::Both => DirectionScope::Downstream,
    }
}

pub(super) fn parse_mib_number(value: &str) -> Option<u16> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

pub(super) fn move_identity<T: Copy + PartialEq>(
    current: Option<T>,
    rows: &[T],
    delta: isize,
) -> Option<T> {
    if rows.is_empty() {
        return None;
    }
    let current_index = current
        .and_then(|value| rows.iter().position(|candidate| *candidate == value))
        .unwrap_or(if delta < 0 { rows.len() - 1 } else { 0 });
    let next = if delta < 0 {
        current_index.saturating_sub(delta.unsigned_abs())
    } else {
        current_index
            .saturating_add(delta as usize)
            .min(rows.len() - 1)
    };
    rows.get(next).copied()
}

pub(super) fn mib_pane_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

pub(super) fn sample_count(
    sample: Option<&SampleView>,
    value: impl Fn(&FlowCounters) -> u64,
) -> String {
    sample
        .map(|sample| value(&sample.counters).to_string())
        .unwrap_or_else(|| "warmup".into())
}

pub(super) fn sample_bytes(
    sample: Option<&SampleView>,
    value: impl Fn(&FlowCounters) -> u64,
) -> String {
    sample
        .map(|sample| human_bytes(value(&sample.counters) as f64))
        .unwrap_or_else(|| "warmup".into())
}

pub(super) fn sample_state(pane: Pane, sample: Option<&SampleView>) -> &'static str {
    match sample {
        None => "warmup",
        Some(sample) if direction_active(pane, &sample.counters) => "active",
        Some(_) => "idle",
    }
}

pub(super) fn activity_matches(
    filter: ActivityFilter,
    pane: Pane,
    sample: Option<&SampleView>,
) -> bool {
    match filter {
        ActivityFilter::All => true,
        ActivityFilter::Active => {
            sample.is_some_and(|sample| direction_active(pane, &sample.counters))
        }
        ActivityFilter::Idle => {
            sample.is_some_and(|sample| !direction_active(pane, &sample.counters))
        }
    }
}

pub(super) fn reconcile_filtered_selection(
    selected: Option<u8>,
    all: &[u8],
    visible: &BTreeSet<u8>,
    initialize: bool,
) -> Option<u8> {
    let Some(selected) = selected else {
        return initialize
            .then(|| all.iter().copied().find(|id| visible.contains(id)))
            .flatten();
    };
    let position = all.iter().position(|id| *id == selected)?;
    if visible.contains(&selected) {
        return Some(selected);
    }
    all[position + 1..]
        .iter()
        .copied()
        .find(|id| visible.contains(id))
        .or_else(|| {
            all[..position]
                .iter()
                .rev()
                .copied()
                .find(|id| visible.contains(id))
        })
}

pub(super) fn direction_active(pane: Pane, counters: &FlowCounters) -> bool {
    match pane {
        Pane::Downstream => {
            counters.ds_gem_packets != 0
                || counters.ds_gem_bytes != 0
                || counters.ds_rx_eth_packets != 0
                || counters.ds_fwd_eth_packets != 0
        }
        Pane::Upstream => {
            counters.us_gem_packets != 0
                || counters.us_gem_bytes != 0
                || counters.us_eth_packets != 0
        }
    }
}

pub(super) fn sample_rate(
    sample: Option<&SampleView>,
    value: impl Fn(&FlowCounters) -> u64,
) -> String {
    let Some(sample) = sample else {
        return "—".into();
    };
    let Some(interval) = sample.interval else {
        return "warmup".into();
    };
    if interval.is_zero() {
        return "—".into();
    }
    human_rate(value(&sample.counters) as f64 / interval.as_secs_f64())
}

pub(super) fn sample_age(sample: Option<&SampleView>) -> String {
    sample
        .map(|sample| format!("{}s", sample.sampled_at.elapsed().as_secs()))
        .unwrap_or_else(|| "—".into())
}

pub(super) fn human_rate(bytes_per_second: f64) -> String {
    if bytes_per_second >= 1_000_000.0 {
        format!("{:.1}M", bytes_per_second / 1_000_000.0)
    } else if bytes_per_second >= 1_000.0 {
        format!("{:.1}K", bytes_per_second / 1_000.0)
    } else {
        format!("{bytes_per_second:.0}")
    }
}

pub(super) fn human_bytes(bytes: f64) -> String {
    if bytes >= 1_000_000.0 {
        format!("{:.1}M", bytes / 1_000_000.0)
    } else if bytes >= 1_000.0 {
        format!("{:.1}K", bytes / 1_000.0)
    } else {
        format!("{bytes:.0}")
    }
}

pub(super) fn format_optional(value: Option<u16>) -> String {
    value.map_or_else(|| "—".into(), |value| value.to_string())
}

pub(super) fn format_power(value: Option<f32>) -> String {
    value.map_or_else(|| "N/A".into(), |value| format!("{value:.2} dBm"))
}

pub(super) fn system_time_age(time: SystemTime) -> String {
    match SystemTime::now().duration_since(time) {
        Ok(age) if age.as_secs() < 2 => "just now".into(),
        Ok(age) => format!("{}s ago", age.as_secs()),
        Err(_) => "clock changed".into(),
    }
}

pub(super) fn render_connection(frame: &mut ratatui::Frame, form: &ConnectionForm) {
    let area = centered_rect(64, 22, frame.area());
    frame.render_widget(Clear, area);
    let title = if form.connecting {
        " Connecting… "
    } else {
        " Connect to ONU "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);
    let fields = form.fields();
    let rows =
        fields
            .iter()
            .enumerate()
            .filter(|(index, _)| form.visible(*index))
            .map(|(index, (label, value))| {
                let marker = if index == form.focused { "▶" } else { " " };
                let style = if index == form.focused {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                Line::from(vec![
                    Span::styled(format!("{marker} {label:<18}"), style),
                    Span::styled(value.clone(), style.add_modifier(Modifier::BOLD)),
                ])
            })
            .chain(std::iter::once(Line::from("")))
            .chain(std::iter::once(Line::from(
                "Tab/↑/↓ fields  Space/←/→ choices  Enter connect",
            )))
            .chain(form.error.as_ref().map(|error| {
                Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red)))
            }))
            .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(rows).wrap(Wrap { trim: true }), inner);
}

pub(super) fn render_add_modal(frame: &mut ratatui::Frame, modal: &AddModal) {
    let area = centered_rect(66, 18, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Add flow ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);
    let fields = [
        ("Direction", modal.scope.to_string()),
        ("GEM port(s)", modal.gem_ports.clone()),
        ("Flow ID", modal.flow_id.clone()),
        ("Type", modal.flow_type.to_string()),
        ("Multicast (DS)", yes_no(modal.multicast).into()),
        ("AES (DS)", yes_no(modal.aes).into()),
    ];
    let mut lines = fields
        .iter()
        .enumerate()
        .map(|(index, (label, value))| {
            let marker = if index == modal.focused { "▶" } else { " " };
            let style = if index == modal.focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{marker} {label:<18}"), style),
                Span::styled(value.clone(), style.add_modifier(Modifier::BOLD)),
            ])
        })
        .collect::<Vec<_>>();
    lines.push(Line::from(""));
    lines.push(Line::from(
        "GEM accepts 1-5,8. Flow ID is `auto` or one exact ID.",
    ));
    lines.push(Line::from(
        "Tab fields  Space choices  Enter add  Esc cancel",
    ));
    if let Some(error) = &modal.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

pub(super) fn render_search(frame: &mut ratatui::Frame, search: &GemSearch) {
    let area = centered_rect(56, 9, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Find GEM port ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);
    let mut lines = vec![
        Line::from(vec![
            Span::raw("GEM port: "),
            Span::styled(
                format!("{}_", search.query),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from("Enter jump  Esc cancel"),
    ];
    if let Some(error) = &search.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

pub(super) fn render_mib_input(frame: &mut ratatui::Frame, input: &MibInput) {
    let (title, hint) = match input.kind {
        MibInputKind::Lookup => (
            " Direct MIB lookup ",
            "Table name or OMCI class ID, optionally followed by entity ID: 256,0x0000",
        ),
        MibInputKind::Search(MibPane::Tables) => (
            " Filter MIB tables ",
            "Case-insensitive table-name or Realtek index substring; empty clears",
        ),
        MibInputKind::Search(MibPane::Entities) => (
            " Jump to entity ",
            "Decimal or 0x-prefixed hexadecimal entity ID",
        ),
        MibInputKind::Search(MibPane::Attributes) => (
            " Filter attributes ",
            "Case-insensitive attribute name or value substring; empty clears",
        ),
    };
    let area = centered_rect(76, 9, frame.area());
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(hint),
        Line::from(""),
        Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Yellow)),
            Span::raw(input.value.as_str()),
        ]),
    ];
    if let Some(error) = &input.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.as_str(),
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from("Enter apply  Esc cancel"));
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

pub(super) fn render_export(frame: &mut ratatui::Frame, export: &ExportModal) {
    let area = centered_rect(76, 10, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Export autoscan JSON ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Path: "),
            Span::styled(
                format!("{}_", export.path),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from("Enter export  Esc cancel  Existing files are never overwritten."),
    ];
    if let Some(error) = &export.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

pub(super) fn render_capture_modal(frame: &mut ratatui::Frame, modal: &CaptureModal) {
    let area = centered_rect(84, 18, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Start capture ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);

    let interface = modal
        .current_interface()
        .map(|interface| {
            // Addresses are how you tell which NIC faces the ONU.
            match interface.addresses.first() {
                Some(address) => format!("{}  ({address})", interface.label()),
                None => interface.label(),
            }
        })
        .unwrap_or_else(|| "none available".into());
    let parsed_duration = modal.parsed_duration();
    let duration = match parsed_duration {
        Ok(Some(duration)) => clock(duration),
        Ok(None) => "until stopped".into(),
        Err(_) => "invalid".into(),
    };
    let fields = [
        ("Interface", interface),
        ("Directory", modal.directory.clone()),
        ("Duration", format!("{} s  ({duration})", modal.duration)),
        (
            "Filter",
            if modal.filter.trim().is_empty() {
                "none".into()
            } else {
                modal.filter.clone()
            },
        ),
    ];
    let mut lines: Vec<Line> = fields
        .into_iter()
        .enumerate()
        .map(|(index, (label, value))| {
            let marker = if index == modal.focused { "▶" } else { " " };
            let style = if index == modal.focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{marker} {label:<18}"), style),
                Span::styled(value, style.add_modifier(Modifier::BOLD)),
            ])
        })
        .collect();

    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Downstream flows configured: {}",
        modal.configured_flows
    )));
    match modal.rate {
        Some(rate) if rate.packets_per_second <= 0.0 => lines.push(Line::from(Span::styled(
            "Forwarded rate is zero — listen-all may not be applied, so this \
             capture would record almost nothing.",
            Style::default().fg(Color::Red),
        ))),
        Some(rate) => lines.push(Line::from(format!(
            "Forwarded: {:.0} packets/s, {} average frame",
            rate.packets_per_second, rate.average_frame as u64
        ))),
        None => lines.push(Line::from(
            "No counter samples yet — size cannot be estimated.",
        )),
    }
    lines.push(Line::from(
        match modal.estimate(parsed_duration.unwrap_or_default()) {
            Some(bytes) => format!("Estimated size: {}", human_bytes(bytes as f64)),
            None => "Estimated size: unknown".into(),
        },
    ));
    lines.push(Line::from(match modal.free_space {
        Some(free) => format!("Free space: {}", human_bytes(free as f64)),
        None => "Free space: unknown".into(),
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(
        "Enter start  Esc cancel  Tab field  ←/→ interface  * show all interfaces",
    ));
    if let Some(error) = &modal.error {
        lines.push(Line::from(Span::styled(
            error.clone(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

/// `mm:ss`, or `h:mm:ss` past an hour.
pub(super) fn clock(duration: Duration) -> String {
    let total = duration.as_secs();
    let (hours, minutes, seconds) = (total / 3600, (total % 3600) / 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

/// Write JSON to a path that must not already exist. Captures and autoscan
/// exports both rely on never silently overwriting an earlier result.
pub(super) fn write_json_new(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(file, value).map_err(io::Error::other)
}

pub(super) fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(super) fn render_confirm(frame: &mut ratatui::Frame, action: &ConfirmAction) {
    let area = centered_rect(64, 9, frame.area());
    frame.render_widget(Clear, area);
    let (message, hint) = match action {
        ConfirmAction::DeleteOne { scope, flow_id } => (
            format!("Delete {scope} flow {flow_id}?"),
            "Enter/y confirm  Esc/n cancel".to_owned(),
        ),
        ConfirmAction::DeleteAll { scope } => (
            format!("Delete ALL {scope} flows?"),
            "s/←/→ scope  Enter/y confirm  Esc/n cancel".to_owned(),
        ),
        ConfirmAction::Setup => (
            "Apply the 12 listen-all capture setup commands?".into(),
            "This changes forwarding, CRC, VLAN and laser settings. Enter/y confirm  Esc/n cancel"
                .into(),
        ),
        ConfirmAction::StartScan(config) => (
            format!(
                "Start destructive autoscan of GEM {}–{} in {} batches?",
                config.gem_start,
                config.gem_end,
                config.total_batches()
            ),
            "The downstream table is temporarily replaced. Recovery is memory-only. Enter/y confirm  Esc/n cancel".into(),
        ),
        ConfirmAction::ApplyActive(gems) => (
            format!(
                "Add {} missing active GEM port{} as downstream Ethernet flow{}?",
                gems.len(),
                if gems.len() == 1 { "" } else { "s" },
                if gems.len() == 1 { "" } else { "s" }
            ),
            "Uses the scan AES setting and lowest free flow IDs. Enter/y confirm  Esc/n cancel"
                .into(),
        ),
        ConfirmAction::AbandonRecovery => (
            "ABANDON restoration of the original downstream table?".into(),
            "The current device configuration may be temporary or incomplete. Enter/y confirms abandonment; Esc/n retries safely later.".into(),
        ),
    };
    let block = Block::default()
        .title(" Confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(area).inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                message,
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(hint),
        ])
        .wrap(Wrap { trim: true }),
        inner,
    );
}

pub(super) fn render_help(frame: &mut ratatui::Frame) {
    let area = centered_rect(76, 20, frame.area());
    frame.render_widget(Clear, area);
    let text = vec![
        Line::from("Navigation").style(Style::default().fg(Color::Cyan)),
        Line::from("  Tab/←/→ switch flow direction; ↑/↓ select a flow"),
        Line::from(""),
        Line::from("Actions").style(Style::default().fg(Color::Cyan)),
        Line::from("  r refresh line and flow configuration (does not read counters)"),
        Line::from("  f cycle all/active/idle; / jump to a GEM port"),
        Line::from("  a add flow(s); d delete selected; D delete all"),
        Line::from("  l apply listen-all setup; c connect/switch backend"),
        Line::from("  p pause/resume destructive counter sampling; e event log"),
        Line::from("  Mouse wheel moves the selected row under the pointer"),
        Line::from("  1 Monitor; 2 Autoscan; 3 read-only OMCI MIB explorer."),
        Line::from("  MIB: Enter loads, Tab changes pane, / filters/jumps, g direct lookup,"),
        Line::from("       r refreshes the table, R refreshes catalog, v shows raw output."),
        Line::from("  Ctrl+R starts a capture from any page and stops one already running."),
        Line::from(""),
        Line::from("Capture writes a pcapng plus a JSON sidecar recording the downstream"),
        Line::from("flow table, because no captured frame identifies its GEM port."),
        Line::from(""),
        Line::from("Traffic counters reset when read. Rates are interval estimates and"),
        Line::from("can undercount if another process also reads the device counters."),
        Line::from("Live optical RX/TX power is unavailable in v1."),
        Line::from(""),
        Line::from("Press ? or Esc to close."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Help ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

pub(super) fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}
