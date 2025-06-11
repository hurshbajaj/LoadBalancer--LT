use std::{sync::{atomic::{AtomicU64, Ordering}, Arc}, time::{Duration, Instant}};

use chrono::{Local, NaiveDateTime, TimeZone};
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use once_cell::sync::Lazy;
use ratatui::{
    layout::{Constraint, Layout}, style::{Style, Stylize}, symbols, text::Line, widgets::{Axis, Block, Borders, Chart, Dataset, List, ListItem, Paragraph}, DefaultTerminal, Frame
};
use tokio::sync::RwLock;

pub static reqs: Lazy<Arc<RwLock<u64>>> = Lazy::new(|| Arc::new(RwLock::new(0u64)));

pub static server_names: Lazy<Arc<RwLock<Vec<String>>>> = Lazy::new(|| Arc::new(RwLock::new(vec![])));
pub static server_rts: Lazy<Arc<RwLock<Vec<String>>>> = Lazy::new(|| Arc::new(RwLock::new(vec![])));
pub static server_is_actives: Lazy<Arc<RwLock<Vec<bool>>>> = Lazy::new(|| Arc::new(RwLock::new(vec![])));

pub static total: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0u64)));
pub static total_bad: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0u64)));
pub static total_ddos_a: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0u64)));

pub static blocked_ips: Lazy<Arc<RwLock<Vec<String>>>> = Lazy::new(|| Arc::new(RwLock::new(vec![])));
static rps_ema: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0u64)));
static rps: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0u64)));
static rpsc: Lazy<Arc<RwLock<Vec<u64>>>> = Lazy::new(|| Arc::new(RwLock::new(vec![])));

pub async fn establish() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let result = App::new().run(terminal).await;
    ratatui::restore();
    result
}

#[derive(Debug, Default)]
pub struct App {
    running: bool,
    req_chart_vals: Vec<(f64, f64)>,
    screen: u64,

    selected: usize,
    server_names: Vec<String>,
    server_rts: Vec<String>,
    server_is_actives: Vec<bool>,

    total: AtomicU64,
    total_bad: AtomicU64,
    total_ddos_a: AtomicU64,

    blocked_ips: Vec<String>,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: 0,
            running: true,
            req_chart_vals: vec![],

            selected: 0,
            server_names: vec![],
            server_rts: vec![],
            server_is_actives: vec![],

            total: AtomicU64::new(0u64),
            total_bad: AtomicU64::new(0u64),
            total_ddos_a: AtomicU64::new(0u64),

            blocked_ips: vec![],
        }
    }

    pub async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        self.running = true;
        let mut timer = 0f64;

        while self.running {
            let start = Instant::now();
            terminal.draw(|frame| self.render(frame))?;
            self.handle_crossterm_events()?;

            timer += start.elapsed().as_secs_f64();
            if timer >= 1.0 {
                let now = chrono::Local::now().timestamp_millis() as f64;
                self.req_chart_vals.push((now, *(reqs.clone().read().await) as f64));
                if self.req_chart_vals.len() > 5{
                    self.req_chart_vals.remove(0);
                }

                let mut Rpsc = {
                    let mut g = rpsc.write().await;
                    g.clone()
                };

                // Retain only last 60 seconds of data
                self.req_chart_vals.retain(|(ts, _)| now - *ts <= 60_000.0);

                let mut Reqs = reqs.write().await;
                rps_ema.store((rps_ema.load(Ordering::SeqCst) + *Reqs) / 2, Ordering::SeqCst);
                Rpsc.push(*Reqs);
                if Rpsc.len() > 100{
                    Rpsc.remove(0);
                }

                *Reqs = 0u64;

                //-----------------------------------------------------------------
                
                self.server_names = (server_names.read().await).clone();
                self.server_rts = (server_rts.read().await).clone();
                self.server_is_actives = (server_is_actives.read().await).clone();

                timer -= 1.0;
    
                //-----------------------------------------------------------------

                self.total.store(total.load(Ordering::SeqCst), Ordering::SeqCst);
                self.total_bad.store(total_bad.load(Ordering::SeqCst), Ordering::SeqCst);
                self.total_ddos_a.store(total_ddos_a.load(Ordering::SeqCst), Ordering::SeqCst);

                //-----------------------------------------------------------------

                self.blocked_ips = (blocked_ips.read().await).clone();

                rps.store((Rpsc.iter().sum::<u64>() / Rpsc.len() as u64)as u64, Ordering::SeqCst);

            }
        }
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        let [graph_sect, metric_sect] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).areas(frame.area());
        let [server_sect, other_sect] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).areas(metric_sect);

        let x_min = self.req_chart_vals.first().map(|(x, _)| *x).unwrap_or(0.0);
        let x_max = self.req_chart_vals.last().map(|(x, _)| *x).unwrap_or(1.0);

        let y_min = self.req_chart_vals
            .iter()
            .map(|(_, y)| *y)
            .fold(f64::INFINITY, f64::min)
            .min(0.0); 

        let y_max = self.req_chart_vals
            .iter()
            .map(|(_, y)| *y)
            .fold(f64::NEG_INFINITY, f64::max)
            .max(1.0); 

        let chart = Chart::new(vec![
                Dataset::default()
                    .marker(symbols::Marker::Braille)
                    .graph_type(ratatui::widgets::GraphType::Line)
                    .style(Style::default().fg(ratatui::style::Color::Gray))
                    .data(&self.req_chart_vals)
            ])
            .block(Block::bordered().title("Requests/s"))
            .x_axis(
                Axis::default()
                    .title("Time")
                    .bounds([x_min, x_max])
                    .labels(self.req_chart_vals.iter().map(|x| ms_since_epoch_to_hms(x.0 as i64)).collect::<Vec<_>>()),
            )
            .y_axis(
                Axis::default()
                    .title("Requests")
                    .bounds([y_min, y_max])
                    .labels(generate_y_labels(y_min, y_max, 4)),
            );

        frame.render_widget(chart, graph_sect);

        let height = server_sect.height as usize - 2; // account for borders
        let start:&usize = &self.selected.saturating_sub(height.saturating_sub(1));
        let end: &usize = &((start + height).min((&self).server_names.len().clone()));
        let visible_names: Vec<_> = (&self).server_names[*start..*end]
            .iter()
            .map(|i| ListItem::new(i.clone()))
            .collect();

        let list = List::new(visible_names)
            .block(Block::default().borders(Borders::ALL).title("Servers"));

        let visible_server_rts: Vec<_> = (&self).server_rts[*start..*end]
            .iter()
            .map(|i| ListItem::new(i.clone()))
            .collect();

        let list_rts = List::new(visible_server_rts)
            .block(Block::default().borders(Borders::ALL).title("Avg Res Time"));

        let visible_server_ias: Vec<_> = (&self).server_is_actives[*start..*end]
            .iter()
            .map(|i| ListItem::new(i.to_string().clone()))
            .collect();

        let list_as = List::new(visible_server_ias)
            .block(Block::default().borders(Borders::ALL).title("Active"));

        let total_l = Paragraph::new(Line::from((&self).total.load(Ordering::SeqCst).to_string()))
            .block(Block::default().title("Total Reqs").borders(Borders::ALL));

        let total_bad_l = Paragraph::new(Line::from(format!("{} (%)", (( (&self).total_bad.load(Ordering::SeqCst) / (&self).total.load(Ordering::SeqCst).max(1) * 100)).to_string())))
            .block(Block::default().title("% of Bad Requests").borders(Borders::ALL));


        let total_ddos_al = Paragraph::new(Line::from(format!("{}", (&self).total_ddos_a.load(Ordering::SeqCst).to_string())))
            .block(Block::default().title("DDoS Attempts").borders(Borders::ALL));

        let height_bl = server_sect.height as usize - 2; // account for borders
        let start_bl:&usize = &self.selected.saturating_sub(height.saturating_sub(1));
        let end_bl: &usize = &((start + height).min((&self).blocked_ips.len().clone()));
        let visible_bl_items: Vec<_> = (&self).blocked_ips[*start_bl..*end_bl]
            .iter()
            .map(|i| ListItem::new(i.clone()))
            .collect();

        let list_bl = List::new(visible_bl_items)
            .block(Block::default().borders(Borders::ALL).title("Banned IP's"));

        if (&self).screen.clone() == 0u64{

            let [server_name_sect, server_avg_rt_sect, server_active_sect] = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1), Constraint::Fill(1)]).areas(server_sect);
            let [Total_req_sect, bad_req_sect, ddos_attempt_sect] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1), Constraint::Fill(1)]).areas(other_sect);

            frame.render_widget(list, server_name_sect);

            frame.render_widget(list_as, server_active_sect);

            frame.render_widget(total_l, Total_req_sect);

            frame.render_widget(total_ddos_al, ddos_attempt_sect);

            frame.render_widget(list_rts, server_avg_rt_sect);

            frame.render_widget(total_bad_l, bad_req_sect);

        }else{

            let [rps_ema_sect, rps_sect] = Layout::vertical([Constraint::Fill(1), Constraint::Fill(1)]).areas(other_sect);

            frame.render_widget(list_bl, server_sect);
            frame.render_widget(Paragraph::new(Line::from(format!("{} requests/s", rps.load(Ordering::SeqCst).to_string())))
                .block(Block::default().title("RPS Avg").borders(Borders::ALL)), rps_sect);
            frame.render_widget(Paragraph::new(Line::from(format!("{} requests/s", rps_ema.load(Ordering::SeqCst).to_string())))
                .block(Block::default().title("RPS Avg [EMA]").borders(Borders::ALL)), rps_ema_sect);
        }
    }

    fn handle_crossterm_events(&mut self) -> Result<()> {
        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => self.on_key_event(key),
                Event::Mouse(_) => {}
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        Ok(())
    }

    pub fn quit(&mut self) {
        self.running = false;
    }

    fn on_key_event(&mut self, key: KeyEvent) {
        match (key.modifiers, key.code) {
                (KeyModifiers::CONTROL, KeyCode::Char('q')) => {
                    self.quit();
                },
                (_, KeyCode::Down) => {
                    if self.selected < self.server_names.len() - 1 {
                        self.selected += 1;
                    }
                },
                (_, KeyCode::Up) => {
                    if self.selected > 0 {
                        self.selected -= 1;
                    }
                },
                (_, KeyCode::Enter) => {
                    self.screen = {
                        if self.screen == 1{
                            0
                        }else{
                            (self.screen + 1)
                        }
                    };
                },
                _ => {}
        }
    }
}

fn ms_since_epoch_to_hms(ms: i64) -> String {
    let secs = ms / 1000;
    let nsecs = ((ms % 1000) * 1_000_000) as u32;
    let naive = NaiveDateTime::from_timestamp_opt(secs, nsecs).expect("Invalid timestamp");
    let datetime = Local.from_utc_datetime(&naive);
    datetime.format("%H:%M:%S").to_string()
}

fn generate_y_labels(min: f64, max: f64, count: usize) -> Vec<String> {
    if (max - min).abs() < std::f64::EPSILON {
        return vec![format!("{:.0}", min)];
    }

    let step = (max - min) / (count - 1) as f64;
    (0..count)
        .map(|i| format!("{:.0}", ( min + step * i as f64) as u64)) // ← Round to nearest int
        .collect()
}


