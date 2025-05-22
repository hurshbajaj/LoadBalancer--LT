use std::{sync::Arc, time::{Duration, Instant}};

use chrono::{Local, NaiveDateTime, TimeZone};
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use once_cell::sync::Lazy;
use ratatui::{
    layout::{Constraint, Layout}, style::{Style, Stylize}, symbols, text::Line, widgets::{Axis, Block, Chart, Dataset, Paragraph}, DefaultTerminal, Frame
};
use tokio::sync::RwLock;

pub static reqs: Lazy<Arc<RwLock<u64>>> = Lazy::new(|| Arc::new(RwLock::new(0u64)));

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
}

impl App {
    pub fn new() -> Self {
        Self {
            running: true,
            req_chart_vals: vec![],
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

                // Retain only last 60 seconds of data
                self.req_chart_vals.retain(|(ts, _)| now - *ts <= 60_000.0);

                let mut Reqs = reqs.write().await;
                *Reqs = 0u64;

                timer -= 1.0;
            }
        }
        Ok(())
    }

    fn render(&mut self, frame: &mut Frame) {
        let [graph_sect, metric_sect] = Layout::vertical([Constraint::Percentage(35), Constraint::Fill(1)]).areas(frame.area());

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
        frame.render_widget(Block::bordered(), metric_sect);
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

    fn on_key_event(&mut self, key: KeyEvent) {
        match (key.modifiers, key.code) {
            (_, KeyCode::Esc | KeyCode::Char('q'))
            | (KeyModifiers::CONTROL, KeyCode::Char('c') | KeyCode::Char('C')) => self.quit(),
            _ => {}
        }
    }

    fn quit(&mut self) {
        self.running = false;
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


