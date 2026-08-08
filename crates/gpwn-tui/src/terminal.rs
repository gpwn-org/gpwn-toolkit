use anyhow::Context;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::{self, Stdout};

trait TerminalActions {
    fn enable_raw(&mut self) -> io::Result<()>;
    fn enter_alternate_screen(&mut self) -> io::Result<()>;
    fn enable_mouse_capture(&mut self) -> io::Result<()>;
    fn disable_mouse_capture(&mut self);
    fn leave_alternate_screen(&mut self);
    fn disable_raw(&mut self);
}

struct SystemTerminalActions;

impl TerminalActions for SystemTerminalActions {
    fn enable_raw(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }

    fn enter_alternate_screen(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnterAlternateScreen)
    }

    fn enable_mouse_capture(&mut self) -> io::Result<()> {
        execute!(io::stdout(), EnableMouseCapture)
    }

    fn disable_mouse_capture(&mut self) {
        let _ = execute!(io::stdout(), DisableMouseCapture);
    }

    fn leave_alternate_screen(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }

    fn disable_raw(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Tracks every terminal mutation as soon as it succeeds. This guard exists
/// before the first fallible setup call, so any later initialization error
/// unwinds all setup that has already taken effect.
struct RestoreGuard<A: TerminalActions> {
    actions: A,
    raw_mode: bool,
    alternate_screen: bool,
    mouse_capture: bool,
}

impl<A: TerminalActions> RestoreGuard<A> {
    fn new(actions: A) -> Self {
        Self {
            actions,
            raw_mode: false,
            alternate_screen: false,
            mouse_capture: false,
        }
    }
}

impl<A: TerminalActions> Drop for RestoreGuard<A> {
    fn drop(&mut self) {
        if self.mouse_capture {
            self.actions.disable_mouse_capture();
        }
        if self.alternate_screen {
            self.actions.leave_alternate_screen();
        }
        if self.raw_mode {
            self.actions.disable_raw();
        }
    }
}

fn prepare_terminal<A: TerminalActions>(actions: A) -> anyhow::Result<RestoreGuard<A>> {
    let mut guard = RestoreGuard::new(actions);
    // Arm each inverse before its setup call: a terminal command can write
    // enough control bytes to mutate state and still report a later I/O error.
    guard.raw_mode = true;
    guard
        .actions
        .enable_raw()
        .context("enable terminal raw mode")?;
    guard.alternate_screen = true;
    guard
        .actions
        .enter_alternate_screen()
        .context("enter alternate screen")?;
    guard.mouse_capture = true;
    guard
        .actions
        .enable_mouse_capture()
        .context("enable mouse capture")?;
    Ok(guard)
}

pub(super) struct TerminalGuard {
    pub(super) terminal: Terminal<CrosstermBackend<Stdout>>,
    _restore: RestoreGuard<SystemTerminalActions>,
}

impl TerminalGuard {
    pub(super) fn enter() -> anyhow::Result<Self> {
        let restore = prepare_terminal(SystemTerminalActions)?;
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend).context("create terminal")?;
        Ok(Self {
            terminal,
            _restore: restore,
        })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.terminal.show_cursor();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct FakeActions {
        fail_at: &'static str,
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl FakeActions {
        fn step(&self, name: &'static str) -> io::Result<()> {
            self.calls.borrow_mut().push(name);
            if self.fail_at == name {
                Err(io::Error::other("injected setup failure"))
            } else {
                Ok(())
            }
        }
    }

    impl TerminalActions for FakeActions {
        fn enable_raw(&mut self) -> io::Result<()> {
            self.step("enable_raw")
        }
        fn enter_alternate_screen(&mut self) -> io::Result<()> {
            self.step("enter_screen")
        }
        fn enable_mouse_capture(&mut self) -> io::Result<()> {
            self.step("enable_mouse")
        }
        fn disable_mouse_capture(&mut self) {
            self.calls.borrow_mut().push("disable_mouse");
        }
        fn leave_alternate_screen(&mut self) {
            self.calls.borrow_mut().push("leave_screen");
        }
        fn disable_raw(&mut self) {
            self.calls.borrow_mut().push("disable_raw");
        }
    }

    #[test]
    fn attempts_raw_mode_restoration_when_enabling_raw_mode_fails() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let result = prepare_terminal(FakeActions {
            fail_at: "enable_raw",
            calls: calls.clone(),
        });
        assert!(result.is_err());
        assert_eq!(calls.borrow().as_slice(), ["enable_raw", "disable_raw"]);
    }

    #[test]
    fn restores_raw_mode_when_entering_screen_fails() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let result = prepare_terminal(FakeActions {
            fail_at: "enter_screen",
            calls: calls.clone(),
        });
        assert!(result.is_err());
        assert_eq!(
            calls.borrow().as_slice(),
            ["enable_raw", "enter_screen", "leave_screen", "disable_raw"]
        );
    }

    #[test]
    fn restores_screen_and_raw_mode_when_mouse_setup_fails() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let result = prepare_terminal(FakeActions {
            fail_at: "enable_mouse",
            calls: calls.clone(),
        });
        assert!(result.is_err());
        assert_eq!(
            calls.borrow().as_slice(),
            [
                "enable_raw",
                "enter_screen",
                "enable_mouse",
                "disable_mouse",
                "leave_screen",
                "disable_raw"
            ]
        );
    }

    #[test]
    fn successful_setup_guard_restores_every_terminal_mutation() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let guard = prepare_terminal(FakeActions {
            fail_at: "never",
            calls: calls.clone(),
        })
        .unwrap();
        drop(guard);
        assert_eq!(
            calls.borrow().as_slice(),
            [
                "enable_raw",
                "enter_screen",
                "enable_mouse",
                "disable_mouse",
                "leave_screen",
                "disable_raw"
            ]
        );
    }
}
