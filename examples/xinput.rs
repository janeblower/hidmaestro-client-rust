#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use hidmaestro_client::{Buttons, Controller, State};
    use std::{
        io, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::UI::Input::XboxController::{XINPUT_STATE, XInputGetState};

    fn read(slot: u32) -> Option<XINPUT_STATE> {
        let mut state = XINPUT_STATE::default();
        // The buffer is initialized and lives through this synchronous call.
        (unsafe { XInputGetState(slot, &mut state) } == 0).then_some(state)
    }
    fn wait(mut condition: impl FnMut() -> bool, message: &str) -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(15);
        while !condition() {
            if Instant::now() >= until {
                return Err(io::Error::new(io::ErrorKind::TimedOut, message.to_owned()));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    let mode = std::env::args().nth(1).unwrap_or_else(|| "verify".into());
    if mode == "probe" {
        for slot in 0..4 {
            if let Some(s) = read(slot) {
                println!(
                    "slot={slot} buttons={:#06x} LT={} RT={} LX={} LY={} RX={} RY={}",
                    s.Gamepad.wButtons,
                    s.Gamepad.bLeftTrigger,
                    s.Gamepad.bRightTrigger,
                    s.Gamepad.sThumbLX,
                    s.Gamepad.sThumbLY,
                    s.Gamepad.sThumbRX,
                    s.Gamepad.sThumbRY
                );
            }
        }
        return Ok(());
    }
    if !matches!(mode.as_str(), "verify" | "hold") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: xinput [verify|hold|probe]",
        ));
    }
    let before = std::array::from_fn::<_, 4, _>(|i| read(i as u32).is_some());
    if before.iter().all(|v| *v) {
        return Err(io::Error::other("all four XInput slots are occupied"));
    }
    let mut controller = Controller::create()?;
    let mut slot = None;
    wait(
        || {
            let added: Vec<_> = (0..4)
                .filter(|&i| !before[i] && read(i as u32).is_some())
                .collect();
            if added.len() == 1 {
                slot = Some(added[0] as u32);
                true
            } else {
                false
            }
        },
        "one new XInput slot",
    )?;
    let slot = slot.unwrap();
    println!("controller PID={} XInput slot={slot}", std::process::id());
    let mut states = vec![State::default()];
    for buttons in [
        Buttons::A,
        Buttons::B,
        Buttons::X,
        Buttons::Y,
        Buttons::LEFT_BUMPER,
        Buttons::RIGHT_BUMPER,
        Buttons::BACK,
        Buttons::START,
        Buttons::LEFT_STICK,
        Buttons::RIGHT_STICK,
        Buttons::UP,
        Buttons::UP | Buttons::RIGHT,
        Buttons::RIGHT,
        Buttons::DOWN | Buttons::RIGHT,
        Buttons::DOWN,
        Buttons::DOWN | Buttons::LEFT,
        Buttons::LEFT,
        Buttons::UP | Buttons::LEFT,
    ] {
        states.push(State {
            buttons,
            ..State::default()
        });
    }
    for value in [i16::MIN, -1, 0, 1, i16::MAX] {
        states.push(State {
            left_x: value,
            left_y: value,
            right_x: value,
            right_y: value,
            ..State::default()
        });
    }
    for (left_trigger, right_trigger) in [(255, 0), (0, 255), (255, 255), (1, 128), (128, 1)] {
        states.push(State {
            left_trigger,
            right_trigger,
            ..State::default()
        });
    }
    states.push(State::default());
    for (index, expected) in states.iter().enumerate() {
        controller.submit(expected)?;
        wait(
            || {
                read(slot).is_some_and(|actual| {
                    let g = actual.Gamepad;
                    g.wButtons == expected.buttons.bits() as u16
                        && g.bLeftTrigger == expected.left_trigger
                        && g.bRightTrigger == expected.right_trigger
                        && g.sThumbLX == expected.left_x
                        && g.sThumbLY == expected.left_y
                        && g.sThumbRX == expected.right_x
                        && g.sThumbRY == expected.right_y
                })
            },
            &format!("XInput state {index}: {expected:?}"),
        )?;
    }
    println!("{} XInput states verified", states.len());
    if mode == "hold" {
        controller.submit(&State {
            buttons: Buttons::A,
            ..State::default()
        })?;
        wait(
            || read(slot).is_some_and(|s| s.Gamepad.wButtons == Buttons::A.bits() as u16),
            "held A",
        )?;
        println!(
            "holding A; terminate PID {} to test crash cleanup",
            std::process::id()
        );
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
    controller.close()?;
    wait(
        || std::array::from_fn::<_, 4, _>(|i| read(i as u32).is_some()) == before,
        "XInput baseline after close",
    )?;
    println!("close verified; original XInput slots preserved");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This example requires Windows x64.");
    std::process::exit(1);
}
