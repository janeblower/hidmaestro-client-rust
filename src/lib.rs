mod report;
#[cfg(windows)]
mod windows;

pub type Result<T> = std::io::Result<T>;

/// Xbox 360 state; positive stick Y points up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub buttons: Buttons,
    pub left_x: i16,
    pub left_y: i16,
    pub right_x: i16,
    pub right_y: i16,
    pub left_trigger: u8,
    pub right_trigger: u8,
}

/// Buttons use XInput bit positions; opposite D-pad directions are rejected on submit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Buttons(u32);

impl Buttons {
    pub const UP: Self = Self(1);
    pub const DOWN: Self = Self(2);
    pub const LEFT: Self = Self(4);
    pub const RIGHT: Self = Self(8);
    pub const START: Self = Self(0x10);
    pub const BACK: Self = Self(0x20);
    pub const LEFT_STICK: Self = Self(0x40);
    pub const RIGHT_STICK: Self = Self(0x80);
    pub const LEFT_BUMPER: Self = Self(0x100);
    pub const RIGHT_BUMPER: Self = Self(0x200);
    pub const GUIDE: Self = Self(0x400);
    pub const A: Self = Self(0x1000);
    pub const B: Self = Self(0x2000);
    pub const X: Self = Self(0x4000);
    pub const Y: Self = Self(0x8000);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !0xf7ff == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for Buttons {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_and_stick_limits_match_companion_decoder() {
        for value in [i16::MIN, -1, 0, 1, i16::MAX] {
            let state = State {
                left_x: value,
                left_y: value,
                right_x: value,
                right_y: value,
                ..State::default()
            };
            let f = report::encode(&state).unwrap();
            for offset in [0, 4] {
                let wire = u16::from_le_bytes([f.gip[offset], f.gip[offset + 1]]);
                assert_eq!(i32::from(wire) - 32768, i32::from(value));
            }
            for offset in [2, 6] {
                let wire = u16::from_le_bytes([f.gip[offset], f.gip[offset + 1]]);
                assert_eq!(32767 - i32::from(wire), i32::from(value));
            }
        }
    }

    #[test]
    fn triggers_round_trip_independently() {
        for (lt, rt) in [(0, 0), (255, 0), (0, 255), (255, 255), (1, 128), (128, 1)] {
            let f = report::encode(&State {
                left_trigger: lt,
                right_trigger: rt,
                ..State::default()
            })
            .unwrap();
            for (offset, expected) in [(8, lt), (10, rt)] {
                let raw = u16::from_le_bytes([f.gip[offset], f.gip[offset + 1]]);
                assert_eq!(u32::from(raw) * 255 / 1023, u32::from(expected));
            }
        }
        let f = report::encode(&State::default()).unwrap();
        assert_eq!(&f.hid[8..10], &32767u16.to_le_bytes());
        assert_eq!(&f.hid[10..14], &[0; 4]);
        assert_eq!(&f.hid[14..], &[0; 4]);
    }

    #[test]
    fn buttons_and_hat_follow_xusb_convention() {
        for (button, low, high) in [
            (Buttons::A, 1, 0),
            (Buttons::B, 2, 0),
            (Buttons::X, 4, 0),
            (Buttons::Y, 8, 0),
            (Buttons::LEFT_BUMPER, 16, 0),
            (Buttons::RIGHT_BUMPER, 32, 0),
            (Buttons::LEFT_STICK, 64, 0),
            (Buttons::RIGHT_STICK, 128, 0),
            (Buttons::BACK, 0, 1),
            (Buttons::START, 0, 2),
            (Buttons::GUIDE, 0, 64),
        ] {
            let f = report::encode(&State {
                buttons: button,
                ..State::default()
            })
            .unwrap();
            assert_eq!(&f.gip[12..], &[low, high]);
        }
        for (dpad, hat) in [
            (Buttons::UP, 1),
            (Buttons::UP | Buttons::RIGHT, 2),
            (Buttons::RIGHT, 3),
            (Buttons::DOWN | Buttons::RIGHT, 4),
            (Buttons::DOWN, 5),
            (Buttons::DOWN | Buttons::LEFT, 6),
            (Buttons::LEFT, 7),
            (Buttons::UP | Buttons::LEFT, 8),
            (Buttons::default(), 0),
        ] {
            let f = report::encode(&State {
                buttons: dpad,
                ..State::default()
            })
            .unwrap();
            assert_eq!(f.gip[13] >> 2, hat);
            assert_eq!(f.hid[15] >> 2, hat);
        }
        for buttons in [Buttons::UP | Buttons::DOWN, Buttons::LEFT | Buttons::RIGHT] {
            assert!(
                report::encode(&State {
                    buttons,
                    ..State::default()
                })
                .is_err()
            );
        }
        assert!(Buttons::from_bits(0x8000_0000).is_none());
    }
}
