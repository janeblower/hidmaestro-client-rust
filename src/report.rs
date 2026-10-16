use crate::{Result, State};

pub(crate) struct EncodedFrame {
    pub hid: [u8; 18],
    pub gip: [u8; 14],
}

pub(crate) fn encode(state: &State) -> Result<EncodedFrame> {
    let b = state.buttons.bits();
    let hat = match b & 15 {
        0 => 0,
        1 => 1,
        9 => 2,
        8 => 3,
        10 => 4,
        2 => 5,
        6 => 6,
        4 => 7,
        5 => 8,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opposite D-pad directions",
            ));
        }
    };
    let mut frame = EncodedFrame {
        hid: [0; 18],
        gip: [0; 14],
    };
    for (offset, value, y) in [
        (0, state.left_x, false),
        (2, state.left_y, true),
        (4, state.right_x, false),
        (6, state.right_y, true),
    ] {
        // companion.c decodes X as raw - 32768, Y as 32767 - raw.
        let raw = if y {
            32767 - i32::from(value)
        } else {
            i32::from(value) + 32768
        } as u16;
        frame.gip[offset..offset + 2].copy_from_slice(&raw.to_le_bytes());
        frame.hid[offset..offset + 2].copy_from_slice(&raw.to_le_bytes());
    }
    for (offset, trigger) in [(8, state.left_trigger), (10, state.right_trigger)] {
        // Round up so the driver's integer conversion back to u8 is lossless.
        let raw = (u32::from(trigger) * 1023).div_ceil(255) as u16;
        frame.gip[offset..offset + 2].copy_from_slice(&raw.to_le_bytes());
        let separate = u16::from(trigger) * 257;
        frame.hid[offset + 2..offset + 4].copy_from_slice(&separate.to_le_bytes());
    }
    let combined = ((i32::from(state.right_trigger) - i32::from(state.left_trigger) + 255) * 65535
        / 510) as u16;
    frame.hid[8..10].copy_from_slice(&combined.to_le_bytes());
    frame.gip[12] = ((b >> 12) | ((b & 0x300) >> 4) | (b & 0xc0)) as u8;
    frame.gip[13] = (((b & 0x20) >> 5) | ((b & 0x10) >> 3) | ((b & 0x400) >> 4)) as u8 | (hat << 2);
    let hid_buttons = ((b >> 12)
        | ((b & 0x300) >> 4)
        | ((b & 0x20) << 1)
        | ((b & 0x10) << 3)
        | ((b & 0xc0) << 2)) as u16
        | (u16::from(hat) << 10);
    frame.hid[14..16].copy_from_slice(&hid_buttons.to_le_bytes());
    Ok(frame)
}
