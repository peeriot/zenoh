//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! The scouting tag: 16 bytes that scope multicast scouting. A node with a tag
//! answers only Scouts carrying the same tag and acts only on Hellos carrying
//! it; its own Scouts and Hellos carry it.

use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Serialize};

/// A scouting tag, written as 32 hexadecimal digits or as a UUID
/// (8-4-4-4-12 digits separated by hyphens).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScoutingTag([u8; ScoutingTag::LEN]);

impl ScoutingTag {
    /// A tag's length in bytes.
    pub const LEN: usize = 16;
    /// Hexadecimal digits per byte.
    const DIGITS_PER_BYTE: usize = 2;
    /// The radix of hexadecimal digits.
    const HEX_RADIX: u32 = 16;
    /// The digit count of each hyphen-separated group of a UUID.
    const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    /// The separator between a UUID's groups.
    const UUID_SEPARATOR: char = '-';

    /// A tag holding `bytes`.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The tag's bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The hexadecimal digits of `s`: all of it, or a UUID's groups joined.
    fn digits(s: &str) -> Result<String, InvalidScoutingTagError> {
        if !s.contains(Self::UUID_SEPARATOR) {
            return Ok(s.to_owned());
        }
        let groups: Vec<&str> = s.split(Self::UUID_SEPARATOR).collect();
        let shaped = groups.len() == Self::UUID_GROUPS.len()
            && groups
                .iter()
                .zip(Self::UUID_GROUPS)
                .all(|(group, len)| group.len() == len);
        if shaped {
            Ok(groups.concat())
        } else {
            Err(InvalidScoutingTagError)
        }
    }
}

impl FromStr for ScoutingTag {
    type Err = InvalidScoutingTagError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = Self::digits(s)?;
        // `from_str_radix` alone would also take a leading '+'.
        if digits.len() != Self::LEN * Self::DIGITS_PER_BYTE
            || !digits.bytes().all(|digit| digit.is_ascii_hexdigit())
        {
            return Err(InvalidScoutingTagError);
        }
        let mut bytes = [0; Self::LEN];
        for (byte, pair) in bytes
            .iter_mut()
            .zip(digits.as_bytes().chunks(Self::DIGITS_PER_BYTE))
        {
            let pair = std::str::from_utf8(pair).map_err(|_| InvalidScoutingTagError)?;
            *byte =
                u8::from_str_radix(pair, Self::HEX_RADIX).map_err(|_| InvalidScoutingTagError)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for ScoutingTag {
    /// Lowercase hexadecimal digits, `DIGITS_PER_BYTE` per byte.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(f, "{byte:0width$x}", width = Self::DIGITS_PER_BYTE))
    }
}

/// A string that is neither 32 hexadecimal digits nor a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidScoutingTagError;

impl fmt::Display for InvalidScoutingTagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a scouting tag is {} hexadecimal digits or a UUID",
            ScoutingTag::LEN * ScoutingTag::DIGITS_PER_BYTE
        )
    }
}

impl std::error::Error for InvalidScoutingTagError {}

impl Serialize for ScoutingTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ScoutingTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef";
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn hex_and_uuid_forms_parse_to_the_same_tag() {
        let hex: ScoutingTag = HEX.parse().unwrap();
        let uuid: ScoutingTag = UUID.parse().unwrap();
        let upper: ScoutingTag = UUID.to_uppercase().parse().unwrap();
        assert_eq!(hex, uuid);
        assert_eq!(hex, upper);
        assert_eq!(hex.to_string(), HEX);
    }

    #[test]
    fn other_strings_are_refused() {
        let short = &HEX[1..];
        let long = format!("{HEX}0");
        let not_hex = HEX.replace('0', "g");
        let signed = HEX.replacen('0', "+", 1);
        let misgrouped = "0123456-789ab-cdef-0123-456789abcdef";
        // A sixth, empty group: the first five match and still give 32 digits.
        let extra_group = format!("{UUID}-");
        for s in [
            short,
            long.as_str(),
            not_hex.as_str(),
            signed.as_str(),
            misgrouped,
            extra_group.as_str(),
            "",
        ] {
            assert_eq!(
                s.parse::<ScoutingTag>(),
                Err(InvalidScoutingTagError),
                "{s}"
            );
        }
    }
}
