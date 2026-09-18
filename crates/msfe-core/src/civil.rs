//! Proleptic-Gregorian calendar arithmetic without a date crate (Howard
//! Hinnant's `days_from_civil` / `civil_from_days`). Days count from
//! 1970-01-01; used for backup stamps and log-day indexing.

/// A calendar date (year, month 1–12, day 1–31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    pub y: i32,
    pub m: u32,
    pub d: u32,
}

impl Date {
    pub fn new(y: i32, m: u32, d: u32) -> Date {
        Date { y, m, d }
    }

    /// Days since 1970-01-01 (negative before it).
    pub fn to_days(self) -> i64 {
        let y = if self.m <= 2 { self.y - 1 } else { self.y } as i64;
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400; // [0, 399]
        let m = self.m as i64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + self.d as i64 - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146_097 + doe - 719_468
    }

    /// The date `days` after 1970-01-01.
    pub fn from_days(days: i64) -> Date {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
        let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
        let y = (yoe + era * 400 + if m <= 2 { 1 } else { 0 }) as i32;
        Date { y, m, d }
    }

    /// The date of a Unix timestamp (UTC).
    pub fn from_unix(secs: u64) -> Date {
        Date::from_days((secs / 86_400) as i64)
    }

    pub fn next(self) -> Date {
        Date::from_days(self.to_days() + 1)
    }

    /// `YYYY-MM-DD` → Date; anything else → None.
    pub fn parse(s: &str) -> Option<Date> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        let y: i32 = s[0..4].parse().ok()?;
        let m: u32 = s[5..7].parse().ok()?;
        let d: u32 = s[8..10].parse().ok()?;
        let date = Date { y, m, d };
        // Reject 2026-02-30 and friends: a valid date survives a round trip.
        (m >= 1 && d >= 1 && Date::from_days(date.to_days()) == date).then_some(date)
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.y, self.m, self.d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_days_including_leap_days() {
        for (y, m, d, days) in [
            (1970, 1, 1, 0),
            (1969, 12, 31, -1),
            (2000, 2, 29, 11_016),
            (2024, 2, 29, 19_782),
            (2026, 9, 18, 20_714),
            (2100, 3, 1, 47_541),
        ] {
            let date = Date::new(y, m, d);
            assert_eq!(date.to_days(), days, "{date}");
            assert_eq!(Date::from_days(days), date);
        }
        assert_eq!(Date::new(2026, 12, 31).next(), Date::new(2027, 1, 1));
        assert_eq!(Date::from_unix(1_789_741_000), Date::new(2026, 9, 18));
    }

    #[test]
    fn parses_and_prints_iso_dates_only() {
        assert_eq!(Date::parse("2026-09-18"), Some(Date::new(2026, 9, 18)));
        assert_eq!(Date::new(2026, 9, 8).to_string(), "2026-09-08");
        for bad in [
            "2026-9-18",
            "2026-02-30",
            "2026-13-01",
            "2026-00-10",
            "18/09/2026",
            "",
        ] {
            assert_eq!(Date::parse(bad), None, "{bad}");
        }
    }
}
