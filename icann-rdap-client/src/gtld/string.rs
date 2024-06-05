use chrono::DateTime;

use super::{GtldOptions, GtldParams};

pub(crate) trait StringUtil {
    fn to_em(self, options: &GtldOptions) -> String;
    fn to_bold(self, options: &GtldOptions) -> String;
    fn to_inline(self, options: &GtldOptions) -> String;
    fn to_header(self, level: usize, options: &GtldOptions) -> String;
    fn to_right(self, width: usize, options: &GtldOptions) -> String;
    fn to_right_em(self, width: usize, options: &GtldOptions) -> String;
    fn to_right_bold(self, width: usize, options: &GtldOptions) -> String;
    fn to_left(self, width: usize, options: &GtldOptions) -> String;
    fn to_left_em(self, width: usize, options: &GtldOptions) -> String;
    fn to_left_bold(self, width: usize, options: &GtldOptions) -> String;
    fn to_center(self, width: usize, options: &GtldOptions) -> String;
    fn to_center_em(self, width: usize, options: &GtldOptions) -> String;
    fn to_center_bold(self, width: usize, options: &GtldOptions) -> String;
    fn to_title_case(self) -> String;
    fn to_words_title_case(self) -> String;
    fn to_cap_acronyms(self) -> String;
    fn format_date_time(self, params: GtldParams) -> Option<String>;
}

impl<T: ToString> StringUtil for T {
    fn to_em(self, options: &GtldOptions) -> String {
        format!(
            "{}{}{}",
            options.text_style_char,
            self.to_string(),
            options.text_style_char
        )
    }

    fn to_bold(self, options: &GtldOptions) -> String {
        format!(
            "{}{}{}{}{}",
            options.text_style_char,
            options.text_style_char,
            self.to_string(),
            options.text_style_char,
            options.text_style_char
        )
    }

    fn to_inline(self, _options: &GtldOptions) -> String {
        format!("`{}`", self.to_string(),)
    }

    fn to_header(self, level: usize, options: &GtldOptions) -> String {
        let s = self.to_string();
        if options.hash_headers {
            format!("{} {s}\n\n", "#".repeat(level))
        } else {
            let line = if level == 1 {
                "=".repeat(s.len())
            } else {
                "-".repeat(s.len())
            };
            format!("{s}\n{line}\n\n")
        }
    }

    fn to_right(self, width: usize, options: &GtldOptions) -> String {
        let str = self.to_string();
        if options.no_unicode_chars {
            format!("{str:>width$}")
        } else {
            format!("{str:\u{2003}>width$}")
        }
    }

    fn to_right_em(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_right(width, options)
        } else {
            self.to_right(width, options).to_em(options)
        }
    }

    fn to_right_bold(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_right(width, options)
        } else {
            self.to_right(width, options).to_bold(options)
        }
    }

    fn to_left(self, width: usize, options: &GtldOptions) -> String {
        let str = self.to_string();
        if options.no_unicode_chars {
            format!("{str:<width$}")
        } else {
            format!("{str:\u{2003}<width$}")
        }
    }

    fn to_left_em(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_left(width, options)
        } else {
            self.to_left(width, options).to_em(options)
        }
    }

    fn to_left_bold(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_left(width, options)
        } else {
            self.to_left(width, options).to_bold(options)
        }
    }

    fn to_center(self, width: usize, options: &GtldOptions) -> String {
        let str = self.to_string();
        if options.no_unicode_chars {
            format!("{str:^width$}")
        } else {
            format!("{str:\u{2003}^width$}")
        }
    }

    fn to_center_em(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_em(options).to_center(width, options)
        } else {
            self.to_center(width, options).to_bold(options)
        }
    }

    fn to_center_bold(self, width: usize, options: &GtldOptions) -> String {
        if options.style_in_justify {
            self.to_bold(options).to_center(width, options)
        } else {
            self.to_center(width, options).to_bold(options)
        }
    }

    fn to_title_case(self) -> String {
        self.to_string()
            .char_indices()
            .map(|(i, mut c)| {
                if i == 0 {
                    c.make_ascii_uppercase();
                    c
                } else {
                    c
                }
            })
            .collect::<String>()
    }

    fn to_words_title_case(self) -> String {
        self.to_string()
            .split_whitespace()
            .map(|s| s.to_title_case())
            .collect::<Vec<String>>()
            .join(" ")
    }

    fn format_date_time(self, _params: GtldParams) -> Option<String> {
        let date = DateTime::parse_from_rfc3339(&self.to_string()).ok()?;
        Some(date.format("%a, %v %X %Z").to_string())
    }

    fn to_cap_acronyms(self) -> String {
        self.to_string()
            .replace("rdap", "RDAP")
            .replace("icann", "ICANN")
            .replace("arin", "ARIN")
            .replace("ripe", "RIPE")
            .replace("apnic", "APNIC")
            .replace("lacnic", "LACNIC")
            .replace("afrinic", "AFRINIC")
            .replace("nro", "NRO")
            .replace("ietf", "IETF")
    }
}

pub(crate) trait StringListUtil {
    fn make_list_all_title_case(self) -> Vec<String>;
    fn make_title_case_list(self) -> String;
}

impl<T: ToString> StringListUtil for &[T] {
    fn make_list_all_title_case(self) -> Vec<String> {
        self.iter()
            .map(|s| s.to_string().to_words_title_case())
            .collect::<Vec<String>>()
    }

    fn make_title_case_list(self) -> String {
        self.make_list_all_title_case().join(", ")
    }
}
