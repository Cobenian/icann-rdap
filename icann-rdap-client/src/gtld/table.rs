use std::cmp::max;

use super::{GtldParams, ToGtld};

pub(crate) trait ToGtldTable {
    fn add_to_gtldtable(&self, table: MultiPartTable, params: GtldParams) -> MultiPartTable;
}

pub(crate) struct MultiPartTable {
    rows: Vec<Row>,
}

enum Row {
    Header(String),
    Data((String, String)),
}

impl MultiPartTable {
    pub(crate) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub(crate) fn header_ref(mut self, name: &impl ToString) -> Self {
        self.rows.push(Row::Header(name.to_string()));
        self
    }

    pub(crate) fn data_ref(mut self, name: &impl ToString, value: &impl ToString) -> Self {
        self.rows
            .push(Row::Data((name.to_string(), value.to_string())));
        self
    }

    pub(crate) fn data(mut self, name: &impl ToString, value: impl ToString) -> Self {
        self.rows
            .push(Row::Data((name.to_string(), value.to_string())));
        self
    }

    pub(crate) fn data_ul_ref(mut self, name: &impl ToString, value: Vec<&impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows
                    .push(Row::Data((name.to_string(), format!("{}", v.to_string()))))
            } else {
                self.rows
                    .push(Row::Data((String::default(), format!("{}", v.to_string()))))
            }
        });
        self
    }

    pub(crate) fn data_ul(mut self, name: &impl ToString, value: Vec<impl ToString>) -> Self {
        value.iter().enumerate().for_each(|(i, v)| {
            if i == 0 {
                self.rows
                    .push(Row::Data((name.to_string(), format!("{}", v.to_string()))))
            } else {
                self.rows
                    .push(Row::Data((String::default(), format!("{}", v.to_string()))))
            }
        });
        self
    }

    pub(crate) fn and_data_ref(mut self, name: &impl ToString, value: &Option<String>) -> Self {
        self.rows.push(Row::Data((
            name.to_string(),
            value.as_deref().unwrap_or_default().to_string(),
        )));
        self
    }

    pub(crate) fn and_data_ref_maybe(self, name: &impl ToString, value: &Option<String>) -> Self {
        if let Some(value) = value {
            self.data_ref(name, value)
        } else {
            self
        }
    }

    pub(crate) fn and_data_ul_ref(
        self,
        name: &impl ToString,
        value: Option<Vec<&impl ToString>>,
    ) -> Self {
        if let Some(value) = value {
            self.data_ul_ref(name, value)
        } else {
            self
        }
    }

    pub(crate) fn and_data_ul(
        self,
        name: &impl ToString,
        value: Option<Vec<impl ToString>>,
    ) -> Self {
        if let Some(value) = value {
            self.data_ul(name, value)
        } else {
            self
        }
    }
}

impl ToGtld for MultiPartTable {
    fn to_gtld(&self, _params: super::GtldParams) -> String {
        let mut md = String::new();

        let _col_type_width = max(
            self.rows
                .iter()
                .map(|row| match row {
                    Row::Header(header) => header.len(),
                    Row::Data((name, _value)) => name.len(),
                })
                .max()
                .unwrap_or(1),
            1,
        );

        self.rows
            .iter()
            .scan(true, |state, x| {
                let new_state = match x {
                    Row::Header(name) => {
                        md.push_str(&format!("\n{}\n", name.to_string()));
                        true
                    }
                    Row::Data((name, value)) => {
                        if *state {
                            md.push_str("\n");
                        };
                        md.push_str(&format!("{} {} \n", name.to_string(), value));
                        false
                    }
                };
                *state = new_state;
                Some(new_state)
            })
            .last();

        md.push_str("\n");
        md
    }
}
