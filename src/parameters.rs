

struct Parameters {
    pub device_id: Option<usize>,
    pub timeout: Option<u32>,
    pub file_path: String,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,
}

impl Parameters {
    pub fn new() -> Self {
        Parameters {
            device_id: Some(0),
            timeout: Some(5),
            file_path: String::new(),
            protocol: None,
            source: None,
            destination: None,
            source_port: None,
            destination_port: None,
        }
    }
}