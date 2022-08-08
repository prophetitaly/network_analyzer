
#[derive(Debug)]
pub struct Parameters {
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

    pub fn set_device_id(&mut self, device_id: usize) {
        self.device_id = Some(device_id);
    }

    pub fn set_timeout(&mut self, timeout: u32) {
        self.timeout = Some(timeout);
    }

    pub fn set_file_path(&mut self, file_path: String) {
        self.file_path = file_path;
    }

    pub fn set_protocol(&mut self, protocol: String) {
        self.protocol = Some(protocol);
    }

    pub fn set_source(&mut self, source: String) {
        self.source = Some(source);
    }

    pub fn set_destination(&mut self, destination: String) {
        self.destination = Some(destination);
    }

    pub fn set_source_port(&mut self, source_port: String) {
        self.source_port = Some(source_port);
    }

    pub fn set_destination_port(&mut self, destination_port: String) {
        self.destination_port = Some(destination_port);
    }
}