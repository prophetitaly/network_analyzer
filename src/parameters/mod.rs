
#[derive(Debug,Clone)]
/// Represents the input parameters for the library
pub struct Parameters {
    /// The device id to capture from
    pub device_id: usize,
    /// The timeout for the capture
    pub timeout: u32,
    /// The path to the output file
    pub file_path: String,
    /// The protocol filter in BPF format
    pub filter: Option<String>,
}

impl Parameters {

    pub fn set_device_id(&mut self, device_id: usize) {
        self.device_id = device_id;
    }

    pub fn set_timeout(&mut self, timeout: u32) {
        self.timeout = timeout;
    }

    pub fn set_file_path(&mut self, file_path: String) {
        self.file_path = file_path;
    }

    pub fn set_protocol(&mut self, filter: String) {
        self.filter = Some(filter);
    }
}