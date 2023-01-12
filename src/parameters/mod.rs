
#[derive(Debug,Clone)]
pub struct Parameters {
    pub device_id: usize,
    pub timeout: u32,
    pub file_path: String,
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