use windows::Win32::Foundation::FILETIME;

#[derive(Debug, Clone)]
pub struct ProcessEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_name: String,
    pub image_path: String,
    pub command_line: String,
    pub session_id: u32,
    pub integrity_level: String,
    pub create_time: Option<FILETIME>,
    pub exit_time: Option<FILETIME>,
    pub exit_code: Option<u32>,
}

impl ProcessEvent {
    pub fn new_start(pid: u32, parent_pid: u32, process_name: String) -> Self {
        Self {
            pid,
            parent_pid,
            process_name,
            image_path: String::new(),
            command_line: String::new(),
            session_id: 0,
            integrity_level: String::from("Unknown"),
            create_time: None,
            exit_time: None,
            exit_code: None,
        }
    }

    pub fn new_end(pid: u32, process_name: String, exit_code: Option<u32>) -> Self {
        Self {
            pid,
            parent_pid: 0,
            process_name,
            image_path: String::new(),
            command_line: String::new(),
            session_id: 0,
            integrity_level: String::from("Unknown"),
            create_time: None,
            exit_time: None,
            exit_code,
        }
    }
}