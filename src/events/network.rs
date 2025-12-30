#[derive(Debug, Clone)]
pub struct NetworkEvent {
    pub pid: u32,
    pub process_name: String,
    pub direction: NetworkDirection,
    pub protocol: Protocol,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connection_state: ConnectionState,
}

#[derive(Debug, Clone)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Listening,
}

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP,
    Other(String),
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
    Established,
    Listening,
    Closed,
    TimeWait,
    Other(String),
}

impl NetworkEvent {
    pub fn new(
        pid: u32,
        process_name: String,
        direction: NetworkDirection,
        protocol: Protocol,
        local_address: String,
        local_port: u16,
        remote_address: String,
        remote_port: u16,
    ) -> Self {
        Self {
            pid,
            process_name,
            direction,
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
            bytes_sent: 0,
            bytes_received: 0,
            connection_state: ConnectionState::Established,
        }
    }
}