use std::collections::HashMap;
use std::fs;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub blocked: BlockSection,
    pub allowed: HashMap<String, u16>,
}

#[derive(Debug, Deserialize)]
pub struct BlockSection {
    pub tcp: String,
    pub udp: String,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}
