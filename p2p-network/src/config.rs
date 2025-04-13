use std::fmt::Debug;
use std::path::Path;
use std::collections::HashMap;
use std::fs;

/// Environment-aware configuration system
pub trait ConfigLoader: Send + Sync + Debug {
    /// Load configuration from a source
    fn load(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Save configuration to a destination
    fn save(&self) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Get a configuration value by key
    fn get(&self, key: &str) -> Option<String>;
    
    /// Set a configuration value
    fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn std::error::Error>>;
    
    /// Check if a configuration key exists
    fn has(&self, key: &str) -> bool;
    
    /// Remove a configuration key
    fn remove(&mut self, key: &str) -> Result<(), Box<dyn std::error::Error>>;
}

/// Native file-based configuration implementation
#[cfg(feature = "native")]
pub struct FileConfigLoader {
    /// Path to the configuration file
    path: std::path::PathBuf,
    
    /// The loaded configuration
    config: std::collections::HashMap<String, String>,
}

#[cfg(feature = "native")]
impl FileConfigLoader {
    /// Create a new file-based configuration loader
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            config: std::collections::HashMap::new(),
        }
    }
}

#[cfg(feature = "native")]
impl Debug for FileConfigLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileConfigLoader")
            .field("path", &self.path)
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(feature = "native")]
impl ConfigLoader for FileConfigLoader {
    fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would load from file
        Ok(())
    }
    
    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would save to file
        Ok(())
    }
    
    fn get(&self, key: &str) -> Option<String> {
        self.config.get(key).cloned()
    }
    
    fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn std::error::Error>> {
        self.config.insert(key.to_string(), value);
        Ok(())
    }
    
    fn has(&self, key: &str) -> bool {
        self.config.contains_key(key)
    }
    
    fn remove(&mut self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.config.remove(key);
        Ok(())
    }
}

/// Browser-friendly configuration implementation
#[cfg(feature = "wasm")]
pub struct LocalStorageConfigLoader {
    /// The storage key prefix
    prefix: String,
}

#[cfg(feature = "wasm")]
impl LocalStorageConfigLoader {
    /// Create a new web-based configuration loader
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }
    
    /// Get the full key with prefix
    fn prefixed_key(&self, key: &str) -> String {
        format!("{}.{}", self.prefix, key)
    }
}

#[cfg(feature = "wasm")]
impl Debug for LocalStorageConfigLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStorageConfigLoader")
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[cfg(feature = "wasm")]
impl ConfigLoader for LocalStorageConfigLoader {
    fn load(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would load from localStorage in browser
        Ok(())
    }
    
    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would save to localStorage in browser
        Ok(())
    }
    
    fn get(&self, key: &str) -> Option<String> {
        // Implementation would get from localStorage in browser
        None
    }
    
    fn set(&mut self, key: &str, value: String) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would set in localStorage in browser
        Ok(())
    }
    
    fn has(&self, key: &str) -> bool {
        // Implementation would check localStorage in browser
        false
    }
    
    fn remove(&mut self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Implementation would remove from localStorage in browser
        Ok(())
    }
} 
