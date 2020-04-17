// use std::collections::HashMap;

// #[derive(PartialEq, Eq)]
// pub enum ConfigStorage {
//     IN_MEMORY,
//     ON_DISK,    
// }

// pub struct Configuration {
//     storage: HashMap<String, ConfigStorage>,
// }

// impl Configuration {
//     pub fn new() -> Configuration {
//         Configuration {
//             storage: HashMap::new(),
//         }
//     }
//     pub fn set_storage(&mut self, storage: ConfigStorage, path: String) {
//         self.storage.insert(path, storage);
//     }
//     pub fn get_storage(&mut self, path: String) -> String {
//         let storageopt = self.storage.get_mut(&path);
//         match storageopt {
//             Some(storageopt) => {
//                 match storageopt {
//                     ConfigStorage::IN_MEMORY => { return String::from("IN_MEMORY"); },
//                     ConfigStorage::ON_DISK => { return String::from("ON_DISK"); },
//                 }
//             },
//             None => {
//                 return String::from("IN_MEMORY");
//             }
//         }
//     }
    
// }

// pub fn set(path: &str, value: &str) {
//     println!("Configuring path {}", path);
// }

// pub fn get(path: &str, value: &str) {
//     println!("Get configuration");
// }
