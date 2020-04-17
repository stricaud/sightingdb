all: sightingdb

sightingdb: src/main.rs src/main.rs
	cargo build

release: src/main.rs src/main.rs
	cargo build --release
