use std::fs;
use pico_sdk::client::DefaultProverClient;

pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
fn main() {
    let elf = load_elf("./program-chacha/elf/riscv32im-pico-zkvm-elf");
    let client = DefaultProverClient::new(&elf);
    println!("{}", client.riscv_vk());
}
