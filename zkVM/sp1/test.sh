export ENCRYPTION_KEY="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
#cargo run --release --bin cli -- --execute

cargo run --release --bin cli -- --execute --save-inputs my_inputs.bin

cargo run --release --bin cli -- --execute --load-inputs my_inputs.bin

#cargo run --release --bin cli -- --prove
