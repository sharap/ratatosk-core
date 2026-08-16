//! Генератор биндингов UniFFI (§13.3).
//!
//! Инструмент сборки, а не часть продукта. Запускается сборочными скриптами
//! клиентов по уже собранной библиотеке:
//!
//! ```text
//! cargo build -p ratatosk-ffi --release --target aarch64-linux-android
//! cargo run -p ratatosk-bindgen --bin uniffi-bindgen -- generate \
//!     --library target/aarch64-linux-android/release/libratatosk_ffi.so \
//!     --language kotlin \
//!     --out-dir clients/android/app/src/main/java
//! ```
//!
//! Версия `uniffi` здесь обязана совпадать с версией в `ratatosk-ffi` —
//! обе берутся из `[workspace.dependencies]`, так что расходиться им негде.

fn main() {
    uniffi::uniffi_bindgen_main();
}
