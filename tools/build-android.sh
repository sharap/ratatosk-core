#!/usr/bin/env bash
#
# Сборка ядра под Android: библиотеки на все ABI и биндинги Kotlin (§13.3).
#
# Что получается на выходе:
#
#   <вывод>/jniLibs/<abi>/libratatosk_ffi.so   — то, что грузит System.loadLibrary
#   <вывод>/kotlin/org/ratatosk/core/*.kt      — то, что видит клиентский код
#
# Обе половины обязаны быть из одной сборки. Биндинги генерируются
# **по собранной библиотеке** (`--library`), а не по исходникам, — иначе они
# однажды разойдутся с тем, что реально лежит в `.so`, и расхождение вылезет
# на устройстве как `UnsatisfiedLinkError` или мусор в аргументах.
#
# Требуется:
#   * Android NDK (переменная ANDROID_NDK_HOME);
#   * cargo-ndk:      cargo install cargo-ndk
#   * цели Rust:      rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Использование:
#   tools/build-android.sh [--debug] [--out КАТАЛОГ] [--abi ABI[,ABI...]]

set -euo pipefail

PROFILE="release"
OUT="target/android"
ABIS="arm64-v8a,armeabi-v7a,x86_64"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug) PROFILE="debug"; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --abi) ABIS="$2"; shift 2 ;;
        *) echo "неизвестный ключ: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ANDROID_NDK_HOME не задан — cargo-ndk не найдёт компилятор" >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null; then
    echo "нет cargo-ndk: cargo install cargo-ndk" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

JNI_LIBS="$OUT/jniLibs"
KOTLIN="$OUT/kotlin"
mkdir -p "$JNI_LIBS" "$KOTLIN"

# --- 1. Библиотеки ----------------------------------------------------------
#
# Признак `tor` включается здесь и не выключается: собирать клиент без
# onion незачем — без него мессенджер работает только внутри одного Wi-Fi.
#
# Профиль `release-android` (см. общий Cargo.toml) отличается от обычного
# release одним: `opt-level = "z"`. На телефоне размер важнее скорости
# прогрева, а arti тянет в бинарник много кода.
CARGO_ARGS=(--package ratatosk-ffi --features tor)
if [[ "$PROFILE" == "release" ]]; then
    CARGO_ARGS+=(--profile release-android)
fi

# shellcheck disable=SC2086
IFS=',' read -r -a ABI_LIST <<< "$ABIS"
NDK_TARGETS=()
for abi in "${ABI_LIST[@]}"; do
    NDK_TARGETS+=(-t "$abi")
done

echo "==> сборка библиотек: $ABIS ($PROFILE)"
cargo ndk "${NDK_TARGETS[@]}" -o "$JNI_LIBS" build "${CARGO_ARGS[@]}"

# --- 2. Биндинги ------------------------------------------------------------
#
# По любой из собранных библиотек: метаданные в них одинаковые, а читать
# нужно именно артефакт, а не исходники.
FIRST_ABI="${ABI_LIST[0]}"
LIB="$JNI_LIBS/$FIRST_ABI/libratatosk_ffi.so"
if [[ ! -f "$LIB" ]]; then
    echo "библиотека не собралась: $LIB" >&2
    exit 1
fi

echo "==> биндинги Kotlin по $LIB"
cargo run --quiet --package ratatosk-bindgen --bin uniffi-bindgen -- \
    generate --library "$LIB" --language kotlin --out-dir "$KOTLIN"

echo
echo "готово:"
echo "  библиотеки: $JNI_LIBS"
echo "  биндинги  : $KOTLIN"
echo
echo "в приложение Android:"
echo "  app/src/main/jniLibs/     ← содержимое $JNI_LIBS"
echo "  app/src/main/java/        ← содержимое $KOTLIN"
echo
echo "и не забыть: android.permission.INTERNET, foreground service для Tor,"
echo "каталог данных из context.filesDir — подробности в ANDROID.md"
