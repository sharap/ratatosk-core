#!/usr/bin/env bash
#
# Сборка ядра под десктоп: библиотека под хост и биндинги Kotlin (§13.3).
#
# Десктоп на Kotlin Compose — это JVM, значит путь тот же, что на Android:
# нативная библиотека плюс сгенерированные биндинги. Отличий от
# `build-android.sh` три, и все три существенные:
#
#   1. Ни `tor`, ни `mail` не включаются. Компаньон (§13.4) ходит только
#      локальной сетью, и arti в десктопной библиотеке был бы несколькими
#      десятками мегабайт кода, который никто не позовёт.
#   2. Библиотеку **грузит JNA**, а не System.loadLibrary. Значит она должна
#      лежать не «где-нибудь», а в каталоге ресурсов с именем, которое JNA
#      ожидает для этой платформы, — или на `-Djna.library.path`.
#   3. Кросс-сборки здесь нет. Три платформы собираются на трёх платформах
#      (или в CI): для macOS нужен Apple SDK, для Windows — свой линкер,
#      и подсовывать их из Linux — отдельная работа, которую этот скрипт
#      не делает и делать не притворяется.
#
# Что получается на выходе:
#
#   <вывод>/resources/<префикс JNA>/<библиотека>   — в resources приложения
#   <вывод>/kotlin/org/ratatosk/core/*.kt          — в исходники приложения
#
# Обе половины обязаны быть из одной сборки: биндинги генерируются
# **по собранной библиотеке** (`--library`), а не по исходникам.
#
# Требуется:
#   * тулчейн Rust для этой платформы (rustup show);
#   * компилятор C и линкер — их зовёт сборка SQLite (`bundled`).
#
# Использование:
#   tools/build-desktop.sh [--debug] [--out КАТАЛОГ] [--target ТРОЙКА]
#                          [--features СПИСОК]

set -euo pipefail

PROFILE="release"
OUT="target/desktop"
TARGET=""
FEATURES=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug) PROFILE="debug"; shift ;;
        --out) OUT="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --features) FEATURES="$2"; shift 2 ;;
        *) echo "неизвестный ключ: $1" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# --- Платформа: имя файла и каталог, в котором его будет искать JNA --------
#
# Имена каталогов — это `com.sun.jna.Platform.RESOURCE_PREFIX`, и здесь они
# воспроизведены, а не вычислены: свериться с истиной можно за одну строку,
# и в DESKTOP.md написано, как именно. Расхождение проявится не при сборке,
# а при запуске — `UnsatisfiedLinkError` без объяснения причин.
if [[ -n "$TARGET" ]]; then
    TRIPLE="$TARGET"
else
    TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
fi

case "$TRIPLE" in
    x86_64-unknown-linux-*)   JNA_DIR="linux-x86-64";   LIB_NAME="libratatosk_ffi.so" ;;
    aarch64-unknown-linux-*)  JNA_DIR="linux-aarch64";  LIB_NAME="libratatosk_ffi.so" ;;
    x86_64-apple-darwin)      JNA_DIR="darwin-x86-64";  LIB_NAME="libratatosk_ffi.dylib" ;;
    aarch64-apple-darwin)     JNA_DIR="darwin-aarch64"; LIB_NAME="libratatosk_ffi.dylib" ;;
    x86_64-pc-windows-*)      JNA_DIR="win32-x86-64";   LIB_NAME="ratatosk_ffi.dll" ;;
    aarch64-pc-windows-*)     JNA_DIR="win32-aarch64";  LIB_NAME="ratatosk_ffi.dll" ;;
    *)
        echo "неизвестная платформа: $TRIPLE" >&2
        echo "добавьте её в этот скрипт: нужны каталог JNA и имя файла" >&2
        exit 1
        ;;
esac

RESOURCES="$OUT/resources/$JNA_DIR"
KOTLIN="$OUT/kotlin"
mkdir -p "$RESOURCES" "$KOTLIN"

# --- 1. Библиотека ---------------------------------------------------------
#
# Без `--features`: ни onion, ни почта десктопу не нужны (см. заголовок).
# Ключ оставлен на случай, когда десктоп понадобится собрать полным клиентом,
# — но это будет уже не компаньон.
CARGO_ARGS=(--package ratatosk-ffi)
if [[ "$PROFILE" == "release" ]]; then
    CARGO_ARGS+=(--release)
fi
if [[ -n "$FEATURES" ]]; then
    CARGO_ARGS+=(--features "$FEATURES")
fi
if [[ -n "$TARGET" ]]; then
    CARGO_ARGS+=(--target "$TARGET")
fi

echo "==> сборка библиотеки: $TRIPLE ($PROFILE)"
cargo build "${CARGO_ARGS[@]}"

if [[ -n "$TARGET" ]]; then
    BUILT="target/$TARGET/$PROFILE/$LIB_NAME"
else
    BUILT="target/$PROFILE/$LIB_NAME"
fi

if [[ ! -f "$BUILT" ]]; then
    echo "библиотека не собралась там, где ожидалась: $BUILT" >&2
    echo "проверьте crate-type = [\"cdylib\", ...] у ratatosk-ffi" >&2
    exit 1
fi

cp "$BUILT" "$RESOURCES/$LIB_NAME"

# --- 2. Биндинги -----------------------------------------------------------
#
# По собранной библиотеке, а не по исходникам: сгенерированные отдельно,
# они однажды разойдутся с тем, что реально лежит в файле, и расхождение
# вылезет при первом вызове, а не при сборке.
echo "==> биндинги Kotlin по $BUILT"
cargo run --quiet --package ratatosk-bindgen --bin uniffi-bindgen -- \
    generate --library "$BUILT" --language kotlin --out-dir "$KOTLIN"

# --- 3. Что понадобится приложению ----------------------------------------
#
# Проверка, а не утверждение: набор импортов у генератора менялся между
# версиями, и написать здесь «нужна такая-то зависимость» значило бы
# записать по памяти то, что лежит рядом текстом.
GENERATED=()
while IFS= read -r line; do GENERATED+=("$line"); done < <(find "$KOTLIN" -name '*.kt')

echo
echo "готово:"
echo "  библиотека: $RESOURCES/$LIB_NAME"
echo "  биндинги  : $KOTLIN"
echo
echo "в проект Compose Desktop:"
echo "  src/main/resources/$JNA_DIR/   ← $RESOURCES/$LIB_NAME"
echo "  src/main/kotlin/               ← содержимое $KOTLIN"
echo
if [[ ${#GENERATED[@]} -gt 0 ]]; then
    echo "зависимости, которых требует сгенерированный код:"
    grep -h '^import ' "${GENERATED[@]}" \
        | grep -v '^import org\.ratatosk\|^import java\.\|^import kotlin\.' \
        | sort -u \
        | sed 's/^/  /'
    echo
    echo "  (список читается из сгенерированного файла, а не берётся из головы;"
    echo "   com.sun.jna → net.java.dev.jna:jna, kotlinx.coroutines → kotlinx-coroutines-core)"
fi
echo
echo "и не забыть: DESKTOP.md — как JNA ищет библиотеку и что делать,"
echo "если она не нашлась"
