#!/usr/bin/env python3
"""Метелка: в `impl Типаж for Тип` не бывает своих методов.

Ошибка компилятора, а не тихая беда, — и метелка здесь не вместо него,
а **вместо круга через человека**. `cargo` в этом дереве не запускается,
сборка идёт на другой машине, и такая описка стоит поставки: человек
получает тарболл, который не собирается, и пишет об этом.

Случилось это дважды подряд и одинаково: вспомогательный метод
(`drop_orphan_files` у `MemoryStore`) уехал внутрь `impl Store for …`
вместо собственного блока `impl MemoryStore`. Правило языка простое —
реализация типажа содержит только его члены, — и проверяется оно текстом
не хуже, чем сборкой.

Что проверяется: у каждого `impl Типаж for Тип` все объявленные `fn`
обязаны быть в объявлении `trait Типаж` этого же дерева. Типажи, которых
в дереве нет (чужие крейты, `Default`, `Display`), пропускаются молча:
сказать о них нечего.

Чего это не ловит: недостающие методы — их компилятор всё равно назовёт,
и назвать их текстом здесь нечем (типаж бывает с умолчаниями).
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ROOT = ROOT_DIR / "crates"

FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+(\w+)")


def block_of(src: str, open_at: int) -> str:
    """Тело от `{` до парной ему скобки."""
    depth = 0
    for j in range(open_at, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at : j + 1]
    return src[open_at:]


def top_level_fns(body: str) -> list[str]:
    """Имена `fn`, объявленных на верхнем уровне тела блока.

    Вложенные (внутри другой функции, внутри `mod tests`) не считаются:
    их глубина больше единицы, и правило типажа к ним не относится.
    """
    names = []
    depth = 0
    for line in body.split("\n"):
        if depth == 1:
            m = FN.match(line)
            if m:
                names.append(m.group(1))
        depth += line.count("{") - line.count("}")
    return names


def main() -> int:
    files = sorted(ROOT.glob("*/src/**/*.rs"))
    text = {p: p.read_text(encoding="utf-8") for p in files}

    # Объявления типажей этого дерева: имя → имена его методов.
    declared: dict[str, set[str]] = {}
    for src in text.values():
        for m in re.finditer(r"\btrait\s+(\w+)[^;{]*\{", src):
            body = block_of(src, m.end() - 1)
            declared[m.group(1)] = set(top_level_fns(body))

    bad = 0
    watched = 0
    for path, src in text.items():
        rel = path.relative_to(ROOT_DIR).as_posix()
        for m in re.finditer(r"\bimpl(?:<[^>]*>)?\s+([\w:]+)(?:<[^>]*>)?\s+for\s+[^{;]+\{", src):
            trait = m.group(1).rsplit("::", 1)[-1]
            if trait not in declared:
                continue
            watched += 1
            body = block_of(src, m.end() - 1)
            for name in top_level_fns(body):
                if name in declared[trait]:
                    continue
                line = src[: m.start()].count("\n") + 1 + body[: body.find(name)].count("\n")
                print(
                    f"{rel}:{line}: `{name}` объявлен в `impl {trait} for …`, "
                    f"но у типажа `{trait}` такого метода нет. "
                    "Своим методам место в отдельном `impl Тип`"
                )
                bad += 1

    print(f"реализаций типажей под присмотром: {watched}")
    print("чисто" if not bad else f"НАХОДОК: {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
