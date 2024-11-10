# MIT License
#
# Copyright (c) 2024 mangalitza-io
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import subprocess
from abc import ABCMeta, abstractmethod
from argparse import ArgumentParser, Namespace
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from enum import Enum
from pathlib import Path
from typing import TypeAlias

Slots: TypeAlias = tuple[str, ...]
ListOfStr: TypeAlias = list[str]


class UMLLevel(Enum):
    BASE: ListOfStr = []
    MINIMAL: ListOfStr = ["--module-names", "y"]
    MODERATE: ListOfStr = [
        "--module-names",
        "y",
        "--all-ancestors",
    ]
    FULL: ListOfStr = [
        "--module-names",
        "y",
        "--all-ancestors",
        "--all-associated",
    ]


class _BaseUmlCreator(metaclass=ABCMeta):
    DIR_SUFFIX: str
    RAW_DIR_PREFIX: str = "raw"
    STYLED_DIR_PREFIX: str = "styled"
    PNG_DIR_PREFIX: str = "png"
    SVG_DIR_PREFIX: str = "svg"

    __slots__: Slots = (
        "_src",
        "_dst",
        "_project_name",
        "_raw_uml_dir_src",
        "_styled_uml_dir_src",
        "_png_uml_dir_src",
        "_svg_uml_dir_src",
    )

    def __init__(self, src: Path, dst: Path) -> None:
        self._src: Path = src
        self._dst: Path = dst
        self._project_name: str = self._src.name

        if self.DIR_SUFFIX is None:
            raise TypeError()

        raw_uml_dir_name: str = f"{self.RAW_DIR_PREFIX}_{self.DIR_SUFFIX}"
        self._raw_uml_dir_src: Path = self._dst.joinpath(
            raw_uml_dir_name, self._project_name
        )
        styled_uml_dir_name: str = (
            f"{self.STYLED_DIR_PREFIX}_{self.DIR_SUFFIX}"
        )
        self._styled_uml_dir_src: Path = self._dst.joinpath(
            styled_uml_dir_name, self._project_name
        )
        png_uml_dir_name: str = f"{self.PNG_DIR_PREFIX}_{self.DIR_SUFFIX}"
        self._png_uml_dir_src: Path = self._dst.joinpath(
            png_uml_dir_name, self._project_name
        )
        svg_uml_dir_name: str = f"{self.SVG_DIR_PREFIX}_{self.DIR_SUFFIX}"
        self._svg_uml_dir_src: Path = self._dst.joinpath(
            svg_uml_dir_name, self._project_name
        )

        if not self._dst.is_dir():
            self._dst.mkdir(parents=True)

    @staticmethod
    def _create_dirs(folders: Iterator[Path]) -> None:
        for folder in folders:
            if not folder.exists():
                folder.mkdir(parents=True)
                continue
            if not folder.is_dir():
                raise OSError()

    @staticmethod
    def _gather_files_with_ext(src: Path, suffix: str) -> Iterator[Path]:
        return src.rglob(f"*{suffix}")

    def _gather_python_modules(self, src: Path) -> Iterator[Path]:
        return self._gather_files_with_ext(src, ".py")

    def _gather_python_packages(self, src: Path) -> Iterator[Path]:
        for file in self._gather_python_modules(src):
            if file.name != "__init__.py":
                continue
            yield file.parent

    @staticmethod
    def _execute_shell_single(cmds: Iterable[list[str]]) -> None:
        for cmd in cmds:
            subprocess.run(cmd, check=True)

    def _execute_shell_parallel(self, cmds: Iterable[list[str]]) -> None:
        with ProcessPoolExecutor() as executor:
            futures = [
                executor.submit(self._execute_shell_single, [cmd])
                for cmd in cmds
            ]

            for future in futures:
                future.result()

    def _create_raw_uml(
        self,
        src_dir: Path,
        dst_dir: Path,
        ext: str,
        module_or_package: bool,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        folders: Iterator[Path] = (
            dst_dir.joinpath(orig_file.relative_to(src_dir))
            for orig_file in self._gather_python_packages(src_dir)
        )
        self._create_dirs(folders)

        excludes: set[str] = {"__init__.py", "__main__.py"}

        iterator: Callable[[Path], Iterator[Path]]
        if module_or_package is True:
            iterator = self._gather_python_modules
        elif module_or_package is False:
            iterator = self._gather_python_packages
        else:
            raise TypeError()

        jobs: list[list[str]] = []
        for py_file in iterator(src_dir):
            if py_file.name in excludes:
                continue
            dest_py_file: Path = dst_dir.joinpath(py_file.relative_to(src_dir))
            # fmt: off
            cmd: list[str] = [
                "pyreverse",
                "--filter-mode", "ALL",
                "--output", ext,
                *lvl.value,
                "--output-directory", dest_py_file.parent.as_posix(),
                "--project", dest_py_file.with_suffix("").name,
                py_file.as_posix(),
            ]
            # fmt: on
            jobs.append(cmd)

        return self._execute_shell_parallel(jobs)

    def _create_styled_uml(
        self,
        src_dir: Path,
        dst_dir: Path,
        old_style: str,
        new_style: str,
    ) -> None:
        folders: Iterator[Path] = (
            dst_dir.joinpath(orig_file.relative_to(src_dir)).parent
            for orig_file in self._gather_files_with_ext(
                src=src_dir, suffix=".puml"
            )
        )
        self._create_dirs(folders)

        src_files: Iterator[Path] = self._gather_files_with_ext(
            src=src_dir, suffix=".puml"
        )
        for src_file in src_files:
            dst_file: Path = dst_dir.joinpath(src_file.relative_to(src_dir))

            text: str = src_file.read_text()
            text = text.replace(old_style, new_style)
            dst_file.write_text(text)

    def _create_pretty_uml(
        self, src_dir: Path, dst_dir: Path, output_format: str
    ) -> None:
        folders: Iterator[Path] = (
            dst_dir.joinpath(orig_file.relative_to(src_dir)).parent
            for orig_file in self._gather_files_with_ext(
                src=src_dir, suffix=".puml"
            )
        )
        self._create_dirs(folders)

        src_files: Iterator[Path] = self._gather_files_with_ext(
            src=src_dir, suffix=".puml"
        )

        jobs: list[list[str]] = []
        for src_file in src_files:
            dst_file: Path = dst_dir.joinpath(src_file.relative_to(src_dir))
            # fmt: off
            cmd: list[str] = [
                "plantuml",
                f"-t{output_format}",
                "-o", dst_file.parent.as_posix(),
                src_file.as_posix(),
            ]
            # fmt: on
            jobs.append(cmd)

        return self._execute_shell_parallel(jobs)

    @abstractmethod
    def create_raw_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        raise NotImplementedError()

    def create_styled_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        src_dir: Path = self._raw_uml_dir_src
        dst_dir: Path = self._styled_uml_dir_src
        old_style: str = "set namespaceSeparator none\n"
        new_style: str = "hide empty members\n" "left to right direction\n"
        if not src_dir.is_dir():
            self.create_raw_uml(lvl=lvl)
        return self._create_styled_uml(
            src_dir=src_dir.parent,
            dst_dir=dst_dir.parent,
            old_style=old_style,
            new_style=new_style,
        )

    def create_png_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        src_dir: Path = self._styled_uml_dir_src
        dst_dir: Path = self._png_uml_dir_src
        output_format: str = "png"

        if not src_dir.is_dir():
            self.create_styled_uml(lvl=lvl)
        return self._create_pretty_uml(
            src_dir=src_dir.parent,
            dst_dir=dst_dir.parent,
            output_format=output_format,
        )

    def create_svg_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        src_dir: Path = self._styled_uml_dir_src
        dst_dir: Path = self._svg_uml_dir_src
        output_format: str = "svg"

        if not src_dir.is_dir():
            self.create_styled_uml(lvl=lvl)
        return self._create_pretty_uml(
            src_dir=src_dir.parent,
            dst_dir=dst_dir.parent,
            output_format=output_format,
        )


class ModuleUmlCreator(_BaseUmlCreator):
    DIR_SUFFIX: str = "uml_modules"
    __slots__: Slots = tuple()

    def create_raw_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        src_dir: Path = self._src
        dst_dir: Path = self._raw_uml_dir_src
        extension: str = "puml"
        return self._create_raw_uml(
            src_dir=src_dir,
            dst_dir=dst_dir,
            ext=extension,
            module_or_package=True,
            lvl=lvl,
        )

    def run(self) -> None:
        self.create_svg_uml()


class PackageUmlCreator(_BaseUmlCreator):
    DIR_SUFFIX: str = "uml_package"
    __slots__: Slots = tuple()

    def create_raw_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        src_dir: Path = self._src
        dst_dir: Path = self._raw_uml_dir_src
        extension: str = "puml"

        self._create_raw_uml(
            src_dir=src_dir,
            dst_dir=dst_dir,
            ext=extension,
            module_or_package=False,
            lvl=lvl,
        )

        for subdir in self._raw_uml_dir_src.rglob("*"):
            if not subdir.is_dir():
                continue
            if any(subdir.iterdir()):
                continue
            subdir.rmdir()

    def run(self) -> None:
        self.create_svg_uml()


class UmlCreator:
    DEFAULT_UML_DIR_NAME: str = "temp_uml"

    def __init__(self, src: str, dst: str | None = None) -> None:
        self._src: Path = Path(src)
        self._dst: Path
        if dst is None:
            # .mkdir(parents=True, exist_ok=True)
            self._dst = self._src.parent.joinpath(self.DEFAULT_UML_DIR_NAME)
        else:
            self._dst = Path(dst)
        self._dst.mkdir(parents=True, exist_ok=True)

        if not self._src.is_dir():
            raise OSError()

        self._module_creator: ModuleUmlCreator = ModuleUmlCreator(
            src=self._src,
            dst=self._dst,
        )
        self._package_creator: PackageUmlCreator = PackageUmlCreator(
            src=self._src,
            dst=self._dst,
        )

    def create_raw_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        self._module_creator.create_raw_uml(lvl=lvl)
        self._package_creator.create_raw_uml(lvl=lvl)

    def create_styled_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        self._module_creator.create_styled_uml(lvl=lvl)
        self._package_creator.create_styled_uml(lvl=lvl)

    def create_png_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        self._module_creator.create_png_uml(lvl=lvl)
        self._package_creator.create_png_uml(lvl=lvl)

    def create_svg_uml(
        self,
        lvl: UMLLevel = UMLLevel.BASE,
    ) -> None:
        self._module_creator.create_svg_uml(lvl=lvl)
        self._package_creator.create_svg_uml(lvl=lvl)


def parse_arguments() -> Namespace:
    description: str = "Generate UML diagrams from apps."
    parser: ArgumentParser = ArgumentParser(description=description)

    parser.add_argument(
        "-s",
        "--source",
        required=True,
        type=str,
        help="Source directory containing the code to generate UML diagrams from.",
    )

    parser.add_argument(
        "-d",
        "--destination",
        required=False,
        type=str,
        default=None,
        help="Destination directory to store the generated UML diagram files.",
    )

    parser.add_argument(
        "-t",
        "--type",
        choices=["raw", "styled", "svg", "png"],
        default="raw",
        help="Type of output for the UML diagrams. Options are: raw, styled, svg, png. Default is 'svg'.",
    )

    parser.add_argument(
        "-l",
        "--level",
        choices=["base", "minimal", "moderate", "full"],
        default="base",
        help="Level of detail for the UML diagrams. Options are: base, minimal, moderate, full. Default is base.",
    )
    return parser.parse_args()


def main() -> None:
    name_space: Namespace = parse_arguments()

    uml_creator: UmlCreator = UmlCreator(
        src=name_space.source,
        dst=name_space.destination,
    )
    lvl: UMLLevel = getattr(UMLLevel, name_space.level.upper())
    match name_space.type:
        case "raw":
            uml_creator.create_raw_uml(lvl=lvl)
        case "styled":
            uml_creator.create_styled_uml(lvl=lvl)
        case "png":
            uml_creator.create_png_uml(lvl=lvl)
        case "svg":
            uml_creator.create_svg_uml(lvl=lvl)
        case _:
            raise ValueError(f"Not in the Options")


if __name__ == "__main__":
    # python3.10 -m black --line-length=79 --target-version=py310 create_uml.py
    # python3.10 -m mypy create_uml.py --strict
    # python3.10 -m isort create_uml.py --profile black

    main()
