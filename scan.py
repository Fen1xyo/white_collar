import os
import argparse


COMMENT_STYLES = {
    ".py":   ("# ", ""),
    ".js":   ("// ", ""),
    ".ts":   ("// ", ""),
    ".jsx":  ("// ", ""),
    ".tsx":  ("// ", ""),
    ".cpp":  ("// ", ""),
    ".c":    ("// ", ""),
    ".h":    ("// ", ""),
    ".java": ("// ", ""),
    ".go":   ("// ", ""),
    ".rs":   ("// ", ""),
    ".css":  ("/* ", " */"),
    ".html": ("<!-- ", " -->"),
    ".xml":  ("<!-- ", " -->"),
    ".sh":   ("# ", ""),
    ".rb":   ("# ", ""),
    ".php":  ("// ", ""),
    ".sql":  ("-- ", ""),
    ".lua":  ("-- ", ""),
    ".r":    ("# ", ""),
    ".yaml": ("# ", ""),
    ".yml":  ("# ", ""),
    ".toml": ("# ", ""),
}

DEFAULT_COMMENT = ("# ", "")


def get_comment(filepath: str, text: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    prefix, suffix = COMMENT_STYLES.get(ext, DEFAULT_COMMENT)
    return f"{prefix}{text}{suffix}"


def merge_files(
    source_dir: str,
    output_file: str,
    extensions: list[str] | None = None,
    encoding: str = "utf-8",
    skip_binary: bool = True,
) -> None:
    source_dir = os.path.abspath(source_dir)
    output_file = os.path.abspath(output_file)

    exts = [e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions] if extensions else None

    collected = []
    for root, dirs, files in os.walk(source_dir):
        # Skip hidden directories
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for filename in sorted(files):
            if filename.startswith("."):
                continue
            filepath = os.path.join(root, filename)
            # Skip the output file itself
            if filepath == output_file:
                continue
            ext = os.path.splitext(filename)[1].lower()
            if exts and ext not in exts:
                continue
            collected.append(filepath)

    total = len(collected)
    print(f"Found {total} file(s) in '{source_dir}'")

    with open(output_file, "w", encoding=encoding) as out:
        for i, filepath in enumerate(collected, 1):
            rel_path = os.path.relpath(filepath, source_dir)

            # Try to read as text
            content = None
            if skip_binary:
                try:
                    with open(filepath, "r", encoding=encoding) as f:
                        content = f.read()
                except (UnicodeDecodeError, PermissionError):
                    print(f"  [{i}/{total}] SKIPPED (binary/unreadable): {rel_path}")
                    continue
            else:
                with open(filepath, "r", encoding=encoding, errors="replace") as f:
                    content = f.read()

            separator = get_comment(filepath, "=" * 60)
            header    = get_comment(filepath, f"FILE: {rel_path}")
            footer    = get_comment(filepath, "=" * 60)

            out.write(f"{separator}\n")
            out.write(f"{header}\n")
            out.write(f"{footer}\n\n")
            out.write(content)
            if not content.endswith("\n"):
                out.write("\n")
            out.write("\n")

            print(f"  [{i}/{total}] {rel_path}")

    print(f"\nDone! Merged into: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Merge all files in a directory into a single file with path comments."
    )
    parser.add_argument(
        "source_dir",
        nargs="?",
        default=".",
        help="Source directory to scan (default: current directory)",
    )
    parser.add_argument(
        "-o", "--output",
        default="merged_output.txt",
        help="Output file path (default: merged_output.txt)",
    )
    parser.add_argument(
        "-e", "--ext",
        nargs="*",
        metavar="EXT",
        help="Only include files with these extensions, e.g. -e .py .js .ts",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="File encoding (default: utf-8)",
    )
    parser.add_argument(
        "--include-binary",
        action="store_true",
        help="Try to include binary files (may produce garbled output)",
    )

    args = parser.parse_args()

    merge_files(
        source_dir=args.source_dir,
        output_file=args.output,
        extensions=args.ext,
        encoding=args.encoding,
        skip_binary=not args.include_binary,
    )


if __name__ == "__main__":
    main()
