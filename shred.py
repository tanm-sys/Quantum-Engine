#!/usr/bin/env python3
"""
File Shredding Module.

Provides a secure file shredding function that overwrites the file multiple times
before deletion to prevent data recovery. In production, you might use a dedicated library.
"""

import os
from pathlib import Path

def shred_file(file_path: str, passes: int = 3) -> None:
    path = Path(file_path)
    if not path.is_file():
        raise ValueError("Provided path is not a file.")
    length = path.stat().st_size
    with open(path, "ba+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    # After overwriting, delete the file.
    path.unlink()
