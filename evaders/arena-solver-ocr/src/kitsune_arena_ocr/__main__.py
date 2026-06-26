# evaders/arena-solver-ocr/__main__ — module entrypoint: python -m kitsune_arena_ocr (delegates to runner).
# Thin shim so the package is runnable; the real flow + ML load live in runner.py (tier-2 IO).

from .runner import main

if __name__ == "__main__":
    main()
