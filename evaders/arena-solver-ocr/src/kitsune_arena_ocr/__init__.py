# evaders/arena-solver-ocr/__init__ — the OCR evasion package (beat the arena text gate, owned gates only).
# Exposes the testable solve flow; the heavy TrOCR recognizer lives in recognizer.py (imported lazily).

from .solver import EthicsError, Recognizer, decode_png_data_uri, is_own_target, solve_text

__all__ = ["EthicsError", "Recognizer", "decode_png_data_uri", "is_own_target", "solve_text"]
