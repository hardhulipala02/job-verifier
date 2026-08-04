import os
import sys

# Ensure the project root (flat modules) is importable from tests/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
