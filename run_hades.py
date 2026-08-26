#!/usr/bin/env python3
"""
HadesAI Launcher - Main Entry Point
Runs the main HadesAI application with GUI
"""

import sys
from HadesAI import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Error launching HadesAI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
