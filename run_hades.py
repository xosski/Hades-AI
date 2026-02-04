#!/usr/bin/env python3
"""
HadesAI Launcher - Main Entry Point
Runs the main HadesAI application with GUI
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    try:
        from PyQt6.QtWidgets import QApplication
        from HadesAI import HadesGUI
        
        app = QApplication(sys.argv)
        window = HadesGUI()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error launching HadesAI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
