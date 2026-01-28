@echo off
REM Install network share dependencies

echo Installing HadesAI Network Share dependencies...
python -m pip install cryptography
echo.
echo Done. Run verify_network_deps.py to confirm.
pause
