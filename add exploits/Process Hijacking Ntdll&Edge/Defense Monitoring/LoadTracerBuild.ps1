# Build script for LoaderTrace.cpp (run from "x64 Native Tools Command Prompt for VS").
param(
    [string]$Source = "LoaderTrace.cpp",
    [string]$Output = "LoaderTrace.exe"
)

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "cl.exe not found. Open the 'x64 Native Tools Command Prompt for VS' and rerun:"
    Write-Host "  cl /nologo /EHsc /W4 $Source /link /out:$Output Dbghelp.lib"
    exit 1
}

& cl /nologo /EHsc /W4 $Source /link /out:$Output Dbghelp.lib