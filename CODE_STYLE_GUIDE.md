# HadesAI Code Style Guide

## Overview
This guide establishes consistent code style for the HadesAI project.

## Naming Conventions

### Classes
- **Style**: PascalCase
- **Examples**: `HadesAI`, `NetworkMonitor`, `ExploitationEngine`
- **Pattern**: Nouns, descriptive, specific

### Functions & Methods
- **Style**: snake_case
- **Examples**: `run_exploit`, `check_vulnerability`, `save_state`
- **Pattern**: Verbs, descriptive, clear intent

### Variables
- **Style**: snake_case
- **Examples**: `target_url`, `threat_level`, `max_iterations`
- **Protected**: `_protected_var`
- **Private**: `__private_var`

### Constants
- **Style**: UPPER_SNAKE_CASE
- **Examples**: `MAX_RETRIES`, `DEFAULT_TIMEOUT`
- **Location**: Top of file or config module

## Code Organization

### File Structure
```python
"""
Module docstring - Purpose and usage.
"""

# ============================================================================
# IMPORTS
# ============================================================================
import os
import sys
from typing import Dict, List, Any

# Third-party imports
from PyQt6.QtWidgets import QMainWindow

# Local imports
from core.config import DEFAULT_TIMEOUT


# ============================================================================
# CONSTANTS
# ============================================================================
MAX_RETRIES = 3
DEFAULT_CHUNK_SIZE = 1024


# ============================================================================
# DATA CLASSES
# ============================================================================
class Experience:
    """Data class for storing experiences."""
    pass


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def validate_url(url: str) -> bool:
    """Validate URL format."""
    pass


# ============================================================================
# MAIN CLASSES
# ============================================================================
class HadesAI:
    """Main AI core."""
    pass
```

### Method Organization within Classes
```python
class ClassName:
    """Class docstring."""
    
    # ===== Magic Methods =====
    def __init__(self):
        pass
    
    def __str__(self):
        pass
    
    # ===== Public Methods =====
    def public_method(self):
        pass
    
    # ===== Protected Methods =====
    def _protected_method(self):
        pass
    
    # ===== Private Methods =====
    def __private_method(self):
        pass
```

## Docstring Format

### Module Docstring
```python
"""
Short description of module purpose.

Longer description explaining what this module does,
how to use it, and any important details.
"""
```

### Class Docstring
```python
class MyClass:
    """
    Short description of class purpose.
    
    Longer description with more details about the class,
    its usage, and important behaviors.
    
    Attributes:
        name (str): Description of name attribute
        count (int): Description of count attribute
    """
```

### Method Docstring
```python
def my_method(self, arg1: str, arg2: int) -> bool:
    """
    Short description of what this method does.
    
    Longer description with more details about the method,
    its behavior, and any important notes.
    
    Args:
        arg1 (str): Description of arg1
        arg2 (int): Description of arg2
    
    Returns:
        bool: Description of return value
    
    Raises:
        ValueError: If arg1 is empty
        TypeError: If arg2 is not int
    """
```

## Type Hints

### Basic Usage
```python
# Good
def process_data(items: List[str]) -> Dict[str, Any]:
    pass

# Also good
from typing import Optional
def find_item(query: str) -> Optional[str]:
    pass

# Classes
class Config:
    def __init__(self, name: str, timeout: int = 30) -> None:
        pass
```

### Complex Types
```python
from typing import Union, Callable

def execute(fn: Callable[[str], int], data: Union[str, bytes]) -> int:
    pass
```

## Import Organization

### Order
1. Standard library imports
2. Third-party imports
3. Local imports

### Format
```python
# Standard library
import os
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Third-party
from PyQt6.QtWidgets import QMainWindow, QPushButton
from PyQt6.QtCore import QThread, pyqtSignal

# Local
from core.config import DEFAULT_TIMEOUT
from core.logger import setup_logger
from security.proxy import ProxyManager
```

## Code Formatting

### Line Length
- Maximum: 100 characters
- Docstrings: 80 characters

### Indentation
- Use 4 spaces (not tabs)
- No mixed indentation

### Spacing
```python
# Around operators
x = 1 + 2  # Good
x=1+2      # Bad

# Function definitions
def function(arg1: str, arg2: int = 5) -> str:  # Good
def function(arg1:str,arg2:int=5)->str:          # Bad

# Class definitions
class MyClass(ParentClass):  # Good
class MyClass(ParentClass ):  # Bad
```

### Comments

#### Single-line comments
```python
# This does something important
x = process(data)
```

#### Multi-line comments
```python
# This is a complex operation that:
# 1. Validates input
# 2. Processes data
# 3. Returns result
result = complex_operation(data)
```

#### Inline comments (sparingly)
```python
x = expensive_operation()  # Cache result for reuse
```

#### Section headers
```python
# ============================================================================
# SECTION NAME
# ============================================================================
```

## Error Handling

### Proper exception handling
```python
# Good
try:
    result = risky_operation()
except ValueError as e:
    logger.error(f"Invalid value: {e}")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    return None

# Bad
try:
    result = risky_operation()
except:
    pass
```

## Logging

### Setup
```python
import logging

logger = logging.getLogger(__name__)

# In functions
logger.debug("Debug message: %s", variable)
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message: %s", error)
```

### Log Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: Confirmation that things work as expected
- **WARNING**: Potential problem
- **ERROR**: Serious problem
- **CRITICAL**: Serious problem preventing operation

## Testing

### Test file naming
- `test_module.py` for module
- `test_class.py` for class
- `test_function.py` for function

### Test function naming
```python
def test_function_success():
    """Test successful case."""
    pass

def test_function_invalid_input():
    """Test with invalid input."""
    pass

def test_function_edge_case():
    """Test edge case."""
    pass
```

## Git Commit Messages

### Format
```
<type>: <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring
- `style`: Formatting changes
- `docs`: Documentation
- `test`: Test additions/changes
- `chore`: Build, dependencies

### Examples
```
feat: add autonomous agent integration

- Added FallbackLLM for offline operation
- Integrated with HadesAI GUI
- Comprehensive documentation

Fixes #123
```

## Common Patterns

### Configuration
```python
# config.py
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BUFFER_SIZE = 1024

class Config:
    def __init__(self):
        self.timeout = DEFAULT_TIMEOUT
```

### Logging setup
```python
# logger.py
import logging

def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
```

### Error handling pattern
```python
def risky_operation() -> Optional[Result]:
    """Perform risky operation safely."""
    try:
        # Do risky thing
        return result
    except SpecificError as e:
        logger.error(f"Specific error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise
```

## What NOT To Do

❌ **Don't**:
- Use `from module import *`
- Use single letter variable names (except loop indices)
- Create functions longer than 50 lines
- Create classes larger than 300 lines
- Leave commented-out code
- Mix spaces and tabs
- Use magic numbers (use constants instead)
- Ignore type hints
- Skip docstrings
- Use vague variable names

## Checklist Before Committing

- [ ] Code follows this style guide
- [ ] All tests pass
- [ ] No PEP 8 violations
- [ ] Docstrings complete
- [ ] Type hints added
- [ ] No debug code left
- [ ] Comments are clear
- [ ] Imports organized
- [ ] No dead code
- [ ] Commit message clear

## Tools

### Code formatting
```bash
# Install black
pip install black

# Format file
black your_file.py
```

### Linting
```bash
# Install pylint
pip install pylint

# Check file
pylint your_file.py
```

### Type checking
```bash
# Install mypy
pip install mypy

# Check file
mypy your_file.py
```

---

**Version**: 1.0
**Last Updated**: 2026-01-26
**Status**: Active
