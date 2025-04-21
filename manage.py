#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    # Add the current directory to the path
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    try:
        from fastapi_admin.cli import cli
    except ImportError:
        print("fastapi-admin package is not installed. Please install it with:")
        print("pip install fastapi-admin")
        sys.exit(1)
    
    cli()
