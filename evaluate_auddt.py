#!/usr/bin/env python3
# evaluate_auddt.py
# Alias entrypoint for Dhwani-Kavach AUDDT evaluation benchmark

import importlib.util
import os
import sys

script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "18_evaluate_auddt.py")
spec = importlib.util.spec_from_file_location("eval_auddt", script_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

if __name__ == "__main__":
    module.main()
