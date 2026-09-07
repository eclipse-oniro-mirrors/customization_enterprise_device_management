#!/usr/bin/env python3
"""Check and fix user_config.xml test_cases path for OpenHarmony developer test framework.

Usage:
    python3 fix_test_config.py <source-root> <product-name>

The test framework resolves relative paths from its own src/ directory, not the source root.
This script ensures test_cases/dir is set to the correct absolute path.
"""

import os
import sys
import xml.etree.ElementTree as ET


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 fix_test_config.py <source-root> <product-name>")
        sys.exit(1)

    source_root = os.path.abspath(sys.argv[1])
    product_name = sys.argv[2]

    config_path = os.path.join(
        source_root,
        "test",
        "testfwk",
        "developer_test",
        "config",
        "user_config.xml",
    )

    if not os.path.exists(config_path):
        print("ERROR: user_config.xml not found at {}".format(config_path))
        sys.exit(1)

    expected_dir = os.path.join(source_root, "out", product_name, "tests")
    expected_dir = os.path.normpath(expected_dir)

    tree = ET.parse(config_path)
    root = tree.getroot()

    test_cases_node = root.find("test_cases")
    if test_cases_node is None:
        test_cases_node = ET.SubElement(root, "test_cases")

    dir_node = test_cases_node.find("dir")
    if dir_node is None:
        dir_node = ET.SubElement(test_cases_node, "dir")

    current_value = dir_node.text.strip() if dir_node.text else ""

    if current_value == expected_dir:
        print("OK: test_cases/dir already set correctly to {}".format(expected_dir))
        return

    if current_value:
        if os.path.isabs(current_value) and os.path.exists(current_value):
            print("OK: test_cases/dir is an existing absolute path: {}".format(current_value))
            return
        print("FIXING: test_cases/dir was '{}' (relative or non-existent)".format(current_value))
    else:
        print("FIXING: test_cases/dir was empty")

    dir_node.text = expected_dir

    tree.write(config_path, encoding="utf-8", xml_declaration=True)
    print("FIXED: test_cases/dir set to {}".format(expected_dir))


if __name__ == "__main__":
    main()
