#!/usr/bin/env python3
"""Push component .so files to device by parsing BUILD.gn install rules.

Usage:
    python3 push_component_so.py <source-root> <product-name> <part-name>

The script:
1. Locates the component's source directory via bundle.json
2. Parses all BUILD.gn files to determine each .so's device install path
3. Finds compiled .so files in the artifact directory
4. Pushes each .so to the device via hdc

Install path rules (from BUILD.gn):
    default                          -> /system/lib/
    innerapi_tags = ["platformsdk"] -> /system/lib/platformsdk/
    relative_install_dir = "xxx"    -> /system/lib/xxx/
    shlib_type = "ani"             -> /system/lib/module/ani/
"""

import json
import os
import re
import subprocess
import sys


def find_component_dir(source_root, part_name):
    """Find the component's source directory by searching bundle.json files."""
    for root, dirs, files in os.walk(source_root):
        if ".git" in dirs:
            dirs.remove(".git")
        # Skip out/ and .repo/ to avoid searching build artifacts
        if os.path.basename(root) == "out" or os.path.basename(root) == ".repo":
            dirs.clear()
            continue
        if "bundle.json" in files:
            json_path = os.path.join(root, "bundle.json")
            try:
                with open(json_path) as f:
                    data = json.load(f)
                if data.get("component", {}).get("name") == part_name:
                    return root
            except (json.JSONDecodeError, KeyError):
                continue
    return None


def get_subsystem(component_dir):
    """Get subsystem name from bundle.json."""
    bundle_path = os.path.join(component_dir, "bundle.json")
    with open(bundle_path) as f:
        data = json.load(f)
    return data.get("component", {}).get("subsystem", "")


def parse_build_gn_files(component_dir):
    """Parse all BUILD.gn files to find shared library install paths.

    Returns a dict: { "libxxx.z.so": "device_subdir" }
    where device_subdir is relative to /system/lib/ (empty string = default).
    """
    so_mapping = {}

    build_gn_files = []
    for root, dirs, files in os.walk(component_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        if "BUILD.gn" in files:
            build_gn_files.append(os.path.join(root, "BUILD.gn"))

    pat_lib = re.compile(r'ohos_shared_library\("([^"]+)"\)')
    pat_relative = re.compile(r'relative_install_dir\s*=\s*"([^"]+)"')
    pat_innerapi = re.compile(r'innerapi_tags\s*=\s*\[.*"platformsdk".*\]')
    pat_ani = re.compile(r'shlib_type\s*=\s*"ani"')

    for gn_file in build_gn_files:
        with open(gn_file) as f:
            lines = f.readlines()

        shared_libs = []
        for i, line in enumerate(lines):
            m = pat_lib.search(line)
            if m:
                shared_libs.append((i, m.group(1)))

        if not shared_libs:
            continue

        for idx, (start_line, target_name) in enumerate(shared_libs):
            end_line = shared_libs[idx + 1][0] if idx + 1 < len(shared_libs) else len(lines)
            block_text = "".join(lines[start_line:end_line])

            so_name = "lib{}.z.so".format(target_name)
            subdir = ""

            if pat_ani.search(block_text):
                subdir = "module/ani"
            elif pat_innerapi.search(block_text):
                subdir = "platformsdk"
            else:
                m = pat_relative.search(block_text)
                if m:
                    subdir = m.group(1).rstrip("/")

            so_mapping[so_name] = subdir

    return so_mapping


def find_artifact_dir(source_root, product, subsystem, part_name, so_mapping):
    """Find the directory containing compiled .so files."""
    direct_path = os.path.join(source_root, "out", product, subsystem, part_name)
    if os.path.isdir(direct_path):
        so_count = sum(1 for f in os.listdir(direct_path) if f in so_mapping)
        if so_count > 0:
            return direct_path

    out_dir = os.path.join(source_root, "out", product)
    if not os.path.isdir(out_dir):
        return None

    best_dir = None
    best_count = 0
    for root, dirs, files in os.walk(out_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        so_count = sum(1 for f in files if f in so_mapping)
        if so_count > best_count:
            best_count = so_count
            best_dir = root
        if best_count == len(so_mapping):
            break

    return best_dir


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 push_component_so.py <source-root> <product-name> <part-name>")
        sys.exit(1)

    source_root = os.path.abspath(sys.argv[1])
    product = sys.argv[2]
    part_name = sys.argv[3]

    component_dir = find_component_dir(source_root, part_name)
    if not component_dir:
        print("[ERROR] Cannot find component directory for part: {}".format(part_name))
        sys.exit(1)

    subsystem = get_subsystem(component_dir)
    so_mapping = parse_build_gn_files(component_dir)

    if not so_mapping:
        print("[ERROR] No shared libraries found in BUILD.gn for part: {}".format(part_name))
        sys.exit(1)

    artifact_dir = find_artifact_dir(source_root, product, subsystem, part_name, so_mapping)
    if not artifact_dir:
        print("[ERROR] Cannot find artifact directory. Please build the component first:")
        print("        ./build.sh --product-name {} --ccache --build-target {}".format(product, part_name))
        sys.exit(1)

    try:
        result = subprocess.run(
            ["hdc", "list", "targets"], capture_output=True, text=True, timeout=30
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[ERROR] hdc not found in PATH or not responding.")
        sys.exit(1)

    output = result.stdout.strip()
    devices = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and "Empty" not in line
    ]

    if not devices:
        print("[ERROR] No device connected. Run 'hdc list targets' to check.")
        sys.exit(1)

    device_sn = devices[0]

    print("=" * 44)
    print("  Push {} .so to device".format(part_name))
    print("=" * 44)
    print("  Product:    {}".format(product))
    print("  Artifact:   {}".format(artifact_dir))
    print("  Device:     {}".format(device_sn))
    print("  SO count:   {}".format(len(so_mapping)))
    print("=" * 44)
    print()

    print("[INFO] Remounting /system as rw...")
    subprocess.run(
        ["hdc", "shell", "mount -o rw,remount,rw /"],
        capture_output=True,
        timeout=30,
    )

    print("[INFO] Pushing {} .so files...".format(len(so_mapping)))
    print()

    success = 0
    failed = 0

    for so_name in sorted(so_mapping.keys()):
        subdir = so_mapping[so_name]
        local_file = os.path.join(artifact_dir, so_name)

        if subdir:
            device_dir = "/system/lib/{}".format(subdir)
        else:
            device_dir = "/system/lib"

        if not os.path.isfile(local_file):
            print("  [MISSING] {} (not built)".format(so_name))
            failed += 1
            continue

        try:
            subprocess.run(
                ["hdc", "shell", "mkdir -p {}".format(device_dir)],
                capture_output=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            pass

        try:
            result = subprocess.run(
                ["hdc", "file", "send", local_file, "{}/{}".format(device_dir, so_name)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print("  [   OK  ] {} -> {}/".format(so_name, device_dir))
                success += 1
            else:
                print("  [ FAILED] {} -> {}/".format(so_name, device_dir))
                failed += 1
        except subprocess.TimeoutExpired:
            print("  [ FAILED] {} (timeout)".format(so_name))
            failed += 1

    print()
    print("=" * 44)
    print("  Summary: {}/{} succeeded, {} failed".format(success, len(so_mapping), failed))
    print("=" * 44)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
