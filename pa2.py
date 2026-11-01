"""
Name: Andy Delly
Student ID: 041089020
"""

import xml.etree.ElementTree as ET
import json
import sys


class AuditError(Exception):
    """Custom exception for audit errors."""
    pass


def load_inventory(xml_file):
    """Reads the inventory XML file and collects statistics."""

    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Get site name if it exists
    site = root.get("site")

    total_devices = 0
    skipped_devices = 0

    roles = {}

    interfaces = {
        "up": 0,
        "down": 0,
        "other": 0
    }

    # Go through each device
    for device in root.findall("device"):

        # Check if device has an ID
        device_id = device.get("id")

        if device_id is None:
            skipped_devices += 1
            continue

        total_devices += 1

        # Count roles
        role = device.get("role","unknown")

        if role in roles:
            roles[role] += 1
        else:
            roles[role] = 1

        # Count interface status
        for interface in device.findall("interface"):

            status = interface.get("status","")

            if status == "up":
                interfaces["up"] += 1

            elif status == "down":
                interfaces["down"] += 1

            else:
                interfaces["other"] += 1

    audit_data = {
        "site": site,
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": [],
        "compliant": []
    }

    return audit_data


def main():
    """Runs the program."""

    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    inventory_file = sys.argv[1]

    audit_data = load_inventory(inventory_file)

    with open("audit.json", "w") as output_file:
        json.dump(audit_data, output_file, indent=4)

    print("Audit report created: audit.json")


if __name__ == "__main__":
    main()