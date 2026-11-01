"""
Name: Andy Delly
Student ID: 041089020
"""

import xml.etree.ElementTree as ET
import json
import sys
import yaml 

class AuditError(Exception):
    """Custom exception for audit errors."""
    pass

def load_policy(policy_file):
    """Loads the YAML policy file safely."""
    try:
        with open(policy_file, "r", encoding="utf-8") as f:
            policy = yaml.safe_load(f)
            return policy if policy else {}
    except (FileNotFoundError, yaml.YAMLError, OSError) as e:
        print(f"Error reading policy file '{policy_file}': {e}")
        sys.exit(1)

def load_inventory(xml_file, policy_file):
    """Reads the inventory XML file and collects statistics."""

    policy = load_policy(policy_file)

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError, OSError) as e:
        print(f"Error reading inventory file '{xml_file}': {e}")
        sys.exit(1)

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

    violations = []
    compliant_ids = []

    # Policy rules for Tier 2
    min_os_policy = policy.get("min_os", {})
    require_owner = policy.get("require_owner", False)
    max_down_limit = policy.get("max_down interfaces")

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

        device_down_count = 0

        # Count interface status
        for interface in device.findall("interface"):

            status = interface.get("status","")

            if status == "up":
                interfaces["up"] += 1

            elif status == "down":
                interfaces["down"] += 1
                device_down_count += 1

            else:
                interfaces["other"] += 1

        # TIER 2 VIOLATION CHECKS
        dev_violations = []

        # unknown_role check
        if min_os_policy is not None and role not in min_os_policy:
            dev_violations.append({
                "device": device_id,
                "type": "unknown_role",
                "role": role
            })

        # missing_owner check
        owner_elem = device.find("owner")
        has_owner = owner_elem is not None and owner_elem.text and owner_elem.text.strip()
        if require_owner and not has_owner:
            dev_violations.append({
                "device": device_id,
                "type": "missing_owner"
            })

        # too_many_down check
        if max_down_limit is not None and device_down_count > max_down_limit:
            dev_violations.append({
                "device": device_id,
                "type": "too_many_down",
                "down": device_down_count
            })

        # violations or compliant status
        if dev_violations:
            violations.extend(dev_violations)
        else:
            compliant_ids.append(device_id)

    audit_data = {
        "site": site,
        "total_devices": total_devices,
        "skipped_devices": skipped_devices,
        "roles": roles,
        "interfaces": interfaces,
        "violations": violations,
        "compliant": sorted(compliant_ids)
    }

    return audit_data

def main():
    """Runs the program."""

    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    inventory_file = sys.argv[1]
    policy_file = sys.argv[2]

    audit_data = load_inventory(inventory_file, policy_file)

    with open("audit.json", "w") as output_file:
        json.dump(audit_data, output_file, indent=4)

    print("Audit report created: audit.json")

if __name__ == "__main__":
    main()