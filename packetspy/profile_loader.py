import re
from pathlib import Path

import yaml

MAX_PROFILE_NAME_LENGTH = 20
PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_]+$")


class ProfileValidationError(ValueError):
    """Raised when a profile has invalid configuration."""
    pass


class Profile:
    def __init__(self, data):
        name = data.get("name", "")
        if not name:
            raise ProfileValidationError("Profile must have a 'name' field")
        if len(name) > MAX_PROFILE_NAME_LENGTH:
            raise ProfileValidationError(
                f"Profile name '{name}' exceeds {MAX_PROFILE_NAME_LENGTH} characters"
            )
        if not PROFILE_NAME_PATTERN.match(name):
            raise ProfileValidationError(
                f"Profile name '{name}' must contain only letters, numbers, and underscores"
            )
        self.name = name
        self.description = data.get("description", "")
        self.processes = [p.lower() for p in data.get("processes", [])]
        self.ports = data.get("ports", {})
        self.port_ranges = data.get("port_ranges", {})
        self.source_ips = data.get("source_ips", [])
        self.dest_ips = data.get("dest_ips", [])
        self.bpf_override = data.get("bpf_filter_override")
        self.addons = data.get("addons", [])

    def generate_bpf(self):
        """Auto-generate BPF filter from port definitions, or return override."""
        if self.bpf_override:
            return self.bpf_override

        clauses = []

        for proto in ("tcp", "udp"):
            for port in self.ports.get(proto, []):
                clauses.append(f"({proto} port {port})")

        for proto in ("tcp", "udp"):
            for r in self.port_ranges.get(proto, []):
                clauses.append(f"({proto} portrange {r['start']}-{r['end']})")

        for ip in self.source_ips:
            keyword = "src net" if "/" in ip else "src host"
            clauses.append(f"({keyword} {ip})")

        for ip in self.dest_ips:
            keyword = "dst net" if "/" in ip else "dst host"
            clauses.append(f"({keyword} {ip})")

        if not clauses:
            return None

        return " or ".join(clauses)


def load_profile(path):
    """Load a YAML profile file and return a Profile object."""
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return Profile(data)


def list_profiles(profiles_dir="profiles"):
    """List all YAML profile files in the given directory."""
    p = Path(profiles_dir)
    if not p.exists():
        return []
    return sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml")))
