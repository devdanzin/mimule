"""Generate and save run metadata for mimule fuzzing sessions.

Ported from lafleur/metadata.py with these adaptations:

  1. psutil dependency removed — mimule has no runtime deps. Hardware
     info now comes from stdlib: os.cpu_count() for logical count,
     /proc/meminfo on Linux for RAM (None elsewhere), shutil.disk_usage
     for disk. Physical CPU count is not available without psutil and
     is simply omitted.

  2. target_python → target_runtime. lafleur queries the target Python
     interpreter via subprocess for version/config/packages. mimule's
     target runtime is node + Monkey, so we instead capture
     ``node --version`` output plus a placeholder for the Monkey
     interpreter path. Full runtime introspection waits until we know
     Henry's invocation contract.

  3. The env_vars capture no longer hard-codes PYTHON_JIT / PYTHON_LLTRACE
     — those are CPython-specific. Placeholder for Monkey-specific env
     vars is empty; we'll populate once Henry ships JIT tracing flags.

  4. get_git_info points at the mimule repo, not lafleur.

Docker-style instance naming (adjective-noun) is preserved verbatim
from lafleur — it's language-agnostic and the name pool is hand-picked.
"""

import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import uuid
from importlib.metadata import distributions
from pathlib import Path

from mimule.utils import save_json_file

ADJECTIVES = [
    "admiring", "adoring", "agitated", "amazing", "angry", "awesome",
    "backstabbing", "bold", "boring", "clever", "cocky", "compassionate",
    "condescending", "cranky", "determined", "distracted", "dreamy",
    "eager", "ecstatic", "elastic", "elated", "elegant", "eloquent",
    "epic", "fervent", "festive", "flamboyant", "focused", "friendly",
    "frosty", "funny", "gallant", "gifted", "goofy", "gracious", "happy",
    "hardcore", "heuristic", "hopeful", "hungry", "infallible", "inspiring",
    "jolly", "jovial", "keen", "kind", "laughing", "loving", "lucid",
    "magical", "modest", "musing", "mystifying", "naughty", "nervous",
    "nice", "nifty", "nostalgic", "objective", "optimistic", "peaceful",
    "pedantic", "pensive", "practical", "priceless", "quirky", "quizzical",
    "recursing", "relaxed", "reverent", "romantic", "sad", "serene",
    "sharp", "silly", "sleepy", "stoic", "strange", "stupefied",
    "suspicious", "sweet", "tender", "thirsty", "trusting", "unruffled",
    "upbeat", "vibrant", "vigilant", "vigorous", "wizardly", "wonderful",
    "xenodochial", "youthful", "zealous", "zen",
]

NOUNS = [
    "albattani", "archimedes", "babbage", "bell", "blackwell", "bohr",
    "brahmagupta", "brown", "carson", "cori", "curie", "darwin", "diffie",
    "dijkstra", "einstein", "elion", "euclid", "fermat", "feynman",
    "franklin", "galileo", "gates", "goldberg", "hawking", "heisenberg",
    "hodgkin", "hopper", "hypatia", "johnson", "jones", "keller", "kepler",
    "kilby", "kowalevski", "lalande", "lamarr", "leakey", "leavitt",
    "lovelace", "mayer", "mccarthy", "mcclintock", "meitner", "mendel",
    "meninsky", "mirzakhani", "morse", "newton", "nightingale", "nobel",
    "noether", "payne", "perlman", "pike", "poitras", "ptolemy",
    "ramanujan", "ritchie", "rosalind", "sagan", "shannon", "shockley",
    "sinoussi", "snyder", "stallman", "stonebraker", "swartz", "tereshkova",
    "tesla", "thompson", "torvalds", "turing", "villani", "wescoff",
    "williams", "wing", "wozniak", "wright", "yalow", "yonath",
]


def generate_docker_style_name() -> str:
    """Generate a random Docker-style name (adjective-noun)."""
    return f"{random.choice(ADJECTIVES)}-{random.choice(NOUNS)}"


def get_git_info() -> dict[str, str | bool]:
    """Get git commit hash and dirty status for the mimule repository."""
    try:
        package_dir = Path(__file__).parent.parent
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=package_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        commit_hash = result.stdout.strip() if result.returncode == 0 else "unknown"

        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=package_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_dirty = bool(result.stdout.strip()) if result.returncode == 0 else False

        return {"commit": commit_hash, "dirty": is_dirty}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"commit": "unknown", "dirty": False}


def get_installed_packages() -> list[dict[str, str]]:
    """Get list of installed packages with their versions from the current interpreter."""
    packages = []
    for dist in distributions():
        try:
            packages.append({"name": dist.metadata["Name"], "version": dist.metadata["Version"]})
        except Exception as e:
            print(f"[!] Warning: Could not read package metadata: {e}", file=sys.stderr)
    return sorted(packages, key=lambda p: p["name"].lower())


def _get_total_ram_bytes() -> int | None:
    """Return total system RAM in bytes, or None if unavailable.

    Uses /proc/meminfo on Linux (mimule's primary platform). Returns
    None on other platforms — psutil would give cross-platform numbers
    but mimule avoids the dependency.
    """
    try:
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def get_target_runtime_info(runtime_path: str) -> dict:
    """Retrieve metadata from the target runtime.

    STUB port: lafleur spawns the target Python interpreter and queries
    version/config/packages. mimule's target is Henry's Monkey runtime,
    which currently means invoking ``node`` (or eventually a dedicated
    ``monkey`` binary). This stub just captures ``<runtime> --version``
    output and leaves the other fields empty.

    Returns:
        Dictionary with keys: version, executable, packages, fallback.
    """
    try:
        result = subprocess.run(
            [runtime_path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return {
                "version": result.stdout.strip(),
                "executable": runtime_path,
                "packages": [],
                "fallback": False,
            }
        print(
            f"[!] Warning: Failed to get info from target runtime ({runtime_path}): "
            f"{result.stderr.strip()}",
            file=sys.stderr,
        )
    except subprocess.TimeoutExpired:
        print(
            f"[!] Warning: Timeout getting info from target runtime ({runtime_path})",
            file=sys.stderr,
        )
    except (FileNotFoundError, OSError) as e:
        print(
            f"[!] Warning: Error getting info from target runtime ({runtime_path}): {e}",
            file=sys.stderr,
        )

    return {
        "version": "unknown",
        "executable": runtime_path,
        "packages": [],
        "fallback": True,
    }


def load_existing_metadata(metadata_path: Path) -> dict | None:
    """Load existing metadata file if it exists."""
    if not metadata_path.exists():
        return None

    try:
        with open(metadata_path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Warning: Could not load existing metadata: {e}", file=sys.stderr)
        return None


def generate_run_metadata(output_dir: Path, args: argparse.Namespace) -> dict:
    """Generate comprehensive run metadata and save to a JSON file.

    Identity persistence: if run_metadata.json already exists in
    output_dir, the existing run_id and instance_name are preserved.
    Dynamic fields (hardware, config) are always refreshed.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "run_metadata.json"

    existing_metadata = load_existing_metadata(metadata_path)

    if existing_metadata:
        run_id = existing_metadata.get("run_id", str(uuid.uuid4()))
        instance_name = existing_metadata.get("instance_name") or generate_docker_style_name()
        print(
            f"[+] Reusing existing instance identity: {instance_name} ({run_id[:8]}...)",
            file=sys.stderr,
        )
    else:
        run_id = str(uuid.uuid4())
        instance_name = getattr(args, "instance_name", None) or generate_docker_style_name()
        print(
            f"[+] Created new instance identity: {instance_name} ({run_id[:8]}...)",
            file=sys.stderr,
        )

    target_runtime = getattr(args, "target_runtime", None) or "node"
    target_info = get_target_runtime_info(target_runtime)

    total_ram_bytes = _get_total_ram_bytes()
    metadata = {
        "run_id": run_id,
        "instance_name": instance_name,
        "environment": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "target_runtime": target_runtime,
            "runtime_version": target_info["version"],
            "runtime_executable": target_info["executable"],
            "target_info_fallback": target_info.get("fallback", False),
            "mimule_version": get_git_info(),
            "host_packages": get_installed_packages(),
        },
        "hardware": {
            "cpu_count_logical": os.cpu_count(),
            "total_ram_gb": (
                round(total_ram_bytes / (1024**3), 2) if total_ram_bytes else None
            ),
            "disk_free_gb": round(shutil.disk_usage(output_dir).free / (1024**3), 2),
        },
        "configuration": {
            "execution_mode": "session" if getattr(args, "session_fuzz", False) else "legacy",
            "args": vars(args),
            "env_vars": {
                # Placeholder — Monkey-specific env vars will be populated once
                # Henry ships his JIT tracing flags.
            },
        },
    }

    metadata["max_sessions"] = getattr(args, "max_sessions", None)
    metadata["max_mutations_per_session"] = getattr(args, "max_mutations_per_session", None)
    metadata["global_seed"] = getattr(args, "seed", None)
    metadata["workdir"] = (
        str(getattr(args, "workdir", None)) if getattr(args, "workdir", None) else None
    )
    metadata["keep_children"] = getattr(args, "keep_children", False)
    metadata["dry_run"] = getattr(args, "dry_run", False)
    metadata["mutator_filter"] = getattr(args, "mutators", None)
    metadata["forced_strategy"] = getattr(args, "strategy", None)

    save_json_file(metadata_path, metadata, sort_keys=False, default=str)

    return metadata
