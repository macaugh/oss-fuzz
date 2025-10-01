#!/usr/bin/env python3
"""
Fuzzer crash monitor with Discord webhook notifications.
Monitors crash directories and sends alerts when new crashes are found.
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Set, Dict
import requests

# Configuration
FUZZING_DATA_DIR = Path("/fuzzing-data")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", 60))
STATE_FILE = Path("/app/crash_state.json")

def load_state() -> Dict[str, Set[str]]:
    """Load known crashes from state file."""
    if STATE_FILE.exists():
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            # Convert lists back to sets
            return {k: set(v) for k, v in data.items()}
    return {}

def save_state(state: Dict[str, Set[str]]):
    """Save known crashes to state file."""
    # Convert sets to lists for JSON serialization
    data = {k: list(v) for k, v in state.items()}
    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_crash_hash(crash_path: Path) -> str:
    """Generate hash of crash file for deduplication."""
    with open(crash_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]

def format_crash_message(fuzzer_name: str, crash_file: Path, crash_hash: str) -> dict:
    """Format crash information for Discord webhook."""

    # Read crash file (limit size)
    try:
        with open(crash_file, "rb") as f:
            crash_data = f.read(2000)
            crash_preview = crash_data.decode("utf-8", errors="replace")[:1000]
    except Exception as e:
        crash_preview = f"Error reading crash file: {e}"

    # Get file size
    file_size = crash_file.stat().st_size

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = {
        "embeds": [{
            "title": f"🐛 New Crash Found: {fuzzer_name}",
            "color": 15158332,  # Red color
            "fields": [
                {
                    "name": "Fuzzer",
                    "value": f"`{fuzzer_name}`",
                    "inline": True
                },
                {
                    "name": "Crash Hash",
                    "value": f"`{crash_hash}`",
                    "inline": True
                },
                {
                    "name": "File Size",
                    "value": f"{file_size} bytes",
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": timestamp,
                    "inline": False
                },
                {
                    "name": "Crash Preview",
                    "value": f"```\n{crash_preview}\n```",
                    "inline": False
                }
            ],
            "footer": {
                "text": "OSS-Fuzz Monitor"
            }
        }]
    }

    return message

def send_discord_alert(message: dict) -> bool:
    """Send alert to Discord webhook."""
    if not DISCORD_WEBHOOK_URL:
        print("Warning: DISCORD_WEBHOOK_URL not set, skipping alert")
        return False

    try:
        response = requests.post(
            DISCORD_WEBHOOK_URL,
            json=message,
            timeout=10
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending Discord alert: {e}")
        return False

def check_for_crashes(known_crashes: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Check all fuzzer directories for new crashes."""

    new_crashes_found = False

    # Iterate through fuzzer directories
    for fuzzer_dir in FUZZING_DATA_DIR.iterdir():
        if not fuzzer_dir.is_dir():
            continue

        fuzzer_name = fuzzer_dir.name
        crash_dir = fuzzer_dir / "crashes"

        if not crash_dir.exists():
            continue

        # Initialize set for this fuzzer if not exists
        if fuzzer_name not in known_crashes:
            known_crashes[fuzzer_name] = set()

        # Check for crash files
        for crash_file in crash_dir.glob("crash-*"):
            if not crash_file.is_file():
                continue

            # Generate hash for deduplication
            crash_hash = get_crash_hash(crash_file)

            # Check if this is a new crash
            if crash_hash not in known_crashes[fuzzer_name]:
                print(f"New crash found: {fuzzer_name} - {crash_file.name}")

                # Send Discord alert
                message = format_crash_message(fuzzer_name, crash_file, crash_hash)
                if send_discord_alert(message):
                    print(f"Discord alert sent for {fuzzer_name}")

                # Add to known crashes
                known_crashes[fuzzer_name].add(crash_hash)
                new_crashes_found = True

    return known_crashes, new_crashes_found

def get_stats() -> dict:
    """Collect fuzzing statistics."""
    stats = {}

    for fuzzer_dir in FUZZING_DATA_DIR.iterdir():
        if not fuzzer_dir.is_dir():
            continue

        fuzzer_name = fuzzer_dir.name
        crash_dir = fuzzer_dir / "crashes"
        corpus_dir = fuzzer_dir / "corpus"

        stats[fuzzer_name] = {
            "crashes": len(list(crash_dir.glob("crash-*"))) if crash_dir.exists() else 0,
            "corpus_size": len(list(corpus_dir.glob("*"))) if corpus_dir.exists() else 0
        }

    return stats

def main():
    """Main monitoring loop."""
    print("Starting OSS-Fuzz crash monitor...")
    print(f"Monitoring directory: {FUZZING_DATA_DIR}")
    print(f"Check interval: {CHECK_INTERVAL} seconds")
    print(f"Discord webhook: {'configured' if DISCORD_WEBHOOK_URL else 'NOT configured'}")

    # Load known crashes
    known_crashes = load_state()
    print(f"Loaded {sum(len(v) for v in known_crashes.values())} known crashes")

    iteration = 0

    while True:
        iteration += 1

        try:
            # Check for new crashes
            known_crashes, new_found = check_for_crashes(known_crashes)

            # Save state if new crashes found
            if new_found:
                save_state(known_crashes)

            # Print stats every 10 iterations (10 minutes with default interval)
            if iteration % 10 == 0:
                stats = get_stats()
                print(f"\n=== Fuzzing Stats (iteration {iteration}) ===")
                for fuzzer_name, fuzzer_stats in stats.items():
                    print(f"  {fuzzer_name}:")
                    print(f"    Crashes: {fuzzer_stats['crashes']}")
                    print(f"    Corpus: {fuzzer_stats['corpus_size']}")
                print("=" * 40)

        except Exception as e:
            print(f"Error in monitoring loop: {e}")

        # Wait before next check
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
