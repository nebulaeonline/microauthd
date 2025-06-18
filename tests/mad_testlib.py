import subprocess
import json
import shlex

ADMIN_URL = "http://localhost:9041"

def run_mad(args, expect_json=True, fail_ok=False):
    """
    Runs a mad CLI command with --json and --admin-url.
    Returns a tuple of (success, output), where output is a dict or str.
    """
    cmd = ["mad"] + args + ["--admin-url", ADMIN_URL]
    if expect_json and "--json" not in cmd:
        cmd.append("--json")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=not fail_ok)
        stdout = result.stdout.strip()

        if expect_json:
            try:
                return True, json.loads(stdout)
            except json.JSONDecodeError as e:
                print("Failed to parse JSON output:")
                print(stdout)
                raise e
        return True, stdout

    except subprocess.CalledProcessError as e:
        if not fail_ok:
            print(f"\n❌ mad command failed: {' '.join(shlex.quote(a) for a in cmd)}")
            print("STDOUT:\n", e.stdout)
            print("STDERR:\n", e.stderr)
            raise
        return False, e.stdout.strip()
