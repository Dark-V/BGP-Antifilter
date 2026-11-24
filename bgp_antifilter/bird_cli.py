import re
import subprocess


IPV4_ROUTE_ROW = re.compile(r"(?m)^((?:\d+\.){3}\d+/\d+)[ \t]+([^\n]+)")


def query(timeout, *args):
    reply = subprocess.run(["birdc", "-v", "-r", *args], capture_output=True, text=True,
                           timeout=timeout, check=False)
    codes = [int(value) for value in re.findall(r"(?m)^(\d{4})[ -]", reply.stdout)]
    # BIRD's explicit "Network not found" is CLI 8001 / exit 1.
    absent = (args[:2] == ("show", "route") and reply.returncode == 1
              and codes and codes[-1] == 8001 and all(code < 8000 or code == 8001 for code in codes))
    if reply.returncode and not absent:
        reply.check_returncode()
    # birdc -v indents continuation lines instead of repeating the code.
    output = re.sub(r"(?m)^(?:\d{4}[ -]| {5})", "", reply.stdout)
    if (any(code >= 8000 for code in codes) and not absent) or 1 not in codes or not re.search(r"BIRD .* ready\.", output):
        raise RuntimeError("BIRD rejected the query")
    return output
