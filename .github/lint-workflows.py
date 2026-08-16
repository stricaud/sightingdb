"""Flag shell variables a workflow step uses but never sets.

Workflow shell is not covered by `cargo test` and cannot be run locally, so a
typo here surfaces halfway through a release. With `set -u` it is a hard
failure; without it, an empty string silently does the wrong thing.

Run with: python3 .github/lint-workflows.py
"""
import re, sys, yaml, pathlib

# Set by the runner for every step.
BUILTIN = {
    "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_SHA", "GITHUB_ENV", "GITHUB_OUTPUT",
    "GITHUB_WORKSPACE", "GITHUB_STEP_SUMMARY", "GITHUB_TOKEN", "GITHUB_REPOSITORY",
    "GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_ACTOR", "HOME", "PATH", "RUNNER_OS",
    "CARGO_TERM_COLOR", "RUSTFLAGS", "PIPESTATUS",
}
USE = re.compile(r'\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
# `name=value`, `for name in`, `read name`
SET = re.compile(
    r'(?:^|[\s;&|)])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)='
    r'|(?:^|[\s;])for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b',
    re.M,
)

problems = 0
for path in sorted(pathlib.Path(".github/workflows").glob("*.yml")):
    doc = yaml.safe_load(path.read_text())
    wf_env = set(doc.get("env", {}))
    for job_name, job in doc.get("jobs", {}).items():
        job_env = set(job.get("env", {}))
        for step in job.get("steps", []):
            script = step.get("run")
            if not script:
                continue
            # ${{ ... }} is substituted before the shell sees it.
            script = re.sub(r'\$\{\{.*?\}\}', 'X', script, flags=re.S)
            defined = BUILTIN | wf_env | job_env | set(step.get("env", {}))
            for m in SET.finditer(script):
                defined.add(m.group(1) or m.group(2))
            for m in USE.finditer(script):
                name = m.group(1)
                if name not in defined:
                    print(f"{path.name}: {job_name} / {step.get('name', 'unnamed')}: "
                          f"uses ${name} but nothing sets it")
                    problems += 1

print("clean" if not problems else f"{problems} problem(s)")
sys.exit(1 if problems else 0)
