# Baselines and real-world ablations (report, Section 4.7)

All three need things that only the project machine has (Docker Hub, an LLM key, the
privacy policies at their URLs), so they are run there. Send the output files back and
they are scored against the same reference set as PrivacyPilot.

## 1. LLM-prompt baseline
    python eval/llm_baseline.py --workdir C:\work\llm_baseline --out llm_baseline.json
One prompt per repository (policy + code excerpts). Output: `llm_baseline.json`.
Use `--dry-run` first to see the prompt sizes. State the model used.

## 2. Privado
Prerequisites: Git, Docker Desktop running, and the Privado CLI
(https://github.com/Privado-Inc/privado-cli). Then, from the project root:

    .\eval\privado_run.ps1

It checks out each of the 12 repositories at its annotated commit under `C:\work\privado`,
runs `privado scan <dir> --skip-upload --overwrite`, and copies each `.privado\privado.json`
to `eval\results\privado\`, with `run_log.csv` (status, time, Privado version).
Use `-Only <name>` to run or rerun one repository.

## 3. Real-world ablations
For each setting, restart the worker with the variable set and rescan the nine
repositories with their policies (save each scan's violations CSV):
    $env:PRIVACYPILOT_DISABLE = "taint"        # then: "verhoeff", then: "ner"
    docker compose up -d --build
    # also one run with the variable unset, in the same vagueness setting, as the reference
    Remove-Item Env:PRIVACYPILOT_DISABLE
The switches are read at start-up (`backend/scanners/code_scanner.py`, `policy_parser.py`).
