# Baselines and real-world ablations (report, Section 4.7)

All three need things that only the project machine has (Docker Hub, an LLM key, the
privacy policies at their URLs), so they are run there. Send the output files back and
they are scored against the same reference set as PrivacyPilot.

## 1. LLM-prompt baseline
    python eval/llm_baseline.py --workdir C:\work\llm_baseline --out llm_baseline.json
One prompt per repository (policy + code excerpts). Output: `llm_baseline.json`.
Use `--dry-run` first to see the prompt sizes. State the model used.

## 2. Privado
    # install: https://github.com/Privado-Inc/privado-cli  (needs Docker running)
    privado scan C:\work\llm_baseline\<repo folder>      # for each of the nine checkouts
Output: `<repo>\.privado\privado.json` for each repository. Privado reports data
elements, sinks and leakages, not DPDP violations, so it is scored by mapping its
data-element-to-sink flows to third-party transmission and its leakages to logging.

## 3. Real-world ablations
For each setting, restart the worker with the variable set and rescan the nine
repositories with their policies (save each scan's violations CSV):
    $env:PRIVACYPILOT_DISABLE = "taint"        # then: "verhoeff", then: "ner"
    docker compose up -d --build
    # also one run with the variable unset, in the same vagueness setting, as the reference
    Remove-Item Env:PRIVACYPILOT_DISABLE
The switches are read at start-up (`backend/scanners/code_scanner.py`, `policy_parser.py`).
