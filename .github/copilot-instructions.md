<!-- Copilot instructions for AI coding agents working on this repo -->
# Copilot Instructions - Cyber-EW Fusion Cell

Purpose: concise, repo-specific guidance so an AI coding agent is immediately productive.

- Big picture:
  - This project is a threaded, queue-based pipeline for cyber telemetry: Ingest -> Normalization -> Correlation -> Behavior -> Scoring -> Output.
  - Key orchestrator: `main.py` creates `CyberEWPipeline` (see `core/pipeline.py`). Engines are instantiated in the pipeline and communicate via Python `Queue` objects.
  - Engines live in `core/engines/` and expose `start()`, `stop()`, `get_stats()` and domain methods like `process_event()` / `analyze_event()` / `score_event()`.

- Key files to inspect for behavior and APIs:
  - `main.py` — CLI entry; modes: `run`, `test`, `stats`, `console`.
  - `core/pipeline.py` — thread lifecycle, queues, and stage workers.
  - `core/engines/*` — implementations for `ingest`, `normalization`, `correlation`, `behavior`, `scoring`, `output`.
  - `core/models/` — canonical event and behavior model classes (use these types when possible).
  - `config/settings.py` and `config/settings.yaml` — runtime configuration (pipeline sizes, enabled sources, scoring weights).

- Runtime & developer workflows:
  - Run the pipeline: `python main.py --mode run` (use `--config` to override `config/settings.yaml`, `--log-level` to change logging).
  - Run tests: `python main.py --mode test` (this calls unittest discovery) or `python -m unittest discover -s tests -p 'test_*.py'`.
  - Logs: configured via `config/logging_config.py`; prefer changing `--log-level` when debugging.

- Conventions & patterns to follow (do not invent alternatives):
  - Use `NormalizedEvent` and `EventType` from `core.models.event_models` — engines expect those fields and helper functions (`ensure_utc`, `.to_dict()`).
  - Engines pass Python objects (not raw dicts) across queues after normalization; keep transformation logic in `NormalizationEngine`.
  - Use existing engine methods for side effects (e.g., `IngestEngine.register_callback`, `OutputEngine.subscribe`) rather than ad-hoc global state.
  - Threading model: workers are long-running threads reading from `Queue.get(timeout=1)` loops. Avoid blocking calls in worker threads and respect `self.running` checks.
  - Persisted state locations: `CONFIG.data_dir` — behavior profiles saved/loaded as `behavior_profiles.json` by the pipeline.

- Integration points & config-driven behavior:
  - Data sources configured via `INGEST_CONFIG` and initialized in `IngestEngine._init_sources()`; add new sources by implementing `DataSource` subclasses.
  - Correlation uses a time window index (`TimeWindowIndex`) — be careful to preserve UTC timestamps (use `ensure_utc` / `normalize_timestamp`).
  - Scoring parameters come from `SCORING_CONFIG.weights` — adjust tests and defaults rather than hardcoding values.

- Testing and changes guidance:
  - Unit tests live in `tests/` and follow `test_*.py` naming. New behavior should have focused unit tests covering engine inputs/outputs (NormalizedEvent in/out).
  - When modifying an engine, run `python main.py --mode test` to validate the test suite. Keep changes minimal and preserve public method signatures used by `core/pipeline.py`.

- Quick examples (common edits):
  - To add a normalization mapping for a new source type, update `NormalizationEngine.field_mappings` and implement `_map_<source>_fields` + unit tests in `tests/`.
  - To add a new output format, extend `OutputFormat` enum and add a formatter in `OutputEngine.formatters` and unit tests for formatting logic.

If any part is unclear or you want more examples (e.g., a template PR checklist, common unit-test patterns), say which area and I'll iterate.
