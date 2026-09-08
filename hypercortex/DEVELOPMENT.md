[PROBLEM]
- The ReportWriterAgent experienced an edge-case regression: it still burned ~19k tokens and timed out, hitting the Fallback logic.
- Root Cause: A legacy injection block `format_bundle_prompt_append(state.context_bundle)` was secretly appending thousands of lines of raw SIEM telemetry (JSON/logs) at the very bottom of our beautifully structured Hierarchical Briefing.
- When reasoning models (Qwen, DeepSeek-R1) see raw logs, their RLHF alignment kicks in, overriding the "Compiler" persona. They enter an infinite `<think>` loop attempting to cross-reference the raw logs against the briefing, burning all `max_tokens` without generating the final markdown.

[SOLUTION]
- Completely severed the `bundle_append` logic from `run_report_writer`. 
- The ReportWriterAgent now strictly receives ONLY the pre-digested `_build_context` briefing. 
- Raw log analysis is rightfully contained within Phase 1 (Recon) and Phase 2 (Forensic).

[REVIEW_LOG]
- Reviewer: Verified pruning. This is the definitive fix for the token exhaustion bug. By entirely removing the untrusted, unformatted telemetry from the Writer's context window, the model has absolutely no raw data left to "reason" about. It is forced into rapid synthesis mode. Post-modification check passed. Progress logged.