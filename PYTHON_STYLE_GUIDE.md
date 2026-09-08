# Python 3.12 Optimization, Refactoring & Platform Style Guide

This document defines the official Python style guide and development guidelines for the AiSOC project to ensure consistency, high performance, and security across all backend services. It combines Black formatter alignment, modern Python 3.12 standard patterns, and platform architecture core principles.

---

## 1. Core Platform Architecture Principles (Platform Integration)

These architectural guidelines ensure seamless integration, high security, and strong robustness, as established during the implementation of the 3-tiered LLM query generation and developer-sandbox isolation.

### 1) Adhere to Single Responsibility Principle (SRP)
*   **Directive**: REST controllers and HTTP endpoints must focus solely on the HTTP lifecycle (handling authentication, parameter validation, database transactions, and RLS tenant mapping).
*   **Practice**: Complex business logic, such as LLM inference, natural-language-to-query translation, and response formatting, must be decoupled from the controller and extracted into dedicated domain service classes (e.g., `HuntQueryGenerator`).

### 2) Maximize Use of Existing Platform Resources (No Redundant Logic)
*   **Directive**: Never manually call `os.getenv` or write isolated duplicate configuration loaders when central settings or helper modules already exist.
*   **Practice**: All LLM-backed features must utilize the standard **`resolve_llm_config(db, tenant_id)`** resolver. This ensures the features automatically inherit multi-tenant Bring-Your-Own-Key (BYOK) credential decryption, credential vault integrations, environment-variable fallbacks, and air-gap policy enforcement.

### 3) Defensive Input Parsing & Backward Compatibility
*   **Directive**: A malformed LLM response, an unreachable service, or missing schema fields in legacy database rows must never raise unhandled 500 exceptions.
*   **Practice**:
    *   **JSON Backtick Cleaning**: LLMs frequently wrap JSON payloads in Markdown code blocks (e.g., ` ```json ... ``` `). Strip these markdown delimiters using custom helpers like `_clean_json_content()` before passing them to JSON decoders.
    *   **Backward-Compatible ORM Mapping**: To prevent app crashes when reading legacy database records or running in pre-migration environments, safely map SQLAlchemy database rows using `getattr(row, "column_name", default_value)`.

### 4) Secure Multi-user Development Sandbox Isolation
*   **Directive**: Multiple developers sharing a single host machine must be able to run distinct, parallel development environments without port collisions, volume overwrites, or container name conflicts.
*   **Practice**: Isolate developer environments by utilizing dynamic compose project prefixes (`COMPOSE_PROJECT_NAME`) and distinct host port bindings (e.g., `1xxxx` and `2xxxx` port ranges) configured inside individual `.env` files.

---

## 2. Python 3.12 Optimization & Refactoring Guidelines

### 1) Guarantee Cross-Platform Compatibility
*   **Path Manipulation**: Always use `pathlib.Path` objects rather than raw string concatenation.
*   **Shell Execution**: Avoid passing `shell=True` to `subprocess` invocations. Pass commands as structured lists instead (e.g., `["cmd", "arg"]`).
*   **File I/O Encoding**: To prevent decoding errors across differing operating systems, explicitly specify `encoding="utf-8"` and `newline=""` when opening text files.
*   **Multiprocessing Entrypoints**: Ensure the `if __name__ == "__main__":` entry point guard is present in all script-executable modules.

### 2) Optimize Memory & Object Copying
*   **Large Dataset Pipelines**: Prefer generator expressions or `yield` statements over heavy list comprehensions to lower memory footprints during sequential stream processing.
*   **Avoid Redundant Deep Copies**: Rely on Python's native zero-copy reference passing wherever possible; avoid redundant `copy.deepcopy()` calls.
*   **Memory Slot Optimization**: For high-concurrency or highly instantiated classes, declare `__slots__` to restrict dynamic dictionary overhead.

### 3) Strict Compliance with Black Formatter
*   **Line-Length Limit**: Hard-limit maximum line lengths to **88 characters**.
*   **String Quotes**: Always declare string literals using double quotes (`"`) rather than single quotes (`'`) for codebase consistency.
*   **Trailing Commas**: Always append a trailing comma (`,`) at the end of multi-line parameters, list items, or dictionary entries.

### 4) Leverage Modern Python 3.12 Type Hinting
*   **PEP 695 Generics & Type Aliases**: Utilize the modern generic syntax (`def func[T](items: list[T]) -> T:`) and modern type alias statements (`type Coord = tuple[float, float]`).
*   **Type Union Operator**: Prefer the simplified pipe operator (`|`) over legacy `Union` imports (e.g., `str | None`).
*   **Override Decorator**: Always annotate subclass method overrides with the `@typing.override` decorator.

### 5) Object-Oriented Design (OOD) & Standard Library Maximization
*   Uphold SOLID design principles and prioritize high-performance built-in structures (e.g., `collections.deque`, `itertools`, `functools.lru_cache`) over custom-built equivalents.

### 6) Respect Legacy Codebases & Support Gradual Enhancements
*   Preserve existing public class interfaces, function signatures, and service contracts to guarantee backwards compatibility and prevent regression risks.

### 7) Lightweight & Clear Error Handling
*   Avoid raising heavy exceptions in high-frequency loops; represent simple, expected failure paths gracefully by returning `None` or `Optional` structures.

### 8) Hardened Container Portability (Docker Compatibility)
*   Isolate code blocks from host-specific system dependencies to guarantee identical, portable, and reliable execution within lightweight Linux Docker containers (e.g., Alpine or Debian Slim).
