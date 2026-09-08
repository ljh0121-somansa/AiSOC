# Harness-Dev: Integrated AI Coding Assistant Harness

An elite SDLC methodology and persona-driven harness designed to transform an AI assistant into a specialized team of experts (Architect, Developer, Reviewer, SDET, Frontend/Designer).

> **Important**: This harness is specifically optimized and designed for the **pi** agent environment. It automatically loads the `AGENTS.md` file at startup, ensuring seamless operation without extra configuration.

## Core Concepts

### 1. The Five Personas
This harness defines five specialized identities, allowing the AI to context-switch across different engineering roles:
- **System Architect**: Global system vision, OOD, and architectural trade-offs.
- **Software Developer**: Precision implementation, memory-safe, and concurrent code.
- **Reviewer**: Uncompromising quality audits, security validation, and architectural alignment.
- **Test Engineer (SDET)**: Extreme edge-case validation and isolated automated testing.
- **Frontend Engineer & UX/UI Designer**: User experience design, web accessibility (a11y), and dedicated i18n implementation.

### 2. The Hypercortex Knowledge System
The `hypercortex/` directory serves as the AI's persistent memory and knowledge graph. It maintains traceability across requirements, design, specifications, development patterns, and quality records.

### 3. Shift-Left Workflow (Continuous Validation)
The 6-Phase SDLC process ensures that every decision is validated before implementation:
- **Phase 1-3 (Analysis/Design/Spec)**: Includes a mandatory [Validation] loop where the Reviewer persona cross-examines outputs.
- **Phase 4 (Development)**: Mandatory [Self-Review] and basic functional verification before finalizing code.
- **Phase 5 (Audit)**: Rigorous audit of security vulnerabilities, performance bottlenecks, and compliance.
- **Phase 6 (Testing)**: Construction of isolated tests to prove system limits.

---

## Getting Started

There are two ways to apply this harness to your project:
1. **Git Submodule Method (Recommended)**: Best for team collaboration, as it supports version pinning (locking to a specific commit) and offers intuitive management.
2. **Git Sparse-Checkout Method (Alternative)**: Pulls only the core `harness/` directory to keep your repository light.

---

### Method A: Git Submodule Method (Recommended ⭐)
The most standard and reliable approach to ensure that the entire team tracks and uses the exact same version of the harness.

#### Step 1: Add as a Git Submodule
Run the following command from your project root to add the harness under the `.harness` directory:
```bash
git submodule add https://gitlab.somansa.com/crowmania/harness-dev.git .harness
```

> 💡 **How to Update**: To pull the latest updates from the remote repository and commit the new version pointer:
> ```bash
> git submodule update --remote --merge
> ```

---

### Method B: Git Sparse-Checkout Method (Alternative)
Use this if you strictly want to pull only the `harness/` directory and avoid downloading other files like translations or examples.

#### Step 1: Initialize with Sparse-Checkout
Run the following commands from your project root:
```bash
# 1. Clone the harness repository into .harness (without checking out files)
git clone --no-checkout https://gitlab.somansa.com/crowmania/harness-dev.git .harness

# 2. Enter the .harness directory
cd .harness

# 3. Initialize sparse-checkout and specify the harness folder
git sparse-checkout init --cone
git sparse-checkout set harness

# 4. Checkout the files
git checkout main

# 5. Return to your project root
cd ..
```

> 💡 **How to Update**: When the harness repository is updated in the future, navigate into `.harness` and pull the changes:
> ```bash
> cd .harness && git pull origin main && cd ..
> ```

---

### Step 2: Set Up Directories
Create the `hypercortex/` and `workspace/` directories.
- `hypercortex/`: Stores methodology documents (REQUIREMENT, DESIGN, etc.).
- `workspace/`: All technical implementation (code, assets, tests) MUST reside here to prevent root contamination.

### Step 3: Register Project-Local Extension (Harness Prompt Extension)
Register the project-local extension that automatically appends the harness guidelines and personas (`PERSONA.md` and `WORKFLOW.md`) directly into the system prompt.

By leveraging pi's `settings.json` configuration, you can load the extension directly from the `.harness` directory without copying files or creating complex symlinks. This is fully cross-platform (works on Windows, Mac, and Linux) and ensures any future updates to the harness extension are applied automatically.

1. Create the `.pi` directory at the project root:
```bash
mkdir -p .pi
```

2. Create or update `.pi/settings.json` with the following content (if the file already exists, simply add the path to the `extensions` array):
```json
{
  "extensions": [
    "../.harness/harness/extensions/harness-prompts.ts"
  ]
}
```
> 💡 **Path Resolution**: Relative paths defined in `.pi/settings.json` are resolved relative to the `.pi` folder. Therefore, `../.harness/...` correctly points to the `.harness` directory at the project root.

After setting up the settings file, **restart** pi (or type `/reload`). The extension will be loaded, automatically applying the harness rules to your system prompt.

---

## Global Execution Rules
- **Zero-Contamination**: Technical implementations must never occur at the project root.
- **Knowledge Traceability**: Decisions must be linked back to their origin in the Hypercortex via Markdown cross-references.
- **Mandatory Internationalization (i18n)**: All UI components must be architected for multiple locales from the start.
- **Validation-First**: Errors must be corrected within the phase they originated.
