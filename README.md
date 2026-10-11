# DataClaw

> **This is a performance art project.** Anthropic built their models on the world's freely shared information, then introduced increasingly [dystopian data policies](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks) to stop anyone else from doing the same with their data - pulling up the ladder behind them. DataClaw lets you throw the ladder back down. The dataset it produces is yours to share.

Turn your Claude Code, Codex, and other coding-agent conversation history into structured data and publish it to Hugging Face with a single command. DataClaw parses session logs, redacts secrets and PII, and uploads the result as a ready-to-use dataset.

![DataClaw](dataclaw.jpeg)

Every export is tagged **`dataclaw`** on Hugging Face. Together, they may someday form a growing [distributed dataset](https://huggingface.co/datasets?other=dataclaw) of real-world human-AI coding collaboration.

## Install

### Mac app

<p align="center">
  <a href="https://github.com/peteromallet/dataclaw/releases/latest/download/DataClaw-macOS-Apple-Silicon.dmg">
    <img alt="Download DataClaw for Apple Silicon Macs" src="https://img.shields.io/badge/Download%20for%20Mac-Apple%20Silicon-111111?style=for-the-badge&logo=apple&logoColor=white">
  </a>
  <a href="https://github.com/peteromallet/dataclaw/releases/latest">
    <img alt="View GitHub Releases" src="https://img.shields.io/badge/View%20Releases-GitHub-0969da?style=for-the-badge&logo=github&logoColor=white">
  </a>
</p>

A menu-bar app for Apple Silicon Macs. Download the DMG, drag `DataClaw.app` to Applications, and launch it from Applications or Spotlight. The app bundles everything it needs — no Python or CLI install required.

#### Opening the app for the first time

The build is currently unsigned (Apple Developer ID signing is being set up), so macOS blocks the first launch. This is expected, one-time, and takes about 20 seconds:

![Four-step macOS Gatekeeper walkthrough for opening unsigned DataClaw.app](docs/images/macos-open-anyway.png)

1. Double-click **DataClaw.app** → a dialog says it can't be opened → click **Done** (not **Move to Trash**).
2. Open **System Settings** and type **Privacy & Security** in the search field (or: Apple menu → System Settings).
3. Scroll to the **Security** section — you'll see *"DataClaw" was blocked to protect your Mac* → click **Open Anyway**.
4. In the confirmation dialog click **Open Anyway** again and authenticate with Touch ID or your password. DataClaw launches and lives in the menu bar; subsequent launches are normal.

### CLI

For the terminal workflow, Intel Macs, or driving DataClaw with a coding agent:

```bash
pip install -U dataclaw
```

## Give this to your agent

Paste this into Claude Code, Codex, or any coding agent:

```
Help me export my Claude Code, Codex, and other coding-agent conversation history to Hugging Face using DataClaw.
Install it, then walk me through the process.

STEP 1 - INSTALL
  pip install -U dataclaw
  If that fails: git clone https://github.com/peteromallet/dataclaw.git /tmp/dataclaw && pip install -U /tmp/dataclaw
  If that also fails, ask the user where the source is.

STEP 2 - INSTALL SKILL
  Skill support is currently only available for Claude Code.
  dataclaw update-skill claude
  For other agentic tools, skip this step and do not improvise a custom flow - follow the instructions in DataClaw's output on each step, especially next_steps and next_command.

STEP 3 - PREP
  dataclaw prep
  Every dataclaw command outputs next_steps in its JSON - follow them through the entire flow.

STEP 3A - CHOOSE SOURCE SCOPE (REQUIRED BEFORE EXPORT)
  Ask the user explicitly which source scope to export: a supported source key such as claude or codex, or all.
  dataclaw config --source all
  Do not export until source scope is explicitly confirmed.

STEP 3B - CHOOSE PROJECT SCOPE (REQUIRED BEFORE EXPORT)
  dataclaw list --source all
  Send the FULL project/folder list to the user in a message (name, source, sessions, size, excluded).
  Ask which projects to exclude.
  dataclaw config --exclude "project1,project2" OR dataclaw config --confirm-projects
  Do not export until folder selection is explicitly confirmed.

STEP 3C - SET REDACTED STRINGS
  Ask the user what additional strings should always be redacted, such as company names, client names, domains, internal URLs, or secrets that regex might miss.
  dataclaw config --redact "string1,string2"
  dataclaw config --redact-usernames "user1,user2"
  Only add these after explicit user confirmation.

STEP 4 - EXPORT LOCALLY
  dataclaw export --no-push --output dataclaw_export.jsonl

STEP 5 - REVIEW AND CONFIRM (REQUIRED BEFORE PUSH)
  Review PII findings and apply excludes/redactions as needed.
  Full name is requested for an exact-name privacy scan against the export.
  If the user declines sharing full name, use --skip-full-name-scan and attest the skip reason.
  dataclaw confirm --full-name "THEIR FULL NAME" --attest-full-name "..." --attest-sensitive "..." --attest-manual-scan "..."

STEP 6 - PUBLISH (ONLY AFTER EXPLICIT USER APPROVAL)
  dataclaw export --publish-attestation "User explicitly approved publishing to Hugging Face."
  Never publish unless the user explicitly says yes.

IF ANY COMMAND FAILS DUE TO A SKIPPED STEP:
  Restate the 6-step checklist above and resume from the blocked step (do not skip ahead).

IMPORTANT: Never run bare `hf auth login` when automating this with an agent - always use `--token`.
IMPORTANT: Always export with --no-push first and review for PII before publishing.
```

## What gets exported

- User messages - Including voice transcripts and images
- Assistant responses
- Assistant thinking - Opt out with `--no-thinking`
- Tool calls - Tool name, inputs, outputs
- Token usage - Input/output tokens per session
- Metadata - Model name, git branch, timestamps

### Privacy & Redaction

DataClaw applies multiple layers of protection:

1. Username redaction - Your OS username + any configured usernames replaced with stable hashes
2. Secret redaction - Regex patterns catch JWT tokens, API keys (Anthropic, OpenAI, HF, GitHub, AWS, etc.), database passwords, private keys, Discord webhooks, and more
3. Entropy analysis - Long high-entropy strings in quotes are flagged as potential secrets
4. Email redaction - Regex pattern catches email addresses
5. Custom redaction - You can configure additional strings to redact
6. Structured redaction - All session fields, tool inputs and outputs, nested metadata, dictionary keys, and embedded JSON containers are checked. Secret-named fields such as `API_KEY_BACKUP` also provide context for opaque values.

**This is NOT foolproof.** Always review your exported data before publishing.
Automated redaction cannot catch everything - especially service-specific
identifiers, third-party PII, or secrets in unusual formats. Binary attachments and
base64 payloads are preserved; this redactor does not decode attachments or read
text from images. Embedded JSON decoding is limited to eight nested wrappers.
Credential-shaped examples may also be redacted conservatively.

We recommend converting the exported jsonl into human-readable yaml using `dataclaw jsonl-to-yaml`,
then use tools such as [trufflehog](https://github.com/trufflesecurity/trufflehog) and [gitleaks](https://github.com/gitleaks/gitleaks) to scan it.
You can also compare the exported jsonl with a previous baseline using `dataclaw diff-jsonl`.

To help improve redaction, report issues: https://github.com/peteromallet/dataclaw/issues

## Finding datasets on Hugging Face

All repos are tagged `dataclaw`.

- **Browse all:** [huggingface.co/datasets?other=dataclaw](https://huggingface.co/datasets?other=dataclaw)
- **Load one:**
  ```python
  from datasets import load_dataset
  ds = load_dataset("alice/my-personal-codex-data", split="train")
  ```
- **Combine several:**
  ```python
  from datasets import load_dataset, concatenate_datasets
  repos = ["alice/my-personal-codex-data", "bob/my-personal-codex-data"]
  ds = concatenate_datasets([load_dataset(r, split="train") for r in repos])
  ```

The auto-generated HF README includes:
- Model distribution (which models, how many sessions each)
- Total token counts
- Project count
- Last updated timestamp

## Contributing

**Missing data:** If you found any data not exported, please report an issue. You can ask your coding agent to analyze the data, export it in this repo, and open a PR.

**Better scheme:** If you need to clean the data and want to propose a better scheme, feel free to open an issue.

**New provider:** If you use a new coding agent, you can ask it to read this repo and export its data as a new provider. Take Claude Code and Codex parsers as examples because they are the most well maintained. When you finish, ask the following questions:
- Did you follow the schema the existing parsers emit? It's fine to add custom fields in `messages[].content_parts` and `tool_uses[].output.raw`.
- Did you export all data, especially:
  - tool call inputs and outputs
  - long inputs and outputs that may be saved somewhere else
  - binary content (may be encoded as base64) such as images, in both user messages and tool calls. We do not apply anonymizer on binary content
  - subagents
- Does the coding agent automatically delete old sessions? How to prevent this?

## Code Quality

<p align="center">
  <img src="scorecard.png" alt="Code Quality Scorecard">
</p>

## License

MIT
