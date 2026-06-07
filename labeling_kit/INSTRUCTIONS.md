# Manual labeling workflow

You'll paste the prompt into a fresh Claude.ai (Sonnet) conversation once,
then paste each chunk as a separate user message. Sonnet will respond with
a `jsonl` code block. Collect all those code blocks into one file.

## Steps

1. **Open a new Claude.ai conversation.** Default Sonnet model.

2. **Paste `PROMPT.md` as the first message.** Wait for Sonnet to reply
   "ready" (or equivalent).

3. **For each `chunk_NN.txt`:**
   - Paste the chunk file's contents as your next message.
   - Sonnet replies with a `jsonl` code block. Copy ONLY the contents
     between the ``` fence markers (not the markers themselves).
   - Append the copied JSONL lines to a single file:
     `data/eval/eval_set_claude_linux_manual.jsonl`
   - Repeat for the next chunk.

4. **When all chunks done:** run the ingester
   ```bash
   uv run python tools/llm_label_ingest.py \
       --input data/eval/eval_set_claude_linux_manual.jsonl
   ```
   It validates each line against the schema, attaches pre_category +
   validator_warnings, and appends to `eval_set_claude_linux.jsonl`.

## If Sonnet drifts

- If output isn't a fenced ```jsonl block, ask: "Reformat your last reply
  as a single jsonl code block, no prose."
- If a tier seems wrong on a high-stakes path (e.g. /etc/shadow as Yellow),
  flag it and ask Sonnet to reconsider — or fix it manually before paste.
- If a category isn't in the allowed enum, ask Sonnet to map to the closest
  one or fall back to "embedded_secrets" for cred-adjacent unknowns.

## If you need to restart

`tools/llm_label_chunkify.py` is idempotent — re-running it recomputes the
unlabeled diff, so you can run it again after partial progress to get
fresh chunks of only-still-unlabeled paths.
