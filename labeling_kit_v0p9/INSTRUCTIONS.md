# v0.9.2 paste-labeling workflow

1. Open a fresh Claude.ai conversation (any Sonnet or Opus model).
2. Paste the entire contents of `PROMPT.md` as your first message.
   Claude should respond with something like "Understood. Send the
   first chunk." (If it asks questions instead, hit it with the
   first chunk anyway — the prompt is self-contained.)
3. For each `chunk_NN.txt` in numerical order:
   - Copy the entire file contents into the next user message.
   - Wait for Claude's jsonl response.
   - Save the jsonl code block content (just the code block contents,
     not the surrounding markdown) to a file
     `responses/chunk_NN.jsonl`.
4. When all chunks are done, run:
   ```
   uv run python tools/llm_label_writeup_ingest.py \
       --responses-dir labeling_kit_v0p9/responses \
       --chunks-dir labeling_kit_v0p9 \
       --output data/eval/writeups/labeled_paths.jsonl
   ```
5. The ingest tool merges responses back to the writeup-paths shape
   for v0.9.3 (Snaffler-blind filter + classifier eval).

Context budget: Claude.ai conversations cap around 100K tokens of
chat history. Each chunk is ~5K tokens. You can fit ~20 chunks per
conversation before context fills; start a fresh one (paste PROMPT.md
again) for chunks past that.
