# Local models and the offline release

emerag can talk to any OpenAI-compatible server on localhost. That covers most
air-gapped setups:

    ollama serve &                          # 127.0.0.1:11434
    llama-server -m model.gguf --port 9931  # 127.0.0.1:9931
    emerag --base-url http://127.0.0.1:9931/v1 --model local

The **offline release** goes further: one file you can copy to a USB stick,
containing emerag, a small GGUF model, and a statically linked llama.cpp
server. On first run emerag extracts the bundle to its cache directory and
starts the server, so no network, package manager, or compiler is needed.

    ./emerag-offline local up
    ./emerag-offline --provider llamacpp --model qwen3-0.6b -p "hi"

`emerag local status` shows what is installed and what the bundle contains.

## Why a bundled server instead of an in-process engine

emerag's core footprint target is small (idle RSS in the low tens of MiB).
A useful model does not fit in that:

| model | quant | file size | typical RSS while generating |
| --- | --- | --- | --- |
| SmolLM2-135M-Instruct | Q4_K_M | ~100 MB | ~250 MB |
| SmolLM2-360M-Instruct | Q8_0 | 386 MB | ~550 MB |
| Qwen3-0.6B | Q4_K_M | 397 MB | ~700 MB |
| Qwen2.5-0.5B-Instruct | Q4_K_M | 491 MB | ~800 MB |
| MiniCPM5-1B | F16 | 2.17 GB | ~3 GB |
| MiniCPM5-2B | F16 | 5.04 GB | ~6 GB |

(Weights are memory-mapped, so the resident set grows with the pages actually
touched; KV cache and activations add 30-100 MB at 4k context.)

Putting the model in the agent process would multiply emerag's footprint by
20-50x and make an OOM kill take the session with it. The bundled server runs
as a separate child process: the agent stays small, the server can be restarted
independently, and an old or constrained machine can still run the agent over
SSH while the model runs elsewhere.

A native Rust inference engine for tiny GGUF models is on the roadmap; the
bundle format and `local` commands are designed so it can replace the bundled
server without changing the user interface.

## Choosing a model

The practical floor is around 0.5B parameters with 4-bit quantization: it can
follow tool-call instructions and edit files for simple tasks, and it fits in
roughly 1 GB of RAM. Below that, models tend to ignore tool schemas.

Recommended, in order:

1. **Qwen3-0.6B** (Apache-2.0, Q4_K_M, 397 MB). Best instruction-following per
   byte at this size. Hidden size is 1024, a multiple of the K-quant block size,
   so a Q4_K_M file is a clean pure K-quant. Needs per-head QK-norm support in
   the runtime (current llama.cpp has it).
2. **Qwen2.5-0.5B-Instruct** (Apache-2.0, Q4_K_M, 491 MB). Very widely tested
   ChatML model. Its hidden size (896) is not a multiple of 256, so Q4_K_M
   files mix K-quants with Q4_0/Q8_0 tensors; llama.cpp handles that, a
   from-scratch engine must dispatch per tensor type.
3. **SmolLM2-360M-Instruct** (Apache-2.0, Q8_0, 386 MB). Smaller absolute
   footprint, lower quality. Official repo ships Q8_0 only.
4. **SmolLM2-135M-Instruct** Q4_K_M (~100 MB) for the absolute minimum; expect
   it to fail at multi-step tool use.

For Chinese-language work, Qwen3-0.6B is the best of these. For a model that
can actually plan a multi-command repair, 0.5B is still a stretch: budget for
retries and keep prompts explicit.

Download (air-gapped: copy the file, then verify its SHA-256):

    https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q4_K_M.gguf
    https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf

## Building the offline release

The release script builds a bundle from an existing llama-server and a GGUF:

    ./scripts/make-offline.sh \
        --server /path/to/llama-server \
        --model ~/models/Qwen3-0.6B-Q4_K_M.gguf \
        --out dist/emerag-offline-x86_64

It appends a payload to a copy of the emerag binary and writes a 64-byte
trailer with the payload offset, length and SHA-256. The host binary is
unchanged otherwise: no sections are added, no loader assumptions are made.

Notes per platform:

- **Linux**: appending after the ELF section table is safe; the loader only
  uses program headers. Do not run `strip` on the bundled file afterwards
  (strip rewrites the file and drops the payload); strip first, bundle second.
- **Windows**: trailing data after the last PE section is ignored by the
  loader. Authenticode signatures cover the whole file, so sign **after**
  bundling, never before.
- **macOS**: code signatures cover the whole file; append the payload before
  signing (`codesign --force -s - emerag-offline`). A notarized ticket is
  stapled to the bundle, not the bare Mach-O, so notarize after bundling.

At runtime `emerag local up` reads the last 64 bytes of its own executable,
validates the SHA-256, extracts the bundle once into
`<cache>/emerag/offline-<hash>/`, and starts:

    llama-server -m <extracted model> --host 127.0.0.1 --port 9931 -c 4096

The server is a child process; `emerag local stop` terminates it. The cache
directory is safe to delete at any time.

## If the bundle is not available

Plain GGUF files also work with an existing runtime:

    # ollama
    ollama pull qwen3:0.6b
    emerag --provider ollama --model qwen3:0.6b

    # llama.cpp
    llama-server -m ./qwen3-0.6b-q4_k_m.gguf --port 9931
    emerag --base-url http://127.0.0.1:9931/v1 --model local

Both are auto-detected by `emerag --provider llamacpp` / `--provider ollama`.

## Limits of small local models

- Tool calling is unreliable below ~1B parameters. Keep tools few and prompts
  short; use `/mode auto` only after you have watched it work.
- Context windows of 4k-32k mean long transcripts get compacted aggressively.
- Expect 5-30 tokens/second on a 4-core x86 CPU; context prefill is the slow
  part, so avoid re-sending large files.
- Quantization costs accuracy. Q4_K_M is the usual sweet spot; Q8_0 is better
  if RAM allows; Q2/Q3 are not worth it at this size.
