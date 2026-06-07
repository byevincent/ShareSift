---
base_model: unsloth/Qwen3-1.7B-unsloth-bnb-4bit
library_name: peft
model_name: content_classifier_v0p3
tags:
- base_model:adapter:unsloth/Qwen3-1.7B-unsloth-bnb-4bit
- lora
- sft
- transformers
- trl
- unsloth
licence: license
pipeline_tag: text-generation
---

# Model Card for content_classifier_v0p3

This model is a fine-tuned version of [unsloth/Qwen3-1.7B-unsloth-bnb-4bit](https://huggingface.co/unsloth/Qwen3-1.7B-unsloth-bnb-4bit).
It has been trained using [TRL](https://github.com/huggingface/trl).

## Quick start

```python
from transformers import pipeline

question = "If you had a time machine, but could only go to the past or the future once and never return, which would you choose and why?"
generator = pipeline("text-generation", model="None", device="cuda")
output = generator([{"role": "user", "content": question}], max_new_tokens=128, return_full_text=False)[0]
print(output["generated_text"])
```

## Training procedure

 


This model was trained with SFT.

### Framework versions

- PEFT 0.19.1
- TRL: 0.24.0
- Transformers: 5.3.0
- Pytorch: 2.12.0
- Datasets: 4.3.0
- Tokenizers: 0.22.2

## Citations



Cite TRL as:
    
```bibtex
@misc{vonwerra2022trl,
	title        = {{TRL: Transformer Reinforcement Learning}},
	author       = {Leandro von Werra and Younes Belkada and Lewis Tunstall and Edward Beeching and Tristan Thrush and Nathan Lambert and Shengyi Huang and Kashif Rasul and Quentin Gallou{\'e}dec},
	year         = 2020,
	journal      = {GitHub repository},
	publisher    = {GitHub},
	howpublished = {\url{https://github.com/huggingface/trl}}
}
```