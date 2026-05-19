# Decoding Project (Mono-Alphabetic First)

This project starts with **mono-alphabetic substitution cracking** using frequency analysis.

## Files

- `mono-alphabetic.txt`: your mono-substitution ciphertext
- `poly-alphabetic.txt`: Vigenere/poly-alphabetic ciphertext
- `mono_decoder.py`: Python script for mono frequency analysis and refinement
- `poly_decoder.py`: Python script for Vigenere key recovery and decryption

## What the script does

1. Counts ciphertext letter frequencies
2. Optionally prints digraph/trigraph and double-letter frequency tables
2. Builds an initial substitution using standard English frequency order
3. Runs a lightweight hill-climbing swap search to improve readability
4. Prints both initial and refined plaintext guesses

## Run

```bash
python mono_decoder.py --input mono-alphabetic.txt --show-ngrams --show-map --output mono-guess.txt
```

Useful options:

- `--iterations 50000` for deeper search
- `--seed 7` to try a different random route
- `--restarts 20` for more hill-climb restarts
- `--top 10` to print only top 10 letter frequencies
- `--show-ngrams` to include digraph/trigraph/double-letter tables

## Next step

## Vigenere / Poly-Alphabetic Decoder

The poly decoder uses:

1. Kasiski repeated trigram distance factor votes (key-length hints)
2. Index of Coincidence ranking for key lengths
3. Per-column Caesar chi-squared matching to recover each key letter

Run auto key recovery:

```bash
python poly_decoder.py --input poly-alphabetic.txt --show-analysis --output poly-guess.txt
```

Useful options:

- `--min-keylen 2 --max-keylen 25` to widen key-length search
- `--top-lens 10` to evaluate more candidate lengths
- `--key LEMON` if you already know the key
