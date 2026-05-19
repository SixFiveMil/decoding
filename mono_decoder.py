#!/usr/bin/env python3
"""Mono-alphabetic substitution helper using frequency analysis.

This script gives you:
1) Ciphertext letter frequencies
2) An initial plaintext guess from frequency mapping
3) A light hill-climb refinement pass (letter swaps)

It is a practical starting point for cracking monoalphabetic substitution ciphers.
"""

from __future__ import annotations

import argparse
import math
import random
import string
import time
from collections import Counter
from typing import Dict

ALPHABET = string.ascii_uppercase
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
COMMON_DIGRAPHS = ("TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND")
COMMON_TRIGRAPHS = ("THE", "ING", "AND", "HER", "ERE", "ENT", "THA", "NTH")
COMMON_DOUBLES = ("LL", "EE", "SS", "OO", "TT", "FF", "RR", "NN", "PP")
QUADGRAM_COUNTS = {
    "TION": 13168375,
    "NTHE": 11234972,
    "THER": 10218035,
    "THAT": 8980536,
    "OFTH": 8132597,
    "FTHE": 7822128,
    "THES": 7717401,
    "WITH": 7630888,
    "INTH": 7225695,
    "ATIO": 7096479,
    "HERE": 6793284,
    "OULD": 6683482,
    "IGHT": 6519941,
    "HAVE": 6238952,
    "HICH": 6110598,
    "WHIC": 6032348,
    "THIS": 5972345,
    "THIN": 5882521,
    "THEM": 5773311,
    "MENT": 5615440,
    "IONS": 5411984,
    "EVER": 5341011,
    "FROM": 5263898,
    "TING": 5175019,
    "EDTH": 5082398,
    "THEC": 4973376,
    "ANDT": 4865544,
    "WERE": 4688300,
    "THEI": 4499056,
    "GTHE": 4421232,
    "DTHA": 4339988,
    "STHE": 4266044,
    "THEF": 4192520,
    "THEA": 4119055,
    "THEN": 4044201,
    "THEY": 3981544,
    "ENDE": 3915204,
    "ONTH": 3841940,
    "ALTH": 3778832,
    "NOTH": 3715514,
    "REAT": 3653841,
    "ANCE": 3534182,
    "HATI": 3479911,
    "TAND": 3375001,
    "THEO": 3274144,
    "ERES": 3228880,
    "NING": 3182910,
    "OTHE": 3092019,
    "DTHE": 3009844,
    "THEL": 2970512,
    "THED": 2932145,
    "SAND": 2895112,
    "ENTH": 2858933,
    "TOBE": 2791044,
    "TOTH": 2757744,
    "INGT": 2726110,
    "EAND": 2663219,
    "ERTH": 2602012,
    "THIR": 2573499,
    "RTHE": 2548011,
    "SION": 2523921,
    "INTE": 2405111,
    "PRES": 2345880,
    "TIVE": 2328122,
    "CTIO": 2310911,
    "SENT": 2294122,
    "OUND": 2279013,
    "OVER": 2265112,
    "ANDE": 2251231,
    "ERIN": 2238444,
    "TTHE": 2190233,
    "DING": 2166011,
    "ETHE": 2142533,
    "WILL": 2131122,
    "HING": 2119811,
    "NGTH": 2108033,
    "THOU": 2097444,
    "EING": 2075044,
    "HIST": 2053122,
    "THRO": 2020811,
    # Common quadgrams with P, Y, Q to improve rare-letter disambiguation
    "PEOP": 4100000,
    "EOPL": 4050000,
    "OPLE": 4000000,
    "PROP": 3200000,
    "ROPE": 3100000,
    "OPER": 3000000,
    "UPON": 2900000,
    "POSI": 2800000,
    "OSIT": 2750000,
    "SITI": 2700000,
    "ITIO": 2650000,
    "YEAR": 2600000,
    "EARS": 2550000,
    "YOUR": 2900000,
    "OURS": 2400000,
    "EQUA": 2300000,
    "QUAL": 2200000,
    "POOR": 2000000,
    "PERI": 1900000,
    "ERIS": 1850000,
    "NATI": 3500000,
    "ATIO": 3400000,
    "TIONS": 3300000,
    "DEAD": 2100000,
    "DEDI": 2050000,
    "EDIC": 2000000,
    "DICA": 1950000,
    "ICAT": 1900000,
    "CATE": 1850000,
    "ATED": 1800000,
    "BRAV": 1700000,
    "RAVE": 1650000,
    "EMEN": 2200000,
    "MENT": 2150000,
    "NATI": 2100000,
    "ATIO": 2050000,
    "IONA": 2000000,
    "ONAL": 1950000,
}

# Standard English monogram frequencies (percent).
ENGLISH_LETTER_FREQ = {
    "E": 12.7,
    "T": 9.1,
    "A": 8.2,
    "O": 7.5,
    "I": 7.0,
    "N": 6.7,
    "S": 6.3,
    "H": 6.1,
    "R": 6.0,
    "D": 4.3,
    "L": 4.0,
    "C": 2.8,
    "U": 2.8,
    "M": 2.4,
    "W": 2.4,
    "F": 2.2,
    "G": 2.0,
    "Y": 2.0,
    "P": 1.9,
    "B": 1.5,
    "V": 1.0,
    "K": 0.8,
    "J": 0.15,
    "X": 0.15,
    "Q": 0.1,
    "Z": 0.07,
}

QUADGRAM_TOTAL = sum(QUADGRAM_COUNTS.values())
QUADGRAM_LOGP = {k: math.log10(v / QUADGRAM_TOTAL) for k, v in QUADGRAM_COUNTS.items()}
QUADGRAM_FLOOR = math.log10(0.01 / QUADGRAM_TOTAL)


def read_ciphertext(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def clean_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def letter_frequency(text: str) -> Counter:
    return Counter(clean_letters(text))


def ngram_frequency(text: str, n: int) -> Counter:
    letters = clean_letters(text)
    if n <= 0 or len(letters) < n:
        return Counter()
    return Counter(letters[i : i + n] for i in range(len(letters) - n + 1))


def double_letter_frequency(text: str) -> Counter:
    letters = clean_letters(text)
    doubles = [letters[i : i + 2] for i in range(len(letters) - 1) if letters[i] == letters[i + 1]]
    return Counter(doubles)


def initial_mapping_from_frequency(text: str) -> Dict[str, str]:
    counts = letter_frequency(text)
    ranked_cipher = [pair[0] for pair in counts.most_common()]

    for letter in ALPHABET:
        if letter not in ranked_cipher:
            ranked_cipher.append(letter)

    mapping: Dict[str, str] = {}
    for cipher_letter, plain_letter in zip(ranked_cipher, ENGLISH_FREQ_ORDER):
        mapping[cipher_letter] = plain_letter

    return mapping


def apply_mapping(text: str, mapping: Dict[str, str], unknown_char: str = "_") -> str:
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHABET:
            repl = mapping.get(up, unknown_char)
            out.append(repl if ch.isupper() else repl.lower())
        else:
            out.append(ch)
    return "".join(out)


def decode_letters_only(cipher_letters: str, mapping: Dict[str, str]) -> str:
    return "".join(mapping[ch] for ch in cipher_letters)


def score_plaintext_letters(letters: str) -> float:
    # Quadgram + light monogram prior.
    if not letters:
        return float("-inf")

    counts = Counter(letters)
    total = len(letters)
    score = 0.0

    for letter in ALPHABET:
        observed = (counts[letter] / total) * 100.0
        expected = ENGLISH_LETTER_FREQ[letter]
        score -= abs(observed - expected) * 0.3

    if total >= 4:
        quad = 0.0
        for i in range(total - 3):
            gram = letters[i : i + 4]
            quad += QUADGRAM_LOGP.get(gram, QUADGRAM_FLOOR)
        score += quad

    # Weight n-gram structure to reward English-like flow.
    for gram in COMMON_DIGRAPHS:
        score += letters.count(gram) * 0.08
    for gram in COMMON_TRIGRAPHS:
        score += letters.count(gram) * 0.16
    for gram in COMMON_DOUBLES:
        score += letters.count(gram) * 0.12

    return score


def random_swap_mapping(mapping: Dict[str, str], rng: random.Random) -> Dict[str, str]:
    cipher_keys = list(ALPHABET)
    a, b = rng.sample(cipher_keys, 2)
    swapped = dict(mapping)
    swapped[a], swapped[b] = swapped[b], swapped[a]
    return swapped


def hill_climb_refine(
    cipher_letters: str,
    mapping: Dict[str, str],
    iterations: int = 20000,
    seed: int = 42,
    progress_every: int = 0,
    progress_label: str = "",
) -> Dict[str, str]:
    rng = random.Random(seed)

    best = dict(mapping)
    best_plain = decode_letters_only(cipher_letters, best)
    best_score = score_plaintext_letters(best_plain)

    current = dict(best)
    current_score = best_score

    for i in range(iterations):
        candidate = random_swap_mapping(current, rng)
        candidate_plain = decode_letters_only(cipher_letters, candidate)
        candidate_score = score_plaintext_letters(candidate_plain)

        # Greedy with occasional random jump for local minima.
        if candidate_score > current_score or rng.random() < 0.0008:
            current = candidate
            current_score = candidate_score

        if current_score > best_score:
            best = dict(current)
            best_score = current_score

        # Restart around best occasionally to keep exploration stable.
        if i > 0 and i % 5000 == 0:
            current = dict(best)
            current_score = best_score

        if progress_every > 0 and (i + 1) % progress_every == 0:
            pct = ((i + 1) / max(iterations, 1)) * 100.0
            print(
                f"{progress_label}  iter {i + 1}/{iterations} ({pct:5.1f}%)  best-score={best_score:.2f}",
                flush=True,
            )

    return best


def perturb_mapping(mapping: Dict[str, str], swaps: int, rng: random.Random) -> Dict[str, str]:
    perturbed = dict(mapping)
    for _ in range(max(swaps, 0)):
        perturbed = random_swap_mapping(perturbed, rng)
    return perturbed


def print_frequency_table(text: str, top_n: int = 26) -> None:
    counts = letter_frequency(text)
    total = sum(counts.values())
    print("Cipher letter frequency:")
    for letter, count in counts.most_common(top_n):
        pct = (count / total * 100.0) if total else 0.0
        print(f"  {letter}: {count:>4} ({pct:5.2f}%)")


def print_ngram_table(label: str, counts: Counter, top_n: int) -> None:
    total = sum(counts.values())
    print(f"\n{label}:")
    if not counts:
        print("  (none)")
        return
    for gram, count in counts.most_common(top_n):
        pct = (count / total * 100.0) if total else 0.0
        print(f"  {gram}: {count:>4} ({pct:5.2f}%)")


def print_mapping(mapping: Dict[str, str]) -> None:
    print("\nMapping (cipher -> plain):")
    for c in ALPHABET:
        print(f"  {c} -> {mapping[c]}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Frequency-analysis helper for monoalphabetic substitution ciphers."
    )
    parser.add_argument(
        "--input",
        default="mono-alphabetic.txt",
        help="Path to ciphertext file (default: mono-alphabetic.txt)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=20000,
        help="Hill-climb swap iterations (default: 20000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--restarts",
        type=int,
        default=12,
        help="Number of hill-climb restarts (default: 12)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=26,
        help="How many frequency entries to print (default: 26)",
    )
    parser.add_argument(
        "--show-ngrams",
        action="store_true",
        help="Print ciphertext digraph/trigraph/double-letter frequency tables",
    )
    parser.add_argument(
        "--show-map",
        action="store_true",
        help="Print final substitution mapping table",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional output file for best plaintext guess",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=5000,
        help="Print progress every N iterations during hill climb (default: 5000)",
    )
    parser.add_argument(
        "--early-stop",
        type=int,
        default=3,
        metavar="N",
        help="Stop after N consecutive restarts that match the global best (default: 3, 0 to disable)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress updates during restart/hill-climb processing",
    )

    args = parser.parse_args()
    ciphertext = read_ciphertext(args.input)
    cipher_letters = clean_letters(ciphertext)

    print_frequency_table(ciphertext, top_n=args.top)
    if args.show_ngrams:
        print_ngram_table("Cipher digraph frequency", ngram_frequency(ciphertext, 2), args.top)
        print_ngram_table("Cipher trigraph frequency", ngram_frequency(ciphertext, 3), args.top)
        print_ngram_table("Cipher double-letter frequency", double_letter_frequency(ciphertext), args.top)

    mapping = initial_mapping_from_frequency(ciphertext)
    initial_guess = apply_mapping(ciphertext, mapping)

    print("\n=== Initial Guess (frequency mapping) ===\n")
    print(initial_guess)

    rng = random.Random(args.seed)
    best_mapping = dict(mapping)
    best_text = decode_letters_only(cipher_letters, best_mapping)
    best_score = score_plaintext_letters(best_text)
    overall_start = time.perf_counter()
    consecutive_matches = 0

    for restart_idx in range(max(args.restarts, 1)):
        restart_start = time.perf_counter()
        if restart_idx == 0:
            start_mapping = dict(mapping)
        else:
            start_mapping = perturb_mapping(best_mapping, swaps=8, rng=rng)

        if not args.quiet:
            print(
                f"\n[restart {restart_idx + 1}/{max(args.restarts, 1)}] starting hill climb...",
                flush=True,
            )

        candidate = hill_climb_refine(
            cipher_letters,
            start_mapping,
            iterations=max(args.iterations, 0),
            seed=rng.randint(0, 10_000_000),
            progress_every=max(args.progress_every, 0) if not args.quiet else 0,
            progress_label=f"[restart {restart_idx + 1}/{max(args.restarts, 1)}]",
        )
        candidate_text = decode_letters_only(cipher_letters, candidate)
        candidate_score = score_plaintext_letters(candidate_text)
        if candidate_score > best_score:
            best_mapping = candidate
            best_text = candidate_text
            best_score = candidate_score
            consecutive_matches = 1
        elif abs(candidate_score - best_score) < 1e-6:
            consecutive_matches += 1
        else:
            consecutive_matches = 0

        if not args.quiet:
            elapsed = time.perf_counter() - restart_start
            print(
                f"[restart {restart_idx + 1}/{max(args.restarts, 1)}] done in {elapsed:.1f}s, candidate-score={candidate_score:.2f}, global-best={best_score:.2f}",
                flush=True,
            )

        early_stop_n = max(args.early_stop, 0)
        if early_stop_n > 0 and consecutive_matches >= early_stop_n:
            if not args.quiet:
                print(
                    f"[early stop] {consecutive_matches} consecutive restarts matched global best — stopping.",
                    flush=True,
                )
            break

    refined = best_mapping
    refined_text = apply_mapping(ciphertext, refined)

    print("\n=== Refined Guess (hill climb) ===\n")
    print(refined_text)
    if not args.quiet:
        total_elapsed = time.perf_counter() - overall_start
        print(f"\nTotal refinement time: {total_elapsed:.1f}s", flush=True)

    if args.show_map:
        print_mapping(refined)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(refined_text)
        print(f"\nSaved refined plaintext guess to: {args.output}")


if __name__ == "__main__":
    main()
