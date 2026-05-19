#!/usr/bin/env python3
"""Vigenere (polyalphabetic) decoder helper.

Features:
1) Kasiski-style repeated n-gram distance hints for key length
2) Index of Coincidence (IC) scoring for key-length candidates
3) Automatic key recovery via per-column Caesar chi-squared scoring
4) Plaintext output with recovered key
"""

from __future__ import annotations

import argparse
import math
import re
import string
from collections import Counter
from typing import Dict, List, Tuple

ALPHABET = string.ascii_uppercase
ALPHABET_SIZE = len(ALPHABET)
ENGLISH_FREQ = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def clean_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def index_of_coincidence(text: str) -> float:
    letters = clean_letters(text)
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    num = sum(c * (c - 1) for c in counts.values())
    den = n * (n - 1)
    return num / den


def split_by_key_length(text: str, key_len: int) -> List[str]:
    letters = clean_letters(text)
    cols = ["" for _ in range(key_len)]
    for i, ch in enumerate(letters):
        cols[i % key_len] += ch
    return cols


def average_column_ic(text: str, key_len: int) -> float:
    cols = split_by_key_length(text, key_len)
    if not cols:
        return 0.0
    values = [index_of_coincidence(col) for col in cols if len(col) > 1]
    return sum(values) / len(values) if values else 0.0


def kasiski_distances(text: str, ngram_len: int = 3) -> List[int]:
    letters = clean_letters(text)
    seen: Dict[str, List[int]] = {}
    for i in range(len(letters) - ngram_len + 1):
        gram = letters[i : i + ngram_len]
        seen.setdefault(gram, []).append(i)

    distances: List[int] = []
    for positions in seen.values():
        if len(positions) < 2:
            continue
        for i in range(len(positions) - 1):
            for j in range(i + 1, len(positions)):
                distances.append(positions[j] - positions[i])
    return distances


def kasiski_factor_votes(distances: List[int], max_key_len: int) -> Counter:
    votes: Counter = Counter()
    for d in distances:
        for f in range(2, max_key_len + 1):
            if d % f == 0:
                votes[f] += 1
    return votes


def caesar_decrypt(text: str, shift: int) -> str:
    out = []
    for ch in text:
        idx = ALPHABET.index(ch)
        out.append(ALPHABET[(idx - shift) % ALPHABET_SIZE])
    return "".join(out)


def chi_squared_english(text: str) -> float:
    letters = clean_letters(text)
    n = len(letters)
    if n == 0:
        return float("inf")

    counts = Counter(letters)
    score = 0.0
    for letter in ALPHABET:
        observed = counts[letter]
        expected = ENGLISH_FREQ[letter] * n
        if expected > 0:
            score += ((observed - expected) ** 2) / expected
    return score


def best_caesar_shift_for_column(column_text: str) -> int:
    best_shift = 0
    best_score = float("inf")

    for shift in range(ALPHABET_SIZE):
        candidate_plain = caesar_decrypt(column_text, shift)
        score = chi_squared_english(candidate_plain)
        if score < best_score:
            best_score = score
            best_shift = shift

    return best_shift


def recover_key(text: str, key_len: int) -> str:
    cols = split_by_key_length(text, key_len)
    shifts = [best_caesar_shift_for_column(col) for col in cols]
    return "".join(ALPHABET[s] for s in shifts)


def decrypt_vigenere(text: str, key: str) -> str:
    key = clean_letters(key)
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")

    out = []
    key_i = 0
    for ch in text:
        up = ch.upper()
        if up in ALPHABET:
            c_idx = ALPHABET.index(up)
            k_idx = ALPHABET.index(key[key_i % len(key)])
            p_idx = (c_idx - k_idx) % ALPHABET_SIZE
            repl = ALPHABET[p_idx]
            out.append(repl if ch.isupper() else repl.lower())
            key_i += 1
        else:
            out.append(ch)
    return "".join(out)


def score_plaintext_basic(text: str) -> float:
    upper = text.upper()
    words = ["THE", "AND", "ING", "THAT", "HAVE", "WITH", "TION", "MENT", "THIS"]
    score = -chi_squared_english(clean_letters(text))
    for w in words:
        score += upper.count(w) * 3.0
    score += upper.count("TH") * 0.5
    score += upper.count("HE") * 0.5
    score += upper.count("IN") * 0.4
    return score


def rank_key_lengths(text: str, min_len: int, max_len: int) -> List[Tuple[int, float]]:
    rows: List[Tuple[int, float]] = []
    target_ic = 0.066
    for k in range(min_len, max_len + 1):
        ic = average_column_ic(text, k)
        # Closer to English IC is better; avoid tiny penalties for larger keys.
        score = -abs(ic - target_ic) - (k * 0.0002)
        rows.append((k, score))
    rows.sort(key=lambda x: x[1], reverse=True)
    return rows


def auto_recover_key(text: str, min_len: int, max_len: int, top_lens: int) -> Tuple[str, int, List[Tuple[int, float]], Counter]:
    ic_ranked = rank_key_lengths(text, min_len, max_len)
    candidate_lengths = [k for k, _ in ic_ranked[: max(top_lens, 1)]]

    distances = kasiski_distances(text, ngram_len=3)
    kasiski_votes = kasiski_factor_votes(distances, max_len)

    # Merge extra likely lengths from Kasiski votes.
    for k, _ in kasiski_votes.most_common(top_lens):
        if k >= min_len and k <= max_len and k not in candidate_lengths:
            candidate_lengths.append(k)

    best_key = ""
    best_len = candidate_lengths[0]
    best_score = -math.inf

    for k in candidate_lengths:
        key = recover_key(text, k)
        plain = decrypt_vigenere(text, key)
        score = score_plaintext_basic(plain)
        if score > best_score:
            best_key = key
            best_len = k
            best_score = score

    return best_key, best_len, ic_ranked, kasiski_votes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vigenere decoder using IC + Kasiski hints + Caesar column scoring."
    )
    parser.add_argument(
        "--input",
        default="poly-alphabetic.txt",
        help="Path to Vigenere ciphertext file (default: poly-alphabetic.txt)",
    )
    parser.add_argument(
        "--key",
        default="",
        help="Optional known key. If given, auto key recovery is skipped.",
    )
    parser.add_argument(
        "--min-keylen",
        type=int,
        default=2,
        help="Minimum key length to test (default: 2)",
    )
    parser.add_argument(
        "--max-keylen",
        type=int,
        default=20,
        help="Maximum key length to test (default: 20)",
    )
    parser.add_argument(
        "--top-lens",
        type=int,
        default=6,
        help="How many top key lengths to evaluate from IC/Kasiski (default: 6)",
    )
    parser.add_argument(
        "--show-analysis",
        action="store_true",
        help="Print IC key-length ranking and Kasiski factor votes",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional output file for decrypted plaintext",
    )

    args = parser.parse_args()
    ciphertext = read_text(args.input)

    if args.key:
        key = clean_letters(args.key)
        if not key:
            raise ValueError("Provided key has no letters.")
        key_len = len(key)
        key_source = "Provided"
        plain = decrypt_vigenere(ciphertext, key)
    else:
        min_len = max(args.min_keylen, 1)
        max_len = max(args.max_keylen, min_len)

        key, key_len, ic_ranked, kasiski_votes = auto_recover_key(
            ciphertext, min_len=min_len, max_len=max_len, top_lens=max(args.top_lens, 1)
        )
        key_source = "Recovered"
        plain = decrypt_vigenere(ciphertext, key)

        if args.show_analysis:
            print("\nTop IC key-length candidates:")
            for k, score in ic_ranked[:10]:
                print(f"  len={k:>2}  score={score: .5f}  avg-IC={average_column_ic(ciphertext, k):.5f}")

            print("\nTop Kasiski factor votes:")
            for k, votes in kasiski_votes.most_common(10):
                print(f"  len={k:>2}  votes={votes}")

    print(f"\n=== {key_source} Key ===")
    print(f"{key} (length {key_len})")
    print("\n=== Decrypted Plaintext ===\n")
    print(plain)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(plain)
        print(f"\nSaved decrypted plaintext to: {args.output}")


if __name__ == "__main__":
    main()
