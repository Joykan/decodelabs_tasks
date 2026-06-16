"""Quick test: verify all 5 samples produce correct verdicts."""
from phishing_analyzer import analyze_message, SAMPLE_EMAILS

for sample in SAMPLE_EMAILS:
    result = analyze_message(sample["body"], sample["sender"])
    v = result["verdict"]
    c = result["confidence"]
    n = result["stats"]["total_flags"]
    print(f"{sample['name']}")
    print(f"  => {v} ({c}% confidence, {n} flags)")
    cats = result["stats"]["categories_triggered"]
    print(f"  => Categories: {', '.join(cats) if cats else 'None'}")
    print()
