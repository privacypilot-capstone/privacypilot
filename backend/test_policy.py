from scoring import calculate_compliance_score

# Fake violations to test scoring
class FakeV:
    def __init__(self, s): self.severity = s

violations = [FakeV("critical"), FakeV("critical"), FakeV("high"), FakeV("high"), FakeV("high")]
result = calculate_compliance_score(violations, 1649, 3)
print(f"Score: {result['score']}/100")
print(f"Rating: {result['rating']}")
print(f"Critical: {result['critical_count']}, High: {result['high_count']}")