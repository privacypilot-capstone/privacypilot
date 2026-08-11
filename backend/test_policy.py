from scanners.policy_parser import parse_privacy_policy

# Test 1 — plain HTML page, definitely works
results = parse_privacy_policy('https://parth268.github.io/App-Privacy-Policy/PrivacyPolicy.html')
print(f'Test 1 - Policy claims: {len(results)}')
for r in results:
    print(f'  {r.pii_category.value}')