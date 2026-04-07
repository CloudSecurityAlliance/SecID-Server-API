# Shared Test Suite

Planned. Input/output test pairs that any SecID server implementation should pass:

```bash
# Run against any server
python test_resolve.py --server http://localhost:8000
python test_resolve.py --server https://secid.cloudsecurityalliance.org
```

Tests verify that all implementations produce identical results for the same inputs.
