# Shared Test Suite

The shared, implementation-neutral test cases live in
[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK):

- `tests/fixtures.json`: the shared client fixtures
- `tests/conformance/fixtures.json`: the resolver conformance suite
- `tests/conformance-harness/python/run.py`: runs the conformance suite against any running server

```bash
# Against a local self-hosted server
python ../SecID-Client-SDK/tests/conformance-harness/python/run.py --target http://localhost:8000

# Against the live service
python ../SecID-Client-SDK/tests/conformance-harness/python/run.py --target https://secid.cloudsecurityalliance.org
```

The Python implementation also runs both fixture files in-process, against the
real registry, in `python/test_real_registry.py`.
