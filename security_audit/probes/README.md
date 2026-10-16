# Isolated audit probes

The original auth/API/epoch/tombstone probes reproduce observations from baseline commit 3341bc0; run them against that baseline with explicitly synthetic configuration, rather than expecting the old calls/results to be compatible with the remediated API. Their saved observations are in ../baseline/. They are not the current regression suite.

Current tests are in ../../tests/. image_smoke.py exercises the packaged final application using synthetic development settings and a temporary database inside a network-isolated non-root container. Production transport/privilege checks are separate.

final_image_verify.py verifies the already built local remediated image, compares every packaged app source with the workspace, runs the synthetic image smoke test, exports a Docker archive, and preserves full vulnerability/secret scans and a CycloneDX SBOM. It requires the recorded Trivy image and existing vulnerability database in `/private/tmp/token-generator-audit-container/cache`; it disables networking and database updates deliberately. Refresh that database before a future assessment rather than reusing this audit's cached snapshot indefinitely. It does not build, publish or deploy images.

The saved postgres_runtime_tls.py and redis_runtime_tls.py generate temporary one-day synthetic identities, use loopback ephemeral ports, run the reviewed derived images and clean their uniquely named containers in finally blocks. They require Docker, OpenSSL and the project dependencies. The default local test tags are token-generator-postgresql:security-fixed and token-generator-redis:security-fixed. Never reuse these synthetic identities/temporary permission arrangements in production. No script reads production configuration or accepts live store credentials.
