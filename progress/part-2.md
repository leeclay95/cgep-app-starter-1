# CGE-P Capstone Progress: Phase 2
## Layer 2 — Policy-as-Code (OPA/Rego)

### Overview
In this phase, I implemented 5 automated guardrails using Rego v1 syntax. These policies enforce CMMC Level 2 technical controls, ensuring that the infrastructure remains compliant and preventing the re-introduction of manual gaps.

---

### Implemented Policies

| Policy File | Control ID | CMMC Practice | Gap Addressed |
| :--- | :--- | :--- | :--- |
| enforce_kms.rego | SC.L2-3.13.11 | FIPS Cryptography | GAP-01, GAP-02 |
| enforce_vpc.rego | SC.L2-3.13.1 | Boundary Protection | GAP-05 |
| enforce_tls.rego | SC.L2-3.13.8 | Transmission Security | GAP-03 |
| enforce_least_privilege.rego | AC.L2-3.1.5 | Least Privilege | GAP-07 |
| enforce_versioning.rego | MP.L2-3.8.9 | Protection of Media | GAP-04 |


