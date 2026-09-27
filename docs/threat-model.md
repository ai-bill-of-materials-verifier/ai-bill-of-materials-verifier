# Threat model

Attackers may modify, truncate, append, swap chunks, or replace files between verification and load. AI Bill of Materials Verifier detects offline byte changes, signature mismatches, bill-of-materials and manifest root mismatches, and disallowed provenance builders or materials. It does not claim to detect malicious model behavior after loading.
