# Threat Lookup SDLC

## 1. Project Summary
Threat Lookup is a Python and Streamlit application for IOC triage using multi-source threat intelligence APIs (VirusTotal, AlienVault OTX, AbuseIPDB, ThreatFox) and optional AI summary generation. The SDLC below defines how the system is planned, built, tested, deployed, and maintained.

## 2. SDLC Model
Model used: iterative incremental delivery.

Reason:
- External API behavior can change and requires ongoing adjustment.
- Performance and analyst UX improvements are delivered in short cycles.
- Threat context features are continuously enhanced based on user feedback.

## 3. Lifecycle Phases

### Phase 1: Requirements and Planning
Objectives:
- Define business goal: fast IOC triage for analyst and supervisor usage.
- Define non-functional goals: speed, reliability, explainability, low setup friction.
- Define scope boundaries: external intelligence enrichment, no guaranteed single-incident attribution.

Inputs:
- Analyst workflow needs.
- API availability and quotas.
- Supervisor reporting expectations.

Outputs:
- Approved feature list.
- Performance targets.
- Delivery and review milestones.

Exit criteria:
- Requirements are documented and prioritized.
- Data sources and constraints are accepted by stakeholders.

### Phase 2: Architecture and Design
Objectives:
- Establish component design for UI, orchestration, scoring, and external connectors.
- Define risk controls for timeout, retry, and rate-limit behavior.
- Define evidence model and verdict calculation strategy.

Design artifacts:
- UML component and sequence diagrams.
- DFD level 0 and level 1.
- Scoring and verdict rules.

Outputs:
- Approved architecture baseline.
- Interface contracts between UI and engine.

Exit criteria:
- Design review passed.
- Traceability from requirements to components is complete.

### Phase 3: Implementation
Objectives:
- Build and refine core modules.
- Keep source structure organized for maintainability.
- Ensure changes are small and testable.

Implementation scope:
- Core engine in threat_lookup.py.
- Dashboard in app.py.
- Launcher and setup scripts.
- Documentation in docs.

Coding standards:
- Clear function boundaries.
- Defensive handling for API timeouts and missing keys.
- Backward-safe changes to interfaces unless explicitly approved.

Exit criteria:
- Feature branch changes are complete.
- Lint or syntax checks pass.
- Required docs are updated.

### Phase 4: Verification and Testing
Objectives:
- Validate functional correctness, performance, and output quality.
- Confirm behavior under partial API failures.

Test levels:
- Unit-level checks for IOC detection and verdict logic.
- Integration tests for API aggregation paths.
- End-to-end runs through Streamlit workflow.
- Performance checks with small and large IOC sets.

Key test scenarios:
- Mixed IOC type processing.
- Rate-limited and timeout conditions.
- High-confidence malicious override behavior.
- Export correctness for CSV and JSON.

Exit criteria:
- No blocking defects.
- Performance target met for daily usage profile.
- Supervisor demo flow passes.

### Phase 5: Deployment and Release
Objectives:
- Package a clean runnable handoff.
- Keep setup friction minimal for non-developer reviewers.

Release package:
- threat_lookup_final folder with app files, setup script, docs, and sample data.

Release checks:
- Fresh environment setup works.
- Dashboard launch path is validated.
- Required API key template is included.

Exit criteria:
- Handoff package accepted.
- Installation and run instructions verified.

### Phase 6: Operations and Maintenance
Objectives:
- Keep API integrations healthy.
- Maintain performance and relevance of threat context.
- Address user feedback in planned iterations.

Operational tasks:
- Monitor API schema or quota changes.
- Tune concurrency and timeout defaults.
- Improve incident context extraction confidence rules.
- Refresh sample IOC datasets.

Patch management:
- Patching is required when any of the following materially affects confidentiality, integrity, availability, or analyst decision quality:
  - Security vulnerability (authentication bypass, injection, unauthorized access, data exposure, cryptographic weakness)
  - Dependency defect (third-party library bug, unpatched transitive dependency, security advisory)
  - Breaking API change (external or internal schema change affecting data flow or integration)
  - Data-handling risk (loss of integrity, unexpected modification, improper retention or deletion)
  - Operational bug (scoring calculation error, incorrect verdict classification, data loss, performance degradation)
- Patching priority is determined by: severity (critical/high/medium/low), exploitability (active/theoretical), exposure (external-facing/internal-only), business impact (incidents possible/unlikely), and availability of mitigations or workarounds.
- Expedited patching (within 72 hours) is required for: critical severity findings, active exploits, external exposure, or data-integrity issues.
- Standard patching (scheduled monthly) applies to: medium/low severity, theoretical exploitability, internal-only exposure, or finding with effective mitigations in place.
- The patch process is: identify and assess issue → select minimal remediation → implement change → validate with targeted testing → update documentation → release and verify in runtime environment → record change with date, reason, and verification.
- Ownership: development team executes patches; technical lead reviews and approves; operations team validates post-deployment.

Future improvement roadmap:
- Evaluate additional IOC intelligence providers to broaden detection coverage and improve confidence scoring.
- Assess migration from free-tier APIs to paid or enterprise tiers where rate limits materially affect analyst workflow.
- Implement response caching, per-source throttling, and queue-based backoff to reduce inefficiencies caused by quota and timeout constraints.
- Explore use of an internal AI-accessible evidence store or curated analyst database to improve consistency of summaries and reduce repeated lookups.
- Extend enrichment with timeline, infrastructure-linking, and incident-correlation features.
- Consider downstream integration with internal security tooling such as SIEM, EDR, and ticketing systems.

Maintenance cadence:
- Short-cycle updates for urgent fixes.
- Scheduled monthly hardening and documentation review.

Exit criteria:
- Post-release issues triaged and resolved within agreed SLA.
- Documentation remains aligned with behavior.

## 4. Security and Governance Controls
- Secrets stored in environment variables, not hardcoded.
- External-source evidence is labeled as contextual, not absolute truth.
- Exports are user-controlled and locally generated.

## 5. Roles and Responsibilities
- **Technical lead**: prioritization of enhancements and defects, approval of architecture changes, sign-off on releases and patches.
- **Development team**: implementation of features and fixes, code review, unit testing, documentation updates, patch execution.
- **Operations/QA**: end-to-end testing, performance validation, patch deployment verification, production monitoring.
- **Analyst/Business owner**: validation of scoring accuracy and triage quality, feedback on usability and feature impact, incident handling guidance.

## 6. Deliverables Checklist
- Functional source code and launcher.
- Setup guide and architecture documentation.
- UML and DFD diagrams.
- SDLC document.
- Sample IOC files and export examples.
- Supervisor handoff package.

## 7. Success Metrics
- Time to analyze small IOC batches remains within interactive expectations.
- High-confidence malicious indicators are surfaced with clear evidence.
- Setup time for new reviewer is minimal.
- Export outputs are reproducible and understandable.

## 8. Change Management
- Record changes with date, reason, and impact.
- Re-test critical flows after each architecture-impacting change.
- Update docs in the same change set as code updates.

## 9. Version
- Document owner: Riaz Haq
- Version: 1.0.
- Last updated: 2026-06-22.
