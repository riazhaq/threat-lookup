# Threat Lookup UML and DFD

This document captures the current architecture of the Threat Lookup project and the Streamlit UI improvements.

## 1. UML Component View

```mermaid
classDiagram
    class StreamlitUI {
      +upload_iocs()
      +configure_run()
      +run_analysis()
      +render_results()
      +render_ioc_details()
      +export_results()
    }

    class ThreatLookupEngine {
      +analyze_bulk()
      +bulk_lookup()
      +calculate_verdict()
      +prepare_iocs()
    }

    class VirusTotalClient {
      +query_virustotal()
    }

    class AlienVaultOTXClient {
      +query_alienvault()
    }

    class AbuseIPDBClient {
      +query_abuseipdb()
    }

    class ThreatFoxClient {
      +query_threatfox()
    }

    class ExportService {
      +to_csv()
      +to_json()
    }

    class OptionalAISummarizer {
      +summarize_context()
    }

    StreamlitUI --> ThreatLookupEngine
    StreamlitUI --> ExportService
    ThreatLookupEngine --> VirusTotalClient
    ThreatLookupEngine --> AlienVaultOTXClient
    ThreatLookupEngine --> AbuseIPDBClient
    ThreatLookupEngine --> ThreatFoxClient
    ThreatLookupEngine --> OptionalAISummarizer
```

## 2. UML Sequence View

```mermaid
sequenceDiagram
    participant User
    participant UI as Streamlit UI
    participant Engine as Threat Lookup Engine
    participant VT as VirusTotal
    participant OTX as AlienVault OTX
    participant AIP as AbuseIPDB
    participant TF as ThreatFox
    User->>UI: Upload IOC file or paste IOCs
    User->>UI: Start analysis
    UI->>Engine: analyze_bulk(iocs, workers, delay, jitter)

    loop For each IOC
        par Threat source lookups
            Engine->>VT: query_virustotal()
            VT-->>Engine: stats, relationships, context
        and
            Engine->>OTX: query_alienvault()
            OTX-->>Engine: pulses, tags, ATT&CK data
        and
            Engine->>AIP: query_abuseipdb()
            AIP-->>Engine: abuse score, reports, categories
        and
            Engine->>TF: query_threatfox()
            TF-->>Engine: family, confidence, references
        end

        Engine->>Engine: calculate verdict and score
        Engine-->>UI: IOC result row
    end

    UI-->>User: Results table, details pane, export options
```

## 3. Data Flow Diagram

### Level 0

```mermaid
flowchart LR
    U[Analyst / Supervisor] -->|IOCs, settings| S[Threat Lookup System]
    S -->|Verdicts, evidence, exports| U

    S <-->|Threat intel queries| VT[(VirusTotal API)]
    S <-->|Threat intel queries| OTX[(AlienVault OTX API)]
    S <-->|Threat intel queries| AIP[(AbuseIPDB API)]
    S <-->|Threat intel queries| TF[(ThreatFox API)]
```

### Level 1

```mermaid
flowchart TB
    U[User] --> P1[1. Ingest IOCs]
    U --> P2[2. Configure Run Profile]
    P1 --> D1[(IOC Queue)]
    P2 --> D2[(Runtime Parameters)]

    D1 --> P3[3. Concurrent IOC Processing]
    D2 --> P3

    P3 --> P31[3.1 Query VirusTotal]
    P3 --> P32[3.2 Query OTX]
    P3 --> P33[3.3 Query AbuseIPDB]
    P3 --> P34[3.4 Query ThreatFox]

    P31 --> E1[(VirusTotal API)]
    P32 --> E2[(AlienVault OTX API)]
    P33 --> E3[(AbuseIPDB API)]
    P34 --> E4[(ThreatFox API)]

    E1 --> P4[4. Normalize and aggregate evidence]
    E2 --> P4
    E3 --> P4
    E4 --> P4

    P4 --> P5[5. Score and classify verdict]
    P5 --> D3[(Result Set)]

    D3 --> P6[6. Streamlit dashboard output]
    D3 --> P7[7. CSV / JSON export]

    P6 --> U
    P7 --> U
```

## 4. Notes

- `threat_lookup.py` is the core engine and scoring layer.
- `app.py` is the Streamlit dashboard and presentation layer.
- `run_gui.py` is the Windows-friendly launcher for the dashboard.
- `threat_lookup_final/` contains the curated handoff package for your supervisor.