# Microsoft Sentinel Detection Rules

A collection of custom detection rules engineered for Microsoft Sentinel, organized by [MITRE ATT&CK](https://attack.mitre.org/tactics/enterprise/) tactic. Rules are written in YAML for readability and maintainability, and are automatically converted to deployment-ready JSON via a CI/CD pipeline on every push.

---

## Repository Structure

```
├── .github/
│   └── workflows/
│       ├── Convert_Detections_YAML.yml     # Auto-converts detection YAMLs to JSON on push
│       ├── Convert_Resources_YAML.yml      # Auto-converts resource YAMLs to JSON on push
│       └── Validate_Detection_Schema.yml   # Validates rules against schema on push and PR
├── Detections/
│   ├── Collection/
│   ├── Command and Control/
│   ├── Credential Access/
│   ├── Defense Evasion/
│   ├── Discovery/
│   ├── Execution/
│   ├── Exfiltration/
│   ├── Impact/
│   ├── Initial Access/
│   ├── Lateral Movement/
│   ├── Persistence/
│   ├── Privilege Escalation/
│   ├── Reconnaissance/
│   └── Resource Development/
├── Resources/
│   └── Sample Template YAML.yml            # Starter template for new detection rules
├── Schemas/
│   └── New_Rule_Validation_Schema.json     # JSON schema used for rule validation
└── Validation_Scripts/
    └── Schema_Validation.py                # Validates YAML/JSON rules against the schema
```

Each tactic folder maps directly to a MITRE ATT&CK tactic. Detection rules are placed in the folder that corresponds to their primary tactic.

---

## How It Works

### Authoring
Detection rules are written in YAML using the Microsoft Sentinel ARM template format. YAML is used as the source of truth because it's human-readable, diff-friendly, and easy to review and version-control.

### Automated Conversion
A GitHub Actions workflow (`Convert_Detections_YAML.yml`) triggers on every push that touches a `.yml` or `.yaml` file inside the `Detections/` folder. It converts each YAML rule to a formatted JSON file in-place, auto-commits the result, and pushes it back to the repository. The JSON output is what gets deployed to Sentinel.

### Validation
The `Schema_Validation.py` script validates both YAML and JSON rule files against the schema defined in `Schemas/New_Rule_Validation_Schema.json`. The schema enforces structural correctness across all required fields including severity, MITRE ATT&CK tactics and techniques, ISO 8601 duration formats, and entity mappings.

Validation runs automatically via GitHub Actions on every push and pull request targeting main that touches files under `Detections/`. The validation check must pass before any PR can be merged. You can also run validation locally before pushing:

```bash
python Validation_Scripts/Schema_Validation.py
```

### Branch Protection
Main is protected by a branch ruleset that requires the schema validation check to pass before any PR can be merged. Direct force pushes to main are blocked. All changes must flow through a PR from dev, pass validation, and be up to date with main before merging.

---

## Detection Rule Format

Every rule follows the Microsoft Sentinel ARM template schema and includes the following fields:

| Field | Description |
|---|---|
| `displayName` | Human-readable name of the detection |
| `description` | What the rule detects and why it matters |
| `severity` | `Informational`, `Low`, `Medium`, or `High` |
| `query` | KQL query that drives the detection |
| `queryFrequency` | How often the query runs (ISO 8601 duration, e.g. `PT5M`) |
| `queryPeriod` | Lookback window for the query |
| `tactics` | MITRE ATT&CK tactics |
| `techniques` | MITRE ATT&CK techniques |
| `subTechniques` | MITRE ATT&CK sub-techniques |
| `entityMappings` | Maps query columns to Sentinel entity types |
| `incidentConfiguration` | Controls incident creation and alert grouping |

---

## Adding a New Detection Rule

1. Copy `Resources/Sample Template YAML.yml` into the appropriate MITRE tactic folder under `Detections/`.
2. Rename the file to match your rule's display name.
3. Fill in all required fields — query, severity, tactics, techniques, entity mappings.
4. Remove the `id` field entirely if creating a new rule (Sentinel will assign one automatically).
5. Push your changes to dev and open a PR targeting main.
6. The schema validation workflow will run automatically on the PR and must pass before merging.
7. Once the PR is merged, the CI/CD pipeline will automatically generate the corresponding JSON file on main.

> **Note:** When updating an existing rule, copy the full `id` field from the existing rule into the YAML before pushing. This ensures Sentinel updates the rule in-place rather than creating a duplicate.

> **Tip:** Run `Schema_Validation.py` locally before pushing to catch any structural issues before they reach the pipeline.

---

## Deploying a Rule to Sentinel

The generated JSON files are ARM templates ready for deployment. You can deploy them using:

**Azure Portal**
- Navigate to **Microsoft Sentinel → Analytics → Create → Import rule from ARM template**
- Upload the `.json` file for the rule you want to deploy

**Azure CLI**
```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file "Detections/<Tactic>/<RuleName>.json" \
  --parameters workspace=<your-sentinel-workspace-name>
```

**PowerShell**
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<your-resource-group>" `
  -TemplateFile "Detections/<Tactic>/<RuleName>.json" `
  -workspace "<your-sentinel-workspace-name>"
```

---

## Detection Coverage

| Tactic | Rules |
|---|---|
| Execution | Detection of MicRun.exe – Potential DeedRAT Activity |
| Persistence | Registry Persistence via MicRun – Potential DeedRAT Activity |
| Persistence | Service Creation via MicRun – Potential DeedRAT Activity |
| Lateral Movement | Detection of AD CS Relay and Coercion Tool Usage (ntlmrelayx, PetitPotam, psexec, DCSync) |
| Lateral Movement | Suspicious NTLM Authentication to Certificate Authority Servers from Unexpected Accounts |
| Impact | Possible Email Bombing Attack |

> This table is updated as new rules are added.

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/tactics/enterprise/)
- [Microsoft Sentinel Analytics Rule ARM Schema](https://learn.microsoft.com/en-us/azure/templates/microsoft.operationalinsights/workspaces/providers/alertrules)
- [Microsoft Sentinel Entity Mappings](https://learn.microsoft.com/en-us/azure/sentinel/create-custom-entity-mapping)
- [KQL Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)