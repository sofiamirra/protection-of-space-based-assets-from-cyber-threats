# Cybersecurity and National Defence - Technical Project

## Topic B - Cyber Risk Prioritization and Treatment Tool

## Group Members

- Pietro Isnardi - s335801
- Lorenzo Iannicelli - s341841
- Sofia Mirra - s329259
- Luca Tartarini - s338507

## Project Description

This project implements a simple cyber risk prioritization and treatment tool.

The program reads three JSON files containing assets, threat scenarios and security controls. For each scenario, it computes the initial risk:

```text
Risk = Likelihood x Impact
```

Then, the program applies the reductions provided by the controls already deployed in that scenario and computes the residual risk. If the residual risk is higher than the acceptable threshold of the affected asset, the tool recommends additional controls from the catalog.

A control can be recommended only if it is applicable to the threat of the scenario and is not already deployed.

The example dataset is based on space-related cyber-physical assets, such as GNSS Ground Stations, AOCS Sensors, SpaceWire buses, COTS hardware, and TT&C uplink channels.

## Python Version

The project requires Python 3.8 or higher.

## Required Libraries

The project uses only the Python standard library:

- `argparse`
- `json`
- `pathlib`
- `typing`

No external libraries are required. The `requirements.txt` file is included for completeness, but it can remain empty.

## Installation

A virtual environment is recommended but not required.

On Linux or macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Then run:

```bash
pip install -r requirements.txt
```

Since the project uses only the Python standard library, no additional packages are installed.

## How to Run

From the project root directory, run the command according to your operating system.

### Windows

```bash
python main.py --input input --output output/result.json
```

### macOS / Linux

```bash
python3 main.py --input input --output output/result.json
```

The `--input` argument must point to the folder containing the input JSON files.  
The `--output` argument defines where the output JSON file will be written.

If the output file already exists, it is overwritten.

## Input Files

The example input folder contains:

```text
input/
├── assets.json
├── security_controls.json
└── scenarios.json
```

### assets.json

Contains the assets to be protected. Each asset includes:

- `id`
- `name`
- `type`
- `value`
- `criticality`
- `risk_threshold`

### security_controls.json

Contains the catalog of available security controls. Each control includes:

- `id`
- `name`
- `description`
- `applicable_threats`
- `likelihood_reduction`
- `impact_reduction`

### scenarios.json

Contains the threat scenarios to analyze. Each scenario includes:

- `id`
- `asset_id`
- `threat`
- `exposure`
- `likelihood`
- `impact`
- `deployed_controls`

In the example dataset, most scenarios start without deployed controls. Scenario `S4` already includes one deployed control, so the program also shows how residual risk is calculated when a mitigation is already in place.

## Main Data Structures

The program uses dictionaries for the main lookup operations.

Assets are stored as:

```python
assets_dict = {a["id"]: a for a in assets.get("assets", [])}
```

This allows the program to quickly retrieve an asset from its identifier.

Controls are stored as:

```python
controls_dict = {c["id"]: c for c in controls.get("security_controls", [])}
```

This allows the program to quickly retrieve a security control from its identifier.

The scenarios are kept as a list and processed one by one.

## Risk Treatment Logic

For each scenario, the program:

1. retrieves the related asset;
2. computes the initial risk;
3. applies the reductions of deployed controls;
4. computes the residual risk;
5. compares the residual risk with the asset threshold;
6. recommends additional controls if needed;
7. sorts the final results by priority.

The recommendation strategy is greedy. Controls are ordered by:

```text
likelihood_reduction + impact_reduction
```

and added until the threshold is met or no more applicable controls are available.

## Output

The program generates a JSON file containing:

- a `summary` section;
- a `risk_results` section with one result for each scenario.

Each scenario result includes the initial risk, deployed controls, residual risk, threshold, status, recommended controls, projected risk after recommendation, treatment result, and priority.

Possible treatment results are:

- `already_acceptable`
- `threshold_met`
- `threshold_not_met`

## Edge Case Handled

One edge case explicitly handled by the implementation is an unknown control identifier.

If a scenario contains a control id that is not present in `security_controls.json`, the program does not stop. The unknown control is reported in the output under:

```json
"invalid_control_references": [...]
```

The scenario is still processed using the valid controls.

The program also avoids counting the same deployed control more than once if it appears multiple times.

## Design Limitation

The main limitation of the project is the greedy recommendation strategy.

This approach is simple and clear, but it does not always guarantee the best possible combination of controls in larger or more complex datasets. The model also uses simplified integer scores from 1 to 5, while real risk assessment would require more detailed technical and organizational analysis.
