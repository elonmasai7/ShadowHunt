# ShadowHunt

ShadowHunt is a lightweight, containerized ATT&CK simulation and detection framework for education and defensive research.

## Ethical Use
Use only in isolated lab environments you own and control.
No outbound internet, no real credentials, no production systems.
All attack activity in this repo is simulated marker generation only.

## Features
- Safe ATT&CK simulations: T1078, T1003, T1021 (synthetic events)
- Multi-step attack chains with adversary profiles: low, medium, high
- Realistic noise injection and controlled false-positive generation
- Detector hardening demo: legacy vs hardened mode for benign encoded marker evasion
- Coverage scoring and ATT&CK gap analysis in dashboard
- Privacy: differential privacy metrics + hashed identifiers
- Dual dashboards: ATT&CK operations and real system telemetry

## Quick Start
```bash
docker compose up -d --build
```

Open:
- API: http://localhost:8000/docs
- ATT&CK Dashboard: http://localhost:8501
- System Dashboard: http://localhost:8502

## API
- POST `/start_sim` with `{"technique":"T1078|T1003|T1021"}`
- POST `/start_chain` with `{"profile":"low|medium|high","include_noise":true,"evasion":false}`
- POST `/detection/mode/{legacy|hardened}`
- GET `/profiles`
- GET `/detect`
- GET `/coverage`
- GET `/report`
- GET `/system/metrics`
- GET `/system/status`

## Security Model
- Internal Docker network (`internal: true`)
- Dropped Linux capabilities where possible
- `no-new-privileges` enabled
- Optional host iptables egress blocking script in `docker/`

## Development Notes
OSSEC config is provided for extension, but the default demo path uses synthetic JSON logs + rule engine + ML + privacy stage to stay lean.

## License
MIT
