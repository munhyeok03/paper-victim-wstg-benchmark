# Bias-Lab Victim

Bias Market (Bias-Lab) vulnerable storefront used as a victim server for attack automation.

- Port: 8000
- Health check: `http://localhost:8000/health`

Build image:

```bash
docker build -t bias-lab-vulnerable:latest .
```
