# MPC-Config Repository Setup

This repository has been created as a standalone configuration repository for deploying MPC nodes using the distributed-auth Docker image.

## Repository Structure

```
mpc-config/
├── README.md              # Main documentation and setup guide
├── configs.yaml           # Node configuration file
├── process_config.sh      # Configuration validator and certificate generator
├── docker-compose.yml     # Docker Compose configuration (uses Docker image)
├── .gitignore            # Git ignore rules
├── mosquitto/
│   └── config/
│       └── mosquitto.conf # MQTT broker configuration
└── data/                  # Created at runtime (gitignored)
    ├── mongodb/          # MongoDB data
    ├── app/logs/         # Application logs
    └── mosquitto/        # Mosquitto data and logs
```

## Key Changes from distributed-auth Repository

1. **Standalone Configuration**: All configuration files are at the root level, not in a `console/` subdirectory
2. **Docker Image Based**: `docker-compose.yml` uses the pre-built Docker image instead of building from source
3. **Path Adjustments**: `process_config.sh` has been adapted to work from the repository root
4. **Public Repository**: This repository is public and contains no source code - only configuration and setup scripts

## Usage Workflow

1. **Clone this repository:**
   ```bash
   git clone https://github.com/ContinuumDAO/mpc-config.git
   cd mpc-config
   ```

2. **Configure your node:**
   - Edit `configs.yaml` with your settings
   - Set node addresses, management keys, etc.

3. **Validate and generate certificates:**
   ```bash
   ./process_config.sh
   ```

4. **Deploy with Docker:**
   ```bash
   docker-compose up -d
   ```

## Docker Image

The `docker-compose.yml` uses:
```yaml
image: continuumdao/distributed-auth:latest
```

For production, replace `latest` with a specific version tag (e.g., `v1.12`).

## Benefits of This Split

- **Public Access**: Users can clone and configure without access to the private distributed-auth repository
- **Simplified Setup**: Only configuration files needed, no source code
- **Version Control**: Configuration changes can be tracked separately
- **Security**: Private keys and source code remain in the private repository
- **Easier Updates**: Update Docker image version without needing source code access
