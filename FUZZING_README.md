# OSS-Fuzz Continuous Fuzzing Setup

Docker Compose-based setup for running OSS-Fuzz harnesses continuously on a VPS with Discord alerts.

## Quick Start

### 1. Prerequisites

- Docker and Docker Compose installed
- Discord webhook URL (optional, for crash notifications)

### 2. Setup

```bash
# Run setup script to build images and prepare directories
./setup-fuzzing.sh
```

### 3. Configure Discord (Optional)

Create a `.env` file:

```bash
cp .env.example .env
# Edit .env and add your Discord webhook URL
```

To create a Discord webhook:
1. Go to your Discord server
2. Server Settings > Integrations > Webhooks
3. Create New Webhook
4. Copy the webhook URL

### 4. Configure Fuzzers

Edit `docker-compose.yml` to add/remove fuzzer services. Each fuzzer needs:

```yaml
fuzzer-jsoup-X:
  image: gcr.io/oss-fuzz/jsoup
  volumes:
    - ./fuzzing-data/jsoup-X:/fuzzing-data
    - ./scripts:/scripts:ro
  command: ["/scripts/run-fuzzer.sh", "YourFuzzerName"]
  environment:
    - FUZZER_NAME=YourFuzzerName
    - MAX_TIME_PER_RUN=3600
  restart: unless-stopped
  cpus: 1
  mem_limit: 2g
```

### 5. Start Fuzzing

```bash
./start-fuzzing.sh
```

## Management Commands

```bash
# View all logs
./logs-fuzzing.sh

# View specific fuzzer logs
./logs-fuzzing.sh fuzzer-jsoup-1

# Check statistics
./stats-fuzzing.sh

# Stop all fuzzers
./stop-fuzzing.sh

# Run introspector analysis manually
./scripts/manual-introspector.sh jsoup
```

## Directory Structure

```
fuzzing-data/
├── jsoup-1/
│   ├── corpus/        # Growing test corpus
│   ├── crashes/       # Crash artifacts
│   └── logs/          # Fuzzer output logs
├── jsoup-2/
│   └── ...
└── jsoup-3/
    └── ...
```

## Features

### Continuous Fuzzing
- Each fuzzer runs in 1-hour cycles indefinitely
- Automatic corpus minimization every 10 runs
- Crash artifacts automatically saved
- Automatic restart on crashes

### Monitoring
- Discord notifications for new crashes
- Detailed crash reports with file previews
- Periodic statistics in logs (every 10 minutes)
- Deduplication of crashes by hash
- Daily introspector reports for coverage analysis (sent to Discord)

### Resource Management
- CPU and memory limits per fuzzer
- Configurable via docker-compose.yml
- Prevents resource starvation

## VPS Recommendations

### Minimum Specs
- **CPU**: 4 cores (1-2 fuzzers per core)
- **RAM**: 8GB (2GB per fuzzer + overhead)
- **Storage**: 50GB SSD (corpus grows over time)

### Recommended Specs
- **CPU**: 8 cores
- **RAM**: 16-32GB
- **Storage**: 100GB+ SSD

### Cloud Providers
- **DigitalOcean**: CPU-Optimized Droplets
- **Linode**: Dedicated CPU Instances
- **AWS**: c6i instances
- **Hetzner**: CPX instances (cost-effective)

## Scaling

### Add More Fuzzers

1. Add new service in `docker-compose.yml`
2. Create data directory: `mkdir -p fuzzing-data/jsoup-4`
3. Restart: `./stop-fuzzing.sh && ./start-fuzzing.sh`

### Adjust Resources

Edit `docker-compose.yml` for each fuzzer:

```yaml
cpus: 2              # Number of CPU cores
mem_limit: 4g        # Memory limit
```

### Adjust Fuzzing Duration

Change `MAX_TIME_PER_RUN` environment variable:

```yaml
environment:
  - MAX_TIME_PER_RUN=7200  # 2 hours per run
```

## Monitoring & Alerting

### Discord Alerts

When crashes are found, you'll receive:
- Fuzzer name
- Crash hash (for deduplication)
- File size
- Crash preview
- Timestamp

### Introspector Reports

Daily introspector runs analyze code coverage and reachability:
- Runs automatically every 24 hours
- Reports saved to `introspector-reports/`
- Summary posted to Discord with key metrics
- Shows which code paths fuzzers are reaching

To run manually:
```bash
./scripts/manual-introspector.sh jsoup
```

The report includes:
- Function coverage statistics
- Unreached code blocks
- Complexity analysis
- HTML visualization (open `introspector-reports/report-*/fuzz_report.html`)

### Manual Inspection

```bash
# View crashes
ls -lh fuzzing-data/*/crashes/

# Reproduce a crash
docker run --rm -v $(pwd)/fuzzing-data/jsoup-1:/data \
  gcr.io/oss-fuzz/jsoup \
  /out/CleanerFuzzer /data/crashes/crash-xyz

# View introspector reports
ls -lh introspector-reports/
```

## Troubleshooting

### Fuzzer Not Starting

```bash
# Check logs
./logs-fuzzing.sh fuzzer-jsoup-1

# Verify fuzzer exists in container
docker run --rm gcr.io/oss-fuzz/jsoup ls /out/
```

### No Crashes Found

- This is normal! Fuzzing can take hours/days
- Check corpus is growing: `./stats-fuzzing.sh`
- Verify fuzzers are running: `docker ps`

### High CPU Usage

- Expected during fuzzing
- Reduce number of fuzzers or CPU limits
- Check `docker stats` for resource usage

### Disk Space Issues

```bash
# Check disk usage
df -h

# Minimize all corpora
for dir in fuzzing-data/*/corpus; do
  # Corpus minimization reduces size
  echo "Consider implementing corpus cleanup"
done
```

## Advanced Configuration

### Custom Fuzzer Image

If you've modified the jsoup project:

```bash
# Rebuild image
python3 infra/helper.py build_image jsoup
python3 infra/helper.py build_fuzzers jsoup

# Restart services
./stop-fuzzing.sh && ./start-fuzzing.sh
```

### Add Coverage Analysis

Uncomment Prometheus in `docker-compose.yml` for metrics collection.

### Backup Corpora

```bash
# Periodic backup (add to cron)
tar czf corpus-backup-$(date +%Y%m%d).tar.gz fuzzing-data/*/corpus
```

## Performance Tips

1. **Use SSD storage** - Corpus I/O intensive
2. **Monitor initially** - First 24 hours to tune resources
3. **Minimize corpus regularly** - Keeps size manageable
4. **Deduplicate crashes** - Monitor does this automatically
5. **Use dedicated CPU instances** - Avoid shared vCPUs

## Security Considerations

- Fuzzers run in isolated Docker containers
- No network access required for fuzzing
- Monitor Discord webhook is only outbound connection
- Keep Docker and base images updated

## Cost Estimation

### Example: DigitalOcean
- **4 CPU / 8GB RAM**: ~$48/month
- **8 CPU / 16GB RAM**: ~$96/month

### Example: Hetzner (Lower Cost)
- **4 CPU / 8GB RAM**: ~€20/month
- **8 CPU / 16GB RAM**: ~€40/month

## Support

For issues with:
- **OSS-Fuzz**: https://github.com/google/oss-fuzz
- **This setup**: Check logs and Docker Compose documentation
