# Self-Annealing System

## Overview

The scanner now includes a self-annealing system that automatically learns from failures and adapts to problematic repositories.

## How It Works

### 1. Failure Tracking
When a repository scan fails (timeout or error), the system:
- Increments `failure_count` in the database
- Records `last_failure_at` timestamp
- Saves `last_failure_reason` (e.g., "timeout after 5.2m", "error: ConnectionError")

### 2. Automatic Skip Logic
Before scanning a repository, the system checks:

```
┌─────────────────────────────────────────────┐
│ 1. Has repo failed ≥3 times?               │
│    └─> YES: Skip if failed within 7 days   │
│    └─> NO: Continue checks                 │
├─────────────────────────────────────────────┤
│ 2. Was repo scanned within 48 hours?       │
│    └─> YES: Skip (if --skipscan flag)      │
│    └─> NO: Continue checks                 │
├─────────────────────────────────────────────┤
│ 3. Is repo inactive (>180 days)?           │
│    └─> YES: Skip                            │
│    └─> NO: Continue to scan                │
└─────────────────────────────────────────────┘
```

### 3. Self-Healing
- **On Success**: Failure count resets to 0
- **On Failure**: Failure count increments
- **Periodic Retry**: After 7 days, even problematic repos are retried

## Configuration

Default thresholds (configurable):
- **Failure threshold**: 3 consecutive failures → auto-skip
- **Retry period**: 7 days before attempting again
- **Timeout**: 5 minutes per repo (with progress monitoring)
- **Idle threshold**: 3 minutes of no progress → timeout

## Example Scenarios

### Scenario 1: Problematic Repo
```
Scan 1: ❌ Timeout (5m) → failure_count = 1
Scan 2: ❌ Timeout (5m) → failure_count = 2
Scan 3: ❌ Timeout (5m) → failure_count = 3
Scan 4: ⏭️ SKIPPED (3 failures, last 2 days ago)
...
Scan 10 (8 days later): 🔄 RETRY → ✅ Success → failure_count = 0
```

### Scenario 2: Transient Issue
```
Scan 1: ❌ Error (network issue) → failure_count = 1
Scan 2: ✅ Success → failure_count = 0 (reset)
```

### Scenario 3: Permanently Problematic
```
Scan 1: ❌ Timeout → failure_count = 1
Scan 2: ❌ Timeout → failure_count = 2
Scan 3: ❌ Timeout → failure_count = 3
Every scan: ⏭️ SKIPPED (until 7 days pass)
Retry after 7 days: ❌ Timeout → failure_count = 4
Every scan: ⏭️ SKIPPED (until 7 days pass again)
```

## Database Schema

```sql
ALTER TABLE repositories
ADD COLUMN failure_count INTEGER DEFAULT 0,
ADD COLUMN last_failure_at TIMESTAMP,
ADD COLUMN last_failure_reason VARCHAR(255);
```

## Migration

Run the migration to add tracking columns:

```bash
docker-compose exec db psql -U auditgh -d auditgh -f /app/migrations/add_failure_tracking.sql
```

## Logs

Watch for self-annealing logs during scans:

```
INFO:root:⏭️ Skipping repo-name: Repository has failed 3 times (last: timeout after 5.2m, 2.1d ago). Will retry after 7 days.
INFO:root:📊 Recorded failure for repo-name: timeout after 5.2m (count: 3)
INFO:root:✅ Reset failure count for repo-name (was: 2)
```

## Benefits

1. **Automatic**: No manual intervention needed for problematic repos
2. **Self-healing**: Automatically retries to detect if issues resolved
3. **Efficient**: Saves time by skipping known problematic repos
4. **Configurable**: Thresholds can be adjusted per environment
5. **Observable**: Clear logging shows what's happening

## Manual Override

To force scan a problematic repo:

```bash
docker-compose run --rm auditgh --repo "repo-name" --overridescan
```

The `--overridescan` flag bypasses ALL skip logic including failure tracking.
