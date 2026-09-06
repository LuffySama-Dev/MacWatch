# SigNoz Cloud setup

MacWatch does not create cloud resources or notification destinations. Complete these steps after at least one user-triggered test event and one heartbeat have arrived.

## Ingestion

1. In SigNoz Cloud, copy the OTLP endpoint for your region. Current endpoints use `https://ingest.<region>.signoz.cloud:443`; deprecated generic endpoints should not be used.
2. Create or copy an ingestion key in SigNoz. Do not paste it into source code or chat.
3. In MacWatch → Cloud, enter the HTTPS base endpoint and key, enable export, and choose **Save locally**. The key is stored in macOS Keychain. Redirects are refused so the credential is not forwarded to another origin.
4. Select **Send clearly labeled test event**. In SigNoz Logs Explorer filter `service.name = 'macwatch' AND event.is_test = true`. This validates only the observed delivery; it does not prove future delivery or alert behavior.
5. In Metrics Explorer confirm `macwatch.heartbeat` has appeared. It is emitted every 60 seconds while MacWatch runs and the Mac is awake.

MacWatch sends OTLP/HTTP JSON to `/v1/logs` and `/v1/metrics` with `Content-Type: application/json` and `signoz-ingestion-key`. It preserves TLS verification, batches up to 20 queued payloads by signal, has a bounded 500-item disk queue, retries transient errors with exponential backoff and jitter, honors numeric `Retry-After`, does not retry partial acceptance or permanent 4xx failures, and drops stale queued heartbeat records.

## Dashboard (current UI workflow)

SigNoz’s V2 dashboard JSON schema is versioned and validated against both panels and layouts. To avoid shipping a brittle unverified definition, create a blank dashboard using the documented current UI:

1. Open **Dashboards → New Dashboard → Blank**; name it `MacWatch`.
2. In **Logs Explorer**, build each log query below, choose a time-series or value visualization, then use **Add to Dashboard** and choose `MacWatch`.
3. In **Metrics Explorer**, build each metric query below and add it to the same dashboard.

Recommended panels:

| Panel | Signal and filter/query | Display |
|---|---|---|
| Camera and microphone activity | Logs: `service.name = 'macwatch' AND event.kind IN ('cameraActivated', 'microphoneActivated')`; aggregate `count()`; group by `event.kind` | Time series |
| Startup changes | Logs: `service.name = 'macwatch' AND event.kind IN ('startupAdded', 'startupRemoved', 'startupModified')`; aggregate `count()`; group by `event.kind` | Time series |
| SSH sessions | Logs: `service.name = 'macwatch' AND event.kind IN ('sshSessionObserved', 'sshSessionClosed')`; aggregate `count()`; group by `event.kind` | Time series |
| Listening endpoints | Logs: `service.name = 'macwatch' AND event.kind IN ('listeningEndpointOpened', 'listeningEndpointClosed')`; show columns `server.address`, `server.port`, `network.transport`, `network.exposure`, and `process.name`; for charts use `count()` grouped by `event.kind`, `server.address`, and `server.port` | Table for details; time series for trends |
| Monitor errors | Logs: `service.name = 'macwatch' AND event.kind = 'monitorError'`; aggregate `count()` | Value and time series |
| Monitoring state | Metric `macwatch.monitor.up`, latest value grouped by `monitor.name` | 1 means a successful scan within 90 seconds with no subsequent failure; 0 means unavailable, stale, or awaiting a first successful scan |
| Last observed heartbeat | Metric `macwatch.heartbeat`, latest value | Value; interpret as Unix seconds |
| Export failure state | Metric `macwatch.export.failure`, latest value | Value (1 means the app last observed an export error) |
| Queue and drops | Metrics `macwatch.export.queue.size` and `macwatch.export.dropped.total` | Time series |

The current SigNoz docs describe [adding log queries to dashboards](https://signoz.io/docs/userguide/logs_query_builder/) and [managing dashboard panels](https://signoz.io/docs/userguide/manage-dashboards/).

## Alerts

Create recipients separately in SigNoz; MacWatch does not change them. For each rule, use **Alerts → New Alert** or the panel’s **… → Create Alerts**, review the query, then configure your chosen notification destination.

1. **Camera/microphone activation** — Log alert with `service.name = 'macwatch' AND event.kind IN ('cameraActivated', 'microphoneActivated')`, `count() > 0` over a user-chosen evaluation window (start with 1 minute). Disable missing-data alerting because these are intentionally sparse events.
2. **Startup location changed** — Log alert with `service.name = 'macwatch' AND event.kind IN ('startupAdded', 'startupRemoved', 'startupModified')`, `count() > 0` over 1 minute. Disable missing-data alerting.
3. **Monitor failure** — Log alert with `service.name = 'macwatch' AND event.kind = 'monitorError'`, `count() > 0` over 5 minutes. Disable missing-data alerting.
4. **SSH session observed** — Alert on `sshSessionObserved`. Authentication success/failure events are unavailable while the Endpoint Security integration is disabled.
5. **Listening endpoint opened** — Alert on `listeningEndpointOpened`. The exported record includes transport, local bind address, port, exposure, and process name. PID and executable path remain local; use MacWatch history for those details.
6. **Monitoring unavailable** — Metrics alert on `macwatch.heartbeat`. In **Advanced Options**, enable **Alert when data stops coming** and set 10 minutes. Name it exactly `Monitoring unavailable`. Do not label this “Compromise detected.”

The [SigNoz missing-data guide](https://signoz.io/docs/alerts-management/user-guides/how-to-configure-alerts-for-missing-data/) notes that the missing period should exceed the reporting interval. Missing heartbeat can mean sleep, shutdown, app exit, network loss, exporter failure, or interference. A missing-data rule generally cannot evaluate a time series that has never existed, so confirm the first heartbeat before relying on the alert, then validate it benignly by quitting MacWatch for longer than the configured interval. Alert delivery is unverified until you perform that end-to-end test.

Health samples expire from the outbound queue after 120 seconds, like heartbeats. Each automatic monitor reports its own health and recovers after a successful scan. Use `monitor.name` to distinguish camera, microphone, startup, SSH configuration (`ssh`), SSH sessions (`ssh-sessions`), and listening ports (`ports`). A running app heartbeat does not imply that every monitor is healthy.

Turning export off stops further batches and requests cancellation of an in-flight request. Data already delivered cannot be recalled. Pending records remain local for a later explicit re-enable. An invalid configuration leaves export disabled.
