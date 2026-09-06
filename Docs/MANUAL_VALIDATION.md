# Benign manual validation checklist

Use only data and accounts you control. None of these steps proves the Mac is uncompromised.

- [ ] Launch MacWatch and confirm the menu-bar eye icon appears. Overview should say exactly what is Active, Periodic, Manual, or Unavailable.
- [ ] Open FaceTime or another trusted camera app. Confirm an activation event appears, then an inactive event after closing it. Confirm responsible process says **Unknown**. MacWatch must not request camera access or show captured media.
- [ ] Open Voice Memos or another trusted microphone app. Confirm activation/deactivation events. MacWatch must not request microphone access or record audio.
- [ ] Disconnect and reconnect an external camera/microphone if available. Confirm interruption/restoration events.
- [ ] For safe startup testing, do **not** use the real LaunchAgents folder. Run `swift run MacWatchSelfTest`; it creates and removes a unique directory under the system temporary directory and verifies baseline/add/modify/remove behavior there.
- [ ] Confirm the SSH monitor establishes a baseline without emitting an event. In System Settings > General > Sharing, enable and then disable Remote Login using an account and network you control; confirm both configuration changes appear. Do not expose SSH to the public internet for this test.
- [ ] SSH authentication success/failure validation is skipped while the Endpoint Security integration is disabled.
- [ ] On a private network you control, enable Remote Login for a dedicated test account and make a valid terminal-backed login from another device. Confirm the session appears under **Active SSH sessions**, then disconnect and verify `sshSessionClosed` includes a duration. Authentication success/failure events are not expected while Endpoint Security is disabled. Disable Remote Login afterward. Never expose the test account or port 22 directly to the public internet.
- [ ] Start a trusted development server bound to `127.0.0.1` on a temporary high port. Confirm `listeningEndpointOpened` reports `loopbackOnly`, then stop it and confirm `listeningEndpointClosed`. If testing an all-interface binding, use only a trusted private network and stop it immediately afterward; a listener does not prove external reachability.
- [ ] Put the Mac to sleep for at least one minute and wake it. Confirm pause/resume events and a reported gap; confirm no queued stale heartbeat later appears as current liveness.
- [ ] Enable SigNoz with a valid endpoint/key, send the labeled test event, and verify both it and `macwatch.heartbeat` in SigNoz before building dashboards.
- [ ] Turn off network connectivity, generate a labeled test event, restore connectivity, and confirm the bounded queue drains. Check original event time is retained.
- [ ] Temporarily save an invalid ingestion key and send a test event. Confirm an actionable permanent authentication failure and dropped count, while local monitoring continues. Restore the correct key locally; never put it in test artifacts.
- [ ] Quit MacWatch for longer than the configured 10-minute missing-data period and validate the **Monitoring unavailable** alert. Remember this can also indicate normal sleep, shutdown, connectivity loss, or app exit.
- [ ] Use **Export JSON…** and inspect the local export. Then use **Clear history** and confirm local history is cleared. Keychain credentials must never appear in the export.
