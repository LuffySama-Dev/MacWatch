# Future Endpoint Security signing and distribution

This integration is currently disabled. Its source remains in the project, but the extension is not embedded in `MacWatch.app`, the activation UI is hidden, and the app does not poll its event store. The following requirements apply only if the feature is re-enabled later.

## Developer prerequisites

1. Join the Apple Developer Program and create signing identities for macOS development and distribution.
2. Register App IDs for `com.personal.MacWatch` and `com.personal.MacWatch.EndpointSecurity` under the same team.
3. Request Apple's `com.apple.developer.endpoint-security.client` entitlement for the extension: <https://developer.apple.com/contact/request/system-extension/>.
4. After approval, create or refresh provisioning profiles containing the System Extension entitlement for the app and Endpoint Security entitlement for the extension.
5. In Xcode, select the same team for the **MacWatch** and **MacWatchEndpointSecurity** targets. Keep their bundle identifiers synchronized with the registered App IDs.
6. Archive, sign, notarize, and distribute the containing MacWatch app. The app must be placed in `/Applications` before normal system-extension activation.

The current MacWatch target intentionally has no dependency on or embed phase for the extension. After Apple grants the entitlement, restore the target dependency, embed phase, host and extension entitlements, SystemExtensions framework linkage, activation controller, UI, and authentication-store polling. Then use appropriately signed development and release configurations for testing and distribution. Apple rejects `es_new_client` when the signed extension lacks the granted Endpoint Security entitlement.

## Intended future user flow

1. Install MacWatch in Applications and open it.
2. Under **SSH login protection**, press **Enable**.
3. Approve MacWatch in **System Settings → General → Login Items & Extensions** when requested.
4. Grant MacWatch Full Disk Access when requested. MacWatch reports the extension unhealthy until its heartbeat is available.
5. Press **Disable** before uninstalling if explicit deactivation is desired. Deleting MacWatch also removes its embedded system extension.

The extension subscribes only to `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN` and `ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT`. Its root-owned local store is capped at 1,024 records; account names and source addresses are omitted from SigNoz telemetry.
