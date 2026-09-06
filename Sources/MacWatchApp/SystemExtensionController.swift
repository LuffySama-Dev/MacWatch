import Foundation
import SystemExtensions

final class SystemExtensionController: NSObject, OSSystemExtensionRequestDelegate {
    static let extensionIdentifier = "com.personal.MacWatch.EndpointSecurity"
    var statusHandler: ((String) -> Void)?
    private enum Action { case activate, deactivate }
    private var pendingAction: Action = .activate

    func activate() {
#if LOCAL_UNSIGNED_BUILD
        statusHandler?("SSH protection requires an Apple-approved Endpoint Security entitlement and signed Release build.")
        return
#else
        pendingAction = .activate
        statusHandler?("Requesting macOS approval for SSH login protection…")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
#endif
    }

    func deactivate() {
        pendingAction = .deactivate
        statusHandler?("Requesting removal of SSH login protection…")
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        statusHandler?("Approval is required in System Settings → General → Login Items & Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            statusHandler?(pendingAction == .activate
                ? "SSH login protection is activated. Grant MacWatch Full Disk Access if macOS requests it."
                : "SSH login protection is deactivated.")
        case .willCompleteAfterReboot:
            statusHandler?(pendingAction == .activate
                ? "SSH login protection will activate after this Mac restarts."
                : "SSH login protection will be removed after this Mac restarts.")
        @unknown default:
            statusHandler?("macOS accepted the SSH protection request with an unknown completion state.")
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        statusHandler?("SSH protection could not be activated: \(error.localizedDescription)")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension extensionProperties: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
