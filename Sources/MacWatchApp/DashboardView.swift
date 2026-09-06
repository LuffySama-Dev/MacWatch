import AppKit
import MacWatchCore
import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var model: AppModel
    @State private var tab = 0
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Label("MacWatch", systemImage: "eye.trianglebadge.exclamationmark").font(.headline)
                Spacer()
                Circle().fill(Color.green).frame(width: 8, height: 8).accessibilityLabel("App running")
                Text("Monitoring").font(.caption)
            }.padding()
            Divider()
            Picker("Section", selection: $tab) {
                Text("Overview").tag(0); Text("Events").tag(1); Text("Cloud").tag(2); Text("Privacy").tag(3)
            }.pickerStyle(.segmented).padding()
            Group {
                switch tab {
                case 0: overview
                case 1: events
                case 2: cloud
                default: privacy
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            HStack { Text("No events detected by enabled monitors is not a guarantee that this Mac is safe.").font(.caption).foregroundStyle(.secondary); Spacer(); Button("Quit") { NSApplication.shared.terminate(nil) } }.padding(10)
        }.frame(width: 600, height: 650)
    }

    private var overview: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                Text("Actual coverage").font(.title3).bold()
                ForEach(model.monitors) { monitor in
                    HStack(alignment: .top) {
                        Image(systemName: icon(monitor.state)).foregroundStyle(color(monitor.state)).frame(width: 22)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack { Text(monitor.name).bold(); Text(monitor.state.rawValue.capitalized).font(.caption).padding(.horizontal, 6).background(.quaternary).clipShape(Capsule()) }
                            Text(monitor.coverage).font(.callout)
                            Text(monitor.detail).font(.caption).foregroundStyle(.secondary)
                        }
                    }.accessibilityElement(children: .combine)
                }
                // SSH login protection controls are hidden until the app can
                // be signed with Apple's restricted Endpoint Security entitlement.
                Divider()
                Text("Active SSH sessions").font(.title3).bold()
                if model.activeSSHSessions.isEmpty {
                    Text("None observed").foregroundStyle(.secondary)
                } else {
                    ForEach(model.activeSSHSessions) { session in
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(session.accountName) from \(session.sourceAddress)").bold()
                            Text("\(session.terminal) · started \(session.startedAt?.formatted() ?? "at an unknown time")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Divider()
                Text("Network-reachable listening endpoints").font(.title3).bold()
                LabeledContent("Current total", value: "\(model.listeningEndpoints.count)")
                LabeledContent("Network-reachable", value: "\(networkReachableEndpoints.count)")
                if networkReachableEndpoints.isEmpty {
                    Text("None observed").foregroundStyle(.secondary)
                } else {
                    ForEach(Array(networkReachableEndpoints.prefix(12))) { endpoint in
                        HStack {
                            Text("\(endpoint.transport.rawValue.uppercased()) \(endpoint.localAddress):\(endpoint.localPort)")
                                .font(.system(.callout, design: .monospaced))
                            Spacer()
                            Text(endpoint.processName).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if networkReachableEndpoints.count > 12 {
                        Text("Showing 12 of \(networkReachableEndpoints.count); changes remain available in Events.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Divider()
                Text("Monitoring health").font(.title3).bold()
                LabeledContent("Local app", value: "Running")
                LabeledContent("SigNoz export", value: model.cloudEnabled ? "Enabled" : "Disabled")
                LabeledContent("Queued telemetry", value: "\(model.exportStatus.queued)")
                LabeledContent("Dropped telemetry", value: "\(model.exportStatus.dropped)")
                LabeledContent("Last successful export", value: model.exportStatus.lastSuccess?.formatted() ?? "Never")
                if let error = model.exportStatus.lastError { Text(error).foregroundStyle(.orange).font(.caption) }
            }.padding()
        }
    }

    private var events: some View {
        VStack {
            HStack {
                TextField("Filter event text", text: $model.searchText).textFieldStyle(.roundedBorder)
                Menu("Kinds") {
                    ForEach(EventKind.allCases, id: \.self) { kind in
                        Toggle(kind.rawValue, isOn: Binding(get: { model.selectedKinds.contains(kind) }, set: { on in
                            if on { model.selectedKinds.insert(kind) } else { model.selectedKinds.remove(kind) }
                        }))
                    }
                }
            }.padding(.horizontal)
            List(model.filteredEvents) { event in
                VStack(alignment: .leading, spacing: 4) {
                    HStack { Text(event.isTest ? "TEST" : event.severity.rawValue.uppercased()).font(.caption).bold().foregroundStyle(event.isTest ? .blue : .primary); Text(event.summary).bold(); Spacer(); Text(event.observedAt, style: .time).font(.caption) }
                    Text(event.details).font(.caption).foregroundStyle(.secondary)
                    if let process = event.processAttribution { Text("Responsible process: \(process)").font(.caption) }
                    if let path = event.executablePath { Text("Executable: \(path)").font(.caption).textSelection(.enabled) }
                    if let signature = event.signature { Text("Signature: \(signature.status)").font(.caption) }
                }.padding(.vertical, 3)
            }.overlay { if model.filteredEvents.isEmpty { ContentUnavailableView("No matching events", systemImage: "checkmark.circle", description: Text("No events detected by enabled monitors.")) } }
            HStack { Button("Export JSON…") { model.exportHistory() }; Button("Clear history", role: .destructive) { model.clearHistory() }; Spacer() }.padding()
        }
    }

    private var cloud: some View {
        Form {
            Toggle("Enable SigNoz Cloud export", isOn: $model.cloudEnabled)
                .onChange(of: model.cloudEnabled) { _, enabled in
                    if !enabled { Task { await model.setCloudEnabled(false) } }
                }
            TextField("HTTPS OTLP base endpoint", text: $model.endpointText).textFieldStyle(.roundedBorder)
            SecureField("Ingestion key (leave blank to keep existing)", text: $ingestionKey).textFieldStyle(.roundedBorder)
            HStack { Button("Save locally") { Task { await model.saveTelemetry(key: ingestionKey); ingestionKey = "" } }; Button("Send clearly labeled test event") { model.sendTestEvent() }.disabled(!model.cloudEnabled) }
            Text(model.settingsMessage).font(.caption).foregroundStyle(.secondary)
            GroupBox("Representative metadata sent") { ScrollView { Text(TelemetryEncoder.representativePreview()).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
            Toggle("Mute local notifications", isOn: Binding(get: { model.notificationsMuted }, set: model.setMuted))
            Button("Request notification permission") { Task { await model.requestNotifications() } }
            LabeledContent("Local event retention") { Stepper("\(model.retentionDays) days", value: $model.retentionDays, in: 1...365) }
            Picker("Export attempt cadence", selection: $model.exportInterval) {
                Text("15 seconds").tag(15.0); Text("30 seconds").tag(30.0); Text("60 seconds").tag(60.0); Text("2 minutes").tag(120.0)
            }
            Button("Save retention and cadence") { model.applyLocalSettings() }
            Text("Export failures do not stop local monitoring. Credentials are never included in logs, local JSON exports, or payload previews.").font(.caption)
        }.formStyle(.grouped).padding(.horizontal)
    }
    @State private var ingestionKey = ""

    private var networkReachableEndpoints: [ListeningEndpoint] {
        model.listeningEndpoints.filter { $0.exposure != .loopbackOnly }
    }

    private var privacy: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Review privacy and remote access").font(.title3).bold()
                Text("MacWatch cannot enumerate other apps’ privacy grants. Review them yourself in System Settings → Privacy & Security → Camera, Microphone, Screen & System Audio Recording, and Accessibility.")
                HStack { settingsButton("Camera", anchor: "Privacy_Camera"); settingsButton("Microphone", anchor: "Privacy_Microphone"); settingsButton("Screen Recording", anchor: "Privacy_ScreenCapture") }
                Text("For remote access, review System Settings → General → Sharing (Screen Sharing, Remote Management, Remote Login), and inspect any remote-access apps you installed. MacWatch inventories terminal-backed SSH sessions, but other remote-control products and SSH sessions without a terminal still require separate evidence.")
                settingsButton("Open Sharing settings", pane: "com.apple.Sharing-Settings.extension", anchor: nil)
                Divider()
                Text("Security limits").font(.headline)
                Text("This app cannot guarantee detection of every screenshot or screen recording, prove the computer is uncompromised, or make local logs tamper-proof. A privileged attacker could stop or alter MacWatch, steal its ingestion credential, suppress telemetry, or fabricate future events. Cloud storage independently preserves events already delivered, but does not make the Mac trustworthy.")
            }.padding()
        }
    }
    private func settingsButton(_ title: String, pane: String = "com.apple.preference.security", anchor: String?) -> some View {
        Button(title) {
            let suffix = anchor.map { "?\($0)" } ?? ""
            if let url = URL(string: "x-apple.systempreferences:\(pane)\(suffix)") { NSWorkspace.shared.open(url) }
        }
    }
    private func icon(_ state: MonitorStatus.State) -> String { switch state { case .active, .periodic: "checkmark.circle.fill"; case .manual: "hand.raised.circle"; case .unavailable: "minus.circle"; case .interrupted: "exclamationmark.triangle" } }
    private func color(_ state: MonitorStatus.State) -> Color { switch state { case .active, .periodic: .green; case .manual: .blue; case .unavailable: .secondary; case .interrupted: .orange } }
}
