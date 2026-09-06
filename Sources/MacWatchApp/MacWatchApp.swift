import SwiftUI

@main
struct MacWatchApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        MenuBarExtra("MacWatch", systemImage: "eye.trianglebadge.exclamationmark") {
            DashboardView().environmentObject(model)
        }
        .menuBarExtraStyle(.window)
    }
}
