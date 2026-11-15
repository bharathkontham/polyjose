// The host app of the hosted AppleKey tests (platforms/swift/HostedTests/project.yml). It shows one
// line and does nothing else; the tests run inside its process.
import SwiftUI

@main
struct PolyjoseHostApp: App {
    var body: some Scene {
        WindowGroup { Text("polyjose hosted tests") }
    }
}
