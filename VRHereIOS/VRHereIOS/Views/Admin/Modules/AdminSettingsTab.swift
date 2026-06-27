import SwiftUI

struct AdminSettingsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var emailNotifications = true
    @State private var maintenanceMode = false
    @State private var autoAssignFreelancer = true
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Global Portal Settings")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 16) {
                    Toggle("Enable Email Notifications", isOn: $emailNotifications)
                    Toggle("System Maintenance Mode", isOn: $maintenanceMode)
                    Toggle("Auto-Assign Freelancer Rules", isOn: $autoAssignFreelancer)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
