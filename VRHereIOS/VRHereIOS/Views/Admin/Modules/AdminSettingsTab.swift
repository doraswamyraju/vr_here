import SwiftUI

struct AdminSettingsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var isDebugMode = true
    @State private var isMaintenanceMode = false
    @State private var isServerOffline = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("GLOBAL PLATFORM CONTROLS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Global Settings")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Configure server debug outputs, maintenance modes, and portal versions.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 25/255, blue: 25/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Settings switches list
                VStack(alignment: .leading, spacing: 16) {
                    Text("PLATFORM TOGGLES")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    Toggle(isOn: $isDebugMode) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Sandbox Debug Logs")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Enables comprehensive console logs in Xcode debugger.")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                    }
                    
                    Divider().background(Color.borderLight)
                    
                    Toggle(isOn: $isMaintenanceMode) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Maintenance State")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Locks access to portals for normal users during updates.")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                    }
                    
                    Divider().background(Color.borderLight)
                    
                    Toggle(isOn: $isServerOffline) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Simulation Sandbox Offline")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Simulates offline state to test caching and offline features.")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(18)
                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                // System Info panel
                VStack(alignment: .leading, spacing: 10) {
                    Text("SYSTEM INFORMATION")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    HStack {
                        Text("App Core Version:")
                            .font(.system(size: 11))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text("1.1.8 (Release)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                    HStack {
                        Text("Target SDK Version:")
                            .font(.system(size: 11))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Text("iOS 16.0 / Swift 5.8")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textDark)
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(18)
                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
