import SwiftUI

struct PartnerDashboardView: View {
    @ObservedObject var viewModel: PartnerDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    let onDeleteAccount: () -> Void
    
    @State private var activeTab = "Overview"
    @State private var showingToast = false
    @State private var toastMsg = ""
    @State private var isShowingNotifications = false
    
    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                // Top Custom Header
                VRHeader(
                    title: "PARTNER SUITE",
                    showMenu: false,
                    showLogout: true,
                    onLogoutClick: onLogout,
                    showBack: activeTab != "Overview",
                    onBackClick: { withAnimation { activeTab = "Overview" } },
                    showNotifications: true,
                    hasUnreadNotifications: viewModel.notifications.contains(where: { !$0.isRead }),
                    onNotificationsClick: { isShowingNotifications = true }
                )
                
                // Main Tab Layout
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
                    switch activeTab {
                    case "Overview":
                        PartnerOverviewTab(viewModel: viewModel, userName: userName)
                    case "Referrals":
                        PartnerReferralsTab(viewModel: viewModel)
                    case "Earnings":
                        PartnerEarningsTab(viewModel: viewModel)
                    case "Settings":
                        PartnerSettingsTab(viewModel: viewModel, onDeleteAccount: onDeleteAccount)
                    default:
                        Text("Unknown Tab")
                    }
                }
                
                // Dock Navigation
                PartnerFloatingDock(activeTab: $activeTab)
            }
            .refreshable {
                await viewModel.refreshAllDataAsync()
            }
            
            // Global Toast
            if showingToast {
                VStack {
                    Spacer()
                    ToastView(message: toastMsg)
                }
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                        showingToast = false
                    }
                }
                .zIndex(20)
            }
        }
        .onAppear {
            viewModel.refreshAllData()
        }
        .onChange(of: viewModel.toastMessage) { val in
            if let msg = val {
                toastMsg = msg
                showingToast = true
                viewModel.toastMessage = nil
            }
        }
        .sheet(isPresented: $isShowingNotifications) {
            NotificationsSheet(
                notifications: viewModel.notifications,
                onMarkAsRead: { viewModel.markNotificationAsRead(id: $0) },
                onClose: { isShowingNotifications = false }
            )
        }
    }
}

// --- Partner Floating Dock Bar ---
struct PartnerFloatingDock: View {
    @Binding var activeTab: String
    
    let tabs = [
        ("Overview", "chart.bar", "Overview"),
        ("Referrals", "link", "Referrals"),
        ("Earnings", "indianrupeesign", "Earnings"),
        ("Settings", "gearshape", "Settings")
    ]
    
    var body: some View {
        VStack(spacing: 0) {
            Divider().background(Color.borderLight)
            HStack(spacing: 0) {
                ForEach(tabs, id: \.0) { tabId, iconName, label in
                    let isSelected = activeTab == tabId
                    Button(action: { activeTab = tabId }) {
                        VStack(spacing: 4) {
                            Image(systemName: iconName + (isSelected ? ".fill" : ""))
                                .font(.system(size: 18))
                                .foregroundColor(isSelected ? .purple : .textMuted)
                            Text(label)
                                .font(.system(size: 9, weight: isSelected ? .black : .semibold))
                                .foregroundColor(isSelected ? .purple : .textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(.vertical, 6)
            .background(Color.white)
        }
    }
}
