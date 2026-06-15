import SwiftUI
import Combine

struct EmployeeDashboardView: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    let userName: String
    let onLogout: () -> Void
    
    @State private var activeTab = "Overview"
    @State private var selectedOrderForProcessing: OrderResponse? = nil
    
    @State private var isSidebarOpen = false
    @State private var showingToast = false
    @State private var toastMsg = ""
    
    var body: some View {
        ZStack {
            // Main Scaffold
            VStack(spacing: 0) {
                // Top Custom Header
                VRHeader(
                    title: "EMPLOYEE PANEL",
                    showMenu: true,
                    onMenuClick: { withAnimation { isSidebarOpen.toggle() } },
                    showLogout: true,
                    onLogoutClick: onLogout
                )
                
                // Active Shift Timer Banner
                if viewModel.isClockedIn, let clockInString = viewModel.currentAttendanceRecord?.clockInAt {
                    ShiftTimerBanner(clockInAt: clockInString)
                }
                
                // Main Tab Switcher
                ZStack {
                    Color.bgLight.ignoresSafeArea()
                    
                    switch activeTab {
                    case "Overview":
                        EmployeeOverviewTab(viewModel: viewModel, userName: userName, onSelectTab: { activeTab = $0 })
                    case "Queue":
                        EmployeeQueueTab(
                            viewModel: viewModel,
                            selectedOrder: $selectedOrderForProcessing
                        )
                    case "Attendance":
                        EmployeeAttendanceTab(viewModel: viewModel)
                    case "Support":
                        EmployeeSupportTab(viewModel: viewModel)
                    case "Notifications":
                        EmployeeNotificationsTab(viewModel: viewModel)
                    case "Security":
                        EmployeeSecurityTab()
                    case "HRMS":
                        HrmsEmployeeScreen()
                    default:
                        Text("Unknown Tab")
                    }
                }
                
                // Dock Navigation Bar at Bottom
                EmployeeFloatingDock(activeTab: $activeTab)
            }
            
            // Sidebar Drawer
            if isSidebarOpen {
                ZStack(alignment: .leading) {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture {
                            withAnimation { isSidebarOpen = false }
                        }
                    
                    EmployeeSidebarView(
                        userName: userName,
                        activeTab: $activeTab,
                        onLogout: onLogout,
                        onClose: {
                            withAnimation { isSidebarOpen = false }
                        }
                    )
                    .transition(.move(edge: .leading))
                }
            }
            
            // Global Toast layer
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
            viewModel.syncDashboardData()
        }
        .onChange(of: viewModel.toastMessage) { val in
            if let msg = val {
                toastMsg = msg
                showingToast = true
                viewModel.toastMessage = nil
            }
        }
    }
}

// --- Active Shift Timer banner ---
struct ShiftTimerBanner: View {
    let clockInAt: String
    
    @State private var elapsedSeconds = 0.0
    let timer = Timer.publish(every: 1.0, on: .main, in: .common).autoconnect()
    
    private var timeInterval: TimeInterval {
        // Date Parsing
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: clockInAt) {
            return Date().timeIntervalSince(date)
        }
        return 0.0
    }
    
    var body: some View {
        HStack {
            HStack(spacing: 6) {
                Circle()
                    .fill(Color.green)
                    .frame(width: 8, height: 8)
                Text("Active Shift Session:")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textMuted)
            }
            
            Spacer()
            
            Text(formattedDuration)
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.blue)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.bgInput)
        .onReceive(timer) { _ in
            elapsedSeconds = timeInterval
        }
        .onAppear {
            elapsedSeconds = timeInterval
        }
    }
    
    private var formattedDuration: String {
        let seconds = Int(elapsedSeconds)
        let h = seconds / 3600
        let m = (seconds % 3600) / 60
        let s = seconds % 60
        return String(format: "%02d:%02d:%02d", h, m, s)
    }
}

// --- Employee Floating Bottom Dock ---
struct EmployeeFloatingDock: View {
    @Binding var activeTab: String
    
    let tabs = [
        ("Overview", "square.grid.2x2", "Me"),
        ("Queue", "briefcase", "Queue"),
        ("Attendance", "clock", "Attendance"),
        ("HRMS", "person.3", "HRMS")
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
                                .foregroundColor(isSelected ? .blue : .textMuted)
                            Text(label)
                                .font(.system(size: 9, weight: isSelected ? .black : .semibold))
                                .foregroundColor(isSelected ? .white : .textMuted)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(.vertical, 6)
            .background(Color.darkSlate)
        }
    }
}

// --- Employee Sidebar Navigation View ---
struct EmployeeSidebarView: View {
    let userName: String
    @Binding var activeTab: String
    let onLogout: () -> Void
    let onClose: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            VStack(alignment: .leading, spacing: 4) {
                Text("VR Here BMS")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.white)
                Text(userName)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.white.opacity(0.8))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(LinearGradient(gradient: Gradient(colors: [.blue, .purple]), startPoint: .topLeading, endPoint: .bottomTrailing))
            
            // Menu
            ScrollView {
                VStack(spacing: 4) {
                    EmployeeSidebarItem(label: "My Overview", iconName: "house", tabId: "Overview", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "Work Queue", iconName: "briefcase", tabId: "Queue", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "Attendance Clock", iconName: "clock", tabId: "Attendance", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "Support Tickets", iconName: "headphones", tabId: "Support", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "Notifications Feed", iconName: "bell", tabId: "Notifications", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "Security Matrix", iconName: "shield", tabId: "Security", activeTab: $activeTab, onClose: onClose)
                    EmployeeSidebarItem(label: "HRMS Portal", iconName: "person.3", tabId: "HRMS", activeTab: $activeTab, onClose: onClose)
                    
                    Divider()
                        .background(Color.borderLight)
                        .padding(.vertical, 12)
                    
                    Button(action: {
                        onClose()
                        onLogout()
                    }) {
                        HStack(spacing: 12) {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                                .foregroundColor(.red)
                            Text("Sign Out")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.red)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 12)
                    }
                }
                .padding(8)
            }
            Spacer()
        }
        .frame(width: 270)
        .background(Color.white)
        .edgesIgnoringSafeArea(.bottom)
    }
}

struct EmployeeSidebarItem: View {
    let label: String
    let iconName: String
    let tabId: String
    @Binding var activeTab: String
    let onClose: () -> Void
    
    var body: some View {
        let isSelected = activeTab == tabId
        Button(action: {
            activeTab = tabId
            onClose()
        }) {
            HStack(spacing: 12) {
                Image(systemName: iconName)
                    .foregroundColor(isSelected ? .white : .textMuted)
                Text(label)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(isSelected ? .white : .textDark)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(isSelected ? Color.blue : Color.clear)
            .cornerRadius(10)
        }
        .buttonStyle(PlainButtonStyle())
    }
}
