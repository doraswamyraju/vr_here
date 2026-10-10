import SwiftUI

struct AdminHrmsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @ObservedObject var hrmsViewModel: HrmsViewModel
    @State private var activeTab: HrmsAdminTab = .timesheets
    
    // Modals
    @State private var showAddNoticeModal = false
    @State private var showAddHolidayModal = false
    
    // Notice Form
    @State private var newNoticeTitle = ""
    @State private var newNoticeMessage = ""
    @State private var newNoticePriority = "High"
    
    // Holiday Form
    @State private var newHolidayTitle = ""
    @State private var newHolidayDate = Date()
    @State private var newHolidayDesc = ""
    
    // Leave approval prompt
    @State private var selectedLeaveForAction: LeaveResponse? = nil
    @State private var leaveAdminNotes = ""
    @State private var showLeaveActionDialog = false
    @State private var leaveTargetStatus = "Approved"

    enum HrmsAdminTab: String, CaseIterable {
        case timesheets = "Staff & Shifts"
        case live = "Live Tracker"
        case approvals = "Leave Approvals"
        case bulletin = "Notice Board"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("HUMAN RESOURCE MANAGEMENT • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("HRMS Enterprise Portal")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        Button(action: { refreshCurrentTab() }) {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.clockwise")
                                Text("Sync")
                            }
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(Color.white.opacity(0.15))
                            .cornerRadius(10)
                        }
                    }
                    
                    Text("Manage employee directories, live geolocation punches, leave queues, and company bulletin broadcasts.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 35/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Navigation Tabs Switcher
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(HrmsAdminTab.allCases, id: \.self) { tab in
                            let isSelected = activeTab == tab
                            Button(action: {
                                activeTab = tab
                                refreshCurrentTab()
                            }) {
                                Text(tab.rawValue)
                                    .font(.system(size: 12, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSelected ? Color.indigo : Color.white)
                                    .cornerRadius(12)
                                    .shadow(color: isSelected ? Color.indigo.opacity(0.3) : Color.clear, radius: 4, y: 2)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12)
                                            .stroke(isSelected ? Color.indigo : Color.borderLight, lineWidth: 1)
                                    )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Tab Content
                VStack {
                    switch activeTab {
                    case .timesheets:
                        staffDirectoryView
                    case .live:
                        liveWorkforceTrackerView
                    case .approvals:
                        leaveApprovalsView
                    case .bulletin:
                        bulletinNoticeManagerView
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            refreshCurrentTab()
        }
        .sheet(isPresented: $showAddNoticeModal) {
            addNoticeSheet
        }
        .sheet(isPresented: $showAddHolidayModal) {
            addHolidaySheet
        }
        .sheet(isPresented: $showLeaveActionDialog) {
            leaveActionSheet
        }
    }

    // MARK: - Tab 1: Staff Directory & Shifts
    private var staffDirectoryView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("EMPLOYEE DIRECTORY (\(viewModel.employees.count))")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
            }
            
            if viewModel.employees.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "person.3")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No staff registered")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(viewModel.employees) { emp in
                    HStack(spacing: 12) {
                        ZStack {
                            Circle()
                                .fill(Color.indigo.opacity(0.12))
                                .frame(width: 42, height: 42)
                            Text(String(emp.name.prefix(1)).uppercased())
                                .font(.system(size: 15, weight: .black))
                                .foregroundColor(.indigo)
                        }
                        
                        VStack(alignment: .leading, spacing: 3) {
                            Text(emp.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(emp.email)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        
                        Spacer()
                        
                        Text(emp.role.capitalized)
                            .font(.system(size: 9, weight: .black))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .foregroundColor(.blue)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(6)
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Tab 2: Workforce Live Tracker
    private var liveWorkforceTrackerView: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Live Status KPI Cards
            let clockedCount = hrmsViewModel.liveStatus?.clockedIn.count ?? 0
            let onLeaveCount = hrmsViewModel.liveStatus?.onLeave.count ?? 0
            let offlineCount = hrmsViewModel.liveStatus?.offline.count ?? 0
            
            HStack(spacing: 10) {
                liveMetricCard(title: "Active Working", count: "\(clockedCount)", color: .green)
                liveMetricCard(title: "On Leave", count: "\(onLeaveCount)", color: .indigo)
                liveMetricCard(title: "Offline", count: "\(offlineCount)", color: .gray)
            }
            
            // Clocked In Section
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Circle().fill(Color.green).frame(width: 8, height: 8)
                    Text("CLOCKED IN SESSIONS (\(clockedCount))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textDark)
                }
                
                if let live = hrmsViewModel.liveStatus, !live.clockedIn.isEmpty {
                    ForEach(live.clockedIn) { emp in
                        HStack(spacing: 12) {
                            Circle()
                                .fill(Color.green.opacity(0.2))
                                .frame(width: 36, height: 36)
                                .overlay(
                                    Text(String(emp.name.prefix(1)).uppercased())
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.green)
                                )
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(emp.name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(emp.email)
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            HStack(spacing: 4) {
                                Image(systemName: "clock.fill")
                                    .font(.system(size: 9))
                                Text("Online")
                                    .font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(.green)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(6)
                        }
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(14)
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
                    }
                } else {
                    Text("No active punch sessions at the moment.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.vertical, 10)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
    }

    private func liveMetricCard(title: String, count: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 9, weight: .black))
                .foregroundColor(color)
            Text(count)
                .font(.system(size: 22, weight: .black))
                .foregroundColor(.textDark)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(color.opacity(0.2), lineWidth: 1))
    }

    // MARK: - Tab 3: Leave Approvals Queue
    private var leaveApprovalsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("PENDING & PROCESSED LEAVES (\(hrmsViewModel.adminLeaves.count))")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            if hrmsViewModel.adminLeaves.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "calendar.badge.checkmark")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No leave requests in queue")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(hrmsViewModel.adminLeaves) { leave in
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(leave.employee?.name ?? "Employee")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.textDark)
                                Text("Type: \(leave.type) • \(leave.startDate) to \(leave.endDate)")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Text(leave.status.uppercased())
                                .font(.system(size: 8, weight: .black))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .foregroundColor(leaveStatusColor(leave.status))
                                .background(leaveStatusColor(leave.status).opacity(0.12))
                                .cornerRadius(6)
                        }
                        
                        if !leave.reason.isEmpty {
                            Text("Reason: \(leave.reason)")
                                .font(.system(size: 11))
                                .foregroundColor(.textDark.opacity(0.8))
                        }
                        
                        if leave.status.lowercased() == "pending" {
                            HStack(spacing: 8) {
                                Button(action: {
                                    selectedLeaveForAction = leave
                                    leaveTargetStatus = "Approved"
                                    leaveAdminNotes = "Approved by Admin"
                                    showLeaveActionDialog = true
                                }) {
                                    Text("Approve")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.vertical, 6)
                                        .frame(maxWidth: .infinity)
                                        .background(Color.green)
                                        .cornerRadius(8)
                                }
                                
                                Button(action: {
                                    selectedLeaveForAction = leave
                                    leaveTargetStatus = "Rejected"
                                    leaveAdminNotes = "Rejected due to operational workload"
                                    showLeaveActionDialog = true
                                }) {
                                    Text("Reject")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.vertical, 6)
                                        .frame(maxWidth: .infinity)
                                        .background(Color.red)
                                        .cornerRadius(8)
                                }
                            }
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Tab 4: Bulletin & Notice Board Manager
    private var bulletinNoticeManagerView: some View {
        VStack(alignment: .leading, spacing: 18) {
            // Notices Section
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("COMPANY NOTICES (\(hrmsViewModel.notices.count))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textMuted)
                    Spacer()
                    Button(action: { showAddNoticeModal = true }) {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("New Notice")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.indigo)
                        .cornerRadius(8)
                    }
                }
                
                ForEach(hrmsViewModel.notices) { notice in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(notice.title)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(notice.message)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        Button(action: { hrmsViewModel.deleteNotice(id: notice.idVal) }) {
                            Image(systemName: "trash")
                                .font(.system(size: 11))
                                .foregroundColor(.red.opacity(0.8))
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
            
            // Holidays Section
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("OFFICIAL HOLIDAYS (\(hrmsViewModel.holidays.count))")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textMuted)
                    Spacer()
                    Button(action: { showAddHolidayModal = true }) {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("Add Holiday")
                        }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.green)
                        .cornerRadius(8)
                    }
                }
                
                ForEach(hrmsViewModel.holidays) { hol in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(hol.title)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(hol.date)
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        Button(action: { hrmsViewModel.deleteHoliday(id: hol.idVal) }) {
                            Image(systemName: "trash")
                                .font(.system(size: 11))
                                .foregroundColor(.red.opacity(0.8))
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Modals
    private var addNoticeSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Notice Information")) {
                    TextField("Title", text: $newNoticeTitle)
                    TextField("Message Content", text: $newNoticeMessage)
                    Picker("Priority", selection: $newNoticePriority) {
                        Text("Low").tag("Low")
                        Text("Medium").tag("Medium")
                        Text("High").tag("High")
                        Text("Urgent").tag("Urgent")
                    }
                }
            }
            .navigationTitle("Publish Notice")
            .navigationBarItems(
                leading: Button("Cancel") { showAddNoticeModal = false },
                trailing: Button("Publish") {
                    hrmsViewModel.createNotice(title: newNoticeTitle, message: newNoticeMessage, priority: newNoticePriority.lowercased())
                    newNoticeTitle = ""
                    newNoticeMessage = ""
                    showAddNoticeModal = false
                }
                .font(.headline)
                .disabled(newNoticeTitle.isEmpty || newNoticeMessage.isEmpty)
            )
        }
    }

    private var addHolidaySheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Holiday Information")) {
                    TextField("Holiday Name (e.g. Diwali)", text: $newHolidayTitle)
                    DatePicker("Date", selection: $newHolidayDate, displayedComponents: .date)
                    TextField("Description", text: $newHolidayDesc)
                }
            }
            .navigationTitle("Declare Holiday")
            .navigationBarItems(
                leading: Button("Cancel") { showAddHolidayModal = false },
                trailing: Button("Save") {
                    let formatter = DateFormatter()
                    formatter.dateFormat = "yyyy-MM-dd"
                    let dateStr = formatter.string(from: newHolidayDate)
                    hrmsViewModel.createHoliday(title: newHolidayTitle, date: dateStr, description: newHolidayDesc)
                    newHolidayTitle = ""
                    newHolidayDesc = ""
                    showAddHolidayModal = false
                }
                .font(.headline)
                .disabled(newHolidayTitle.isEmpty)
            )
        }
    }

    private var leaveActionSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Leave Decision")) {
                    Text("Action: \(leaveTargetStatus)")
                        .font(.headline)
                        .foregroundColor(leaveTargetStatus == "Approved" ? .green : .red)
                    TextField("Admin Notes / Remarks", text: $leaveAdminNotes)
                }
            }
            .navigationTitle("Process Leave")
            .navigationBarItems(
                leading: Button("Cancel") { showLeaveActionDialog = false },
                trailing: Button("Confirm") {
                    if let leave = selectedLeaveForAction {
                        hrmsViewModel.approveLeave(leaveId: leave.idVal, status: leaveTargetStatus, adminNotes: leaveAdminNotes)
                    }
                    showLeaveActionDialog = false
                }
                .font(.headline)
            )
        }
    }

    private func refreshCurrentTab() {
        switch activeTab {
        case .timesheets:
            break
        case .live:
            hrmsViewModel.fetchLiveStatus()
        case .approvals:
            hrmsViewModel.fetchAdminLeaves()
        case .bulletin:
            hrmsViewModel.fetchBulletins()
        }
    }

    private func leaveStatusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "approved":
            return .green
        case "pending":
            return .orange
        case "rejected":
            return .red
        default:
            return .gray
        }
    }
}
