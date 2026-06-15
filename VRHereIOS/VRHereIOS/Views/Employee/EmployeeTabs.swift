import SwiftUI

// ==========================================
// 1. EMPLOYEE OVERVIEW TAB
// ==========================================
struct EmployeeOverviewTab: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    let userName: String
    let onSelectTab: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Welcome
                VStack(alignment: .leading, spacing: 4) {
                    Text("Welcome, \(userName)")
                        .font(.system(size: 22, weight: .black))
                        .foregroundColor(.textDark)
                    Text("View your assignments and record shifts.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Shift status card
                VStack(alignment: .leading, spacing: 12) {
                    Text("Attendance Quick Actions")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Shift Status")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.textMuted)
                            Text(viewModel.isClockedIn ? "CLOCKED IN" : "OFF-DUTY")
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(viewModel.isClockedIn ? .green : .red)
                        }
                        Spacer()
                        Button(action: { onSelectTab("Attendance") }) {
                            Text(viewModel.isClockedIn ? "Clock Out" : "Clock In")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 16)
                                .padding(.vertical, 8)
                                .background(viewModel.isClockedIn ? Color.red : Color.blue)
                                .cornerRadius(8)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(16)
                    .glassCard()
                }
                .padding(.horizontal, 20)
                
                // Assignments summary grid
                VStack(alignment: .leading, spacing: 12) {
                    Text("Your Assignments")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Active Orders")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.assignedOrders.count)")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Tasks Queue")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.assignedTodos.count)")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 2. EMPLOYEE WORK QUEUE TAB
// ==========================================
struct EmployeeQueueTab: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    @Binding var selectedOrder: OrderResponse?
    
    @State private var showingDocPicker = false
    @State private var inputQueryTitle = ""
    @State private var inputQueryType = "Detail"
    
    @State private var showTimeLogSheet = false
    @State private var logMinutesInput = ""
    @State private var logNotesInput = ""
    @State private var targetTimeLogTaskId = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let order = selectedOrder {
                    // Detailed Processing drilldown
                    Button(action: { selectedOrder = nil }) {
                        HStack(spacing: 6) {
                            Image(systemName: "chevron.backward")
                            Text("Back to Work Queue")
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.blue)
                    }
                    .padding(.top, 16)
                    .padding(.horizontal, 20)
                    
                    VStack(alignment: .leading, spacing: 10) {
                        Text(order.serviceName)
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.textDark)
                        Text("Client: \(order.clientName) (\(order.email))")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.textMuted)
                        
                        Divider().background(Color.borderLight)
                        
                        // Milestone status dropdown analog
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Update Milestone Status")
                                .font(.system(size: 10, weight: .black))
                                .foregroundColor(.textMuted)
                            
                            Menu {
                                Button("Pending Documents") { viewModel.updateOrderStatus(orderId: order.id, status: "Pending Documents") }
                                Button("Documents Verified") { viewModel.updateOrderStatus(orderId: order.id, status: "Documents Verified") }
                                Button("Processing at Portal") { viewModel.updateOrderStatus(orderId: order.id, status: "Processing at Portal") }
                                Button("Waiting for Clarification") { viewModel.updateOrderStatus(orderId: order.id, status: "Waiting for Clarification") }
                                Button("Completed") { viewModel.updateOrderStatus(orderId: order.id, status: "Completed") }
                            } label: {
                                HStack {
                                    Text(order.status)
                                        .font(.system(size: 13, weight: .bold))
                                    Spacer()
                                    Image(systemName: "chevron.down")
                                }
                                .padding(.horizontal, 14)
                                .padding(.vertical, 10)
                                .background(Color.bgInput)
                                .cornerRadius(10)
                            }
                        }
                    }
                    .padding(16)
                    .glassCard()
                    .padding(.horizontal, 20)
                    
                    // Certificate Delivery Action
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("Finish & Deliver Certificate")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.green)
                        }
                        
                        if let url = order.finalCertificateUrl {
                            Text("Delivered URL: \(url)")
                                .font(.system(size: 11))
                                .foregroundColor(.textDark)
                        } else {
                            Button(action: {
                                if !viewModel.isClockedIn {
                                    viewModel.toastMessage = "Please clock in first."
                                    return
                                }
                                showingDocPicker = true
                            }) {
                                HStack {
                                    Image(systemName: "arrow.up.doc")
                                    Text("Upload Final Certificate PDF")
                                }
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 44)
                                .background(Color.green)
                                .cornerRadius(10)
                            }
                        }
                    }
                    .padding(16)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(16)
                    .padding(.horizontal, 20)
                    
                    // Task Workflow Checklist
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Operational Tasks & Subtasks")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        
                        ForEach(order.tasks) { task in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Text(task.title)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(task.status)
                                        .font(.system(size: 9, weight: .black))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 4)
                                        .background(task.status == "Completed" ? Color.green.opacity(0.1) : Color.orange.opacity(0.1))
                                        .foregroundColor(task.status == "Completed" ? .green : .orange)
                                        .cornerRadius(4)
                                    
                                    // Complete trigger
                                    if task.status != "Completed" {
                                        Button(action: {
                                            viewModel.updateTaskStatus(orderId: order.id, taskId: task.id, status: "Completed")
                                        }) {
                                            Image(systemName: "checkmark.circle")
                                                .foregroundColor(.green)
                                        }
                                    }
                                }
                                
                                // Time Logging button
                                Button(action: {
                                    targetTimeLogTaskId = task.id
                                    logMinutesInput = ""
                                    logNotesInput = ""
                                    showTimeLogSheet = true
                                }) {
                                    Text("Log Time Minutes")
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.blue)
                                }
                                
                                // Subtasks list
                                ForEach(task.subtasks) { subtask in
                                    HStack {
                                        Image(systemName: subtask.isCompleted ? "checkmark.square.fill" : "square")
                                            .foregroundColor(subtask.isCompleted ? .green : .textMuted)
                                            .onTapGesture {
                                                viewModel.updateSubtaskStatus(
                                                    orderId: order.id,
                                                    taskId: task.id,
                                                    subtaskId: subtask.id,
                                                    isCompleted: !subtask.isCompleted,
                                                    status: !subtask.isCompleted ? "Completed" : "Pending"
                                                )
                                            }
                                        Text(subtask.title)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                    }
                                    .padding(.leading, 12)
                                }
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                    
                    // Raise new Query Form
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Raise Client Query / Document Requirement")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        
                        CustomInputField(label: "Query Title", placeholder: "E.g. Upload PAN Card clear Scan", iconName: "questionmark.circle", text: $inputQueryTitle)
                        
                        Picker("Type", selection: $inputQueryType) {
                            Text("Text Detail").tag("Detail")
                            Text("Document upload request").tag("Document")
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        
                        Button(action: {
                            if !inputQueryTitle.isEmpty {
                                viewModel.raiseRequirement(orderId: order.id, title: inputQueryTitle, type: inputQueryType)
                                inputQueryTitle = ""
                            }
                        }) {
                            Text("RAISE QUERY")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity)
                                .frame(height: 40)
                                .background(Color.red)
                                .cornerRadius(8)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    .padding(16)
                    .glassCard()
                    .padding(.horizontal, 20)
                    
                } else {
                    // Queue List
                    Text("Work Queue Assignments")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    if viewModel.assignedOrders.isEmpty {
                        Text("No orders assigned to you.")
                            .font(.system(size: 13))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(viewModel.assignedOrders) { order in
                                Button(action: { selectedOrder = order }) {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(order.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Text("Client: \(order.clientName)")
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        Text(order.status)
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.blue)
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 4)
                                            .background(Color.blue.opacity(0.1))
                                            .cornerRadius(6)
                                    }
                                    .padding(14)
                                    .glassCard()
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .sheet(isPresented: $showingDocPicker) {
            // Simple mock file picker sheet to select a document mock representation
            VStack(spacing: 20) {
                Text("Select Document mock PDF")
                    .font(.headline)
                Button("Upload Mock Certificate") {
                    showingDocPicker = false
                    if let order = selectedOrder {
                        let mockData = "PDF_CONTENT".data(using: .utf8)!
                        viewModel.uploadFinalCertificate(orderId: order.id, fileData: mockData, fileName: "signed_incorporation.pdf")
                    }
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(40)
        }
        .sheet(isPresented: $showTimeLogSheet) {
            VStack(spacing: 16) {
                Text("Log Task Operational Time")
                    .font(.headline)
                
                CustomInputField(label: "Minutes Spent", placeholder: "E.g. 30", iconName: "clock", text: $logMinutesInput)
                CustomInputField(label: "Time Log description notes", placeholder: "Completed verification", iconName: "doc.text", text: $logNotesInput)
                
                Button("Submit Time Log") {
                    showTimeLogSheet = false
                    if let min = Int(logMinutesInput), let order = selectedOrder {
                        viewModel.logTaskTime(orderId: order.id, taskId: targetTimeLogTaskId, minutes: min, notes: logNotesInput)
                    }
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            }
            .padding(24)
        }
    }
}

// ==========================================
// 3. EMPLOYEE ATTENDANCE TAB
// ==========================================
struct EmployeeAttendanceTab: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Attendance Shift Manager")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Clock-in Controller card
                VStack(alignment: .leading, spacing: 14) {
                    Text("Log Duty Shift")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    
                    if !viewModel.isClockedIn {
                        CustomInputField(
                            label: "Shift Start Note (optional)",
                            placeholder: "Enter shift details, e.g. Morning team support",
                            iconName: "pencil",
                            text: $viewModel.clockInNote
                        )
                    }
                    
                    Button(action: {
                        viewModel.toggleClockStatus()
                    }) {
                        HStack {
                            Image(systemName: viewModel.isClockedIn ? "stop.fill" : "play.fill")
                            Text(viewModel.isClockedIn ? "CLOCK-OUT NOW" : "CLOCK-IN NOW")
                        }
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                        .background(viewModel.isClockedIn ? Color.red : Color.blue)
                        .cornerRadius(12)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
                
                // Shift logs list
                VStack(alignment: .leading, spacing: 12) {
                    Text("Your Shifts History")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    ForEach(viewModel.attendanceLogs) { log in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(log.dateKey)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("In: \(log.clockInAt) • Out: \(log.clockOutAt ?? "Active")")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("\(log.totalSeconds / 60) mins")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                        }
                        .padding(12)
                        .glassCard()
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 4. EMPLOYEE SUPPORT TAB
// ==========================================
struct EmployeeSupportTab: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Support Communication Logs")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.supportTickets.isEmpty {
                    Text("No customer support tickets registered.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.supportTickets) { ticket in
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text(ticket.subject)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(ticket.status)
                                        .font(.system(size: 9))
                                        .foregroundColor(.blue)
                                }
                                Text(ticket.description)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            .padding(12)
                            .glassCard()
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 5. EMPLOYEE NOTIFICATIONS TAB
// ==========================================
struct EmployeeNotificationsTab: View {
    @ObservedObject var viewModel: EmployeeDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Notifications Feed")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                if viewModel.notifications.isEmpty {
                    Text("No updates recorded.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.notifications) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.title)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text(item.message)
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                            }
                            .padding(12)
                            .glassCard()
                            .overlay(
                                Circle()
                                    .fill(item.isRead ? Color.clear : Color.blue)
                                    .frame(width: 6, height: 6)
                                    .padding(8),
                                alignment: .topTrailing
                            )
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 6. EMPLOYEE SECURITY TAB
// ==========================================
struct EmployeeSecurityTab: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Security Matrix Guidelines")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("1. Document protection protocols.")
                    Text("2. Keep authorization keys confidential.")
                    Text("3. Make sure to close active sessions on shared terminals.")
                }
                .font(.system(size: 12))
                .foregroundColor(.textDark)
                .padding(16)
                .glassCard()
                .padding(.horizontal, 20)
            }
        }
    }
}

// ==========================================
// 7. EMPLOYEE HRMS MODULE
// ==========================================
struct HrmsEmployeeScreen: View {
    @StateObject var hrmsViewModel = HrmsViewModel()
    
    @State private var showingApplySheet = false
    @State private var leaveType = "Sick Leave"
    @State private var leaveReason = ""
    @State private var leaveStart = ""
    @State private var leaveEnd = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("HRMS Staff Portal")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Action: Apply leave
                Button(action: { showingApplySheet = true }) {
                    HStack {
                        Image(systemName: "plus.circle")
                        Text("Apply for Leave")
                    }
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .background(Color.blue)
                    .cornerRadius(10)
                }
                .buttonStyle(ScaleOnPressButtonStyle())
                .padding(.horizontal, 20)
                
                // My Leaves history list
                VStack(alignment: .leading, spacing: 12) {
                    Text("My Leave Applications")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    if hrmsViewModel.leaves.isEmpty {
                        Text("No leave logs found.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(hrmsViewModel.leaves) { leave in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(leave.type)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Text("\(leave.startDate) to \(leave.endDate)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                Text(leave.status)
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(leave.status == "Approved" ? .green : .orange)
                            }
                            .padding(12)
                            .glassCard()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                // Bulletins & Notices & Holidays feed
                VStack(alignment: .leading, spacing: 12) {
                    Text("Bulletins & Announcements")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    ForEach(hrmsViewModel.notices) { notice in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(notice.title)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(notice.message)
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        .padding(12)
                        .glassCard()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .onAppear {
            hrmsViewModel.fetchMyLeaves()
            hrmsViewModel.fetchBulletins()
        }
        .sheet(isPresented: $showingApplySheet) {
            VStack(spacing: 16) {
                Text("Submit Leave Application")
                    .font(.headline)
                
                Picker("Leave Type", selection: $leaveType) {
                    Text("Sick Leave").tag("Sick Leave")
                    Text("Casual Leave").tag("Casual Leave")
                    Text("Maternity/Paternity").tag("Maternity")
                }
                .pickerStyle(SegmentedPickerStyle())
                
                CustomInputField(label: "Start Date (YYYY-MM-DD)", placeholder: "E.g. 2026-06-20", iconName: "calendar", text: $leaveStart)
                CustomInputField(label: "End Date (YYYY-MM-DD)", placeholder: "E.g. 2026-06-22", iconName: "calendar", text: $leaveEnd)
                CustomInputField(label: "Reason", placeholder: "Personal details", iconName: "pencil", text: $leaveReason)
                
                Button("Apply") {
                    showingApplySheet = false
                    hrmsViewModel.applyLeave(startDate: leaveStart, endDate: leaveEnd, type: leaveType, reason: leaveReason)
                    leaveReason = ""
                    leaveStart = ""
                    leaveEnd = ""
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            }
            .padding(24)
        }
    }
}
