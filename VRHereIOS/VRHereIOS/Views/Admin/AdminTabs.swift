import SwiftUI
import Combine

// Helper style utilities
extension View {
    func glassCardStyle() -> some View {
        self.padding(16)
            .background(Color.white)
            .cornerRadius(16)
            .shadow(color: Color.black.opacity(0.04), radius: 8, x: 0, y: 4)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.black.opacity(0.05), lineWidth: 1)
            )
    }
}

// ==========================================
// 1. ADMIN OVERVIEW / COMMAND TAB
// ==========================================
struct AdminOverviewTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let userName: String
    let onNavigate: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Purple Command Center Card
                VStack(alignment: .leading, spacing: 12) {
                    Text("ADMIN COMMAND CENTER (V1.1.8)")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(Color.cyan)
                        .tracking(1)
                    
                    Text("Operations Studio")
                        .font(.system(size: 26, weight: .black))
                        .foregroundColor(.white)
                    
                    Text("Service delivery, consultation conversion, and execution status in one place.")
                        .font(.system(size: 13))
                        .foregroundColor(Color.white.opacity(0.7))
                        .lineLimit(2)
                    
                    HStack(spacing: 12) {
                        Button(action: { onNavigate("Orders") }) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("ACTIVE PIPELINE")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundColor(.cyan)
                                Text("\(viewModel.orders.filter { $0.status != "Completed" }.count) Projects")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.white)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                            .background(Color.white.opacity(0.1))
                            .cornerRadius(10)
                        }
                        
                        Button(action: { onNavigate("Finance") }) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("TOTAL VALUE")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundColor(.cyan)
                                Text("₹\(Int(viewModel.totalPipelineValue))")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(.white)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                            .background(Color.white.opacity(0.1))
                            .cornerRadius(10)
                        }
                    }
                    .padding(.top, 8)
                }
                .padding(20)
                .background(
                    LinearGradient(gradient: Gradient(colors: [Color(red: 0.1, green: 0.1, blue: 0.3), Color(red: 0.2, green: 0.05, blue: 0.4)]), startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // 2x2 Quick Actions Grid
                VStack(spacing: 12) {
                    HStack(spacing: 12) {
                        QuickActionCard(title: "NEW ORDER", icon: "plus.circle.fill", color: .green) {
                            onNavigate("Orders")
                        }
                        QuickActionCard(title: "ADD TO-DO", icon: "checkmark.circle.fill", color: .orange) {
                            onNavigate("Todo")
                        }
                    }
                    HStack(spacing: 12) {
                        QuickActionCard(title: "FINANCE", icon: "indianrupeesign.circle.fill", color: .purple) {
                            onNavigate("Finance")
                        }
                        QuickActionCard(title: "REFRESH", icon: "arrow.clockwise.circle.fill", color: .gray) {
                            viewModel.syncDashboardData()
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                // Metrics telemetry
                VStack(spacing: 12) {
                    Text("TELEMETRY STATUS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    
                    TelemetryRow(title: "TOTAL ORDERS", value: "\(viewModel.statTotalOrders)", icon: "layers.fill", color: .blue)
                    TelemetryRow(title: "PENDING PROJECTS", value: "\(viewModel.statPending)", icon: "clock.fill", color: .orange)
                    TelemetryRow(title: "COMPLETED DELIVERIES", value: "\(viewModel.statCompleted)", icon: "checkmark.seal.fill", color: .green)
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

struct QuickActionCard: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                    .foregroundColor(color)
                Text(title)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.textDark)
                Spacer()
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(14)
            .shadow(color: Color.black.opacity(0.02), radius: 4)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

struct TelemetryRow: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(color)
                .padding(8)
                .background(color.opacity(0.1))
                .clipShape(Circle())
            
            Text(title)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
            
            Spacer()
            
            Text(value)
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(12)
    }
}

// ==========================================
// 2. ADMIN ORDERS TAB
// ==========================================
struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedOrderId = ""
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("All System Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    TextField("Search client or service...", text: $searchQuery)
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(10)
                        .padding(.horizontal, 20)
                    
                    VStack(spacing: 12) {
                        let filtered = viewModel.orders.filter {
                            searchQuery.isEmpty ||
                            $0.serviceName.localizedCaseInsensitiveContains(searchQuery) ||
                            $0.clientName.localizedCaseInsensitiveContains(searchQuery)
                        }
                        
                        ForEach(filtered) { order in
                            Button(action: { selectedOrderId = order.id }) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(order.serviceName)
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("Client: \(order.clientName) • Price: ₹\(Int(order.price))")
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    Text(order.status)
                                        .font(.system(size: 9, weight: .bold))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(order.status == "Completed" ? Color.green : Color.orange)
                                        .cornerRadius(6)
                                }
                                .glassCardStyle()
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 20)
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Orders")
                            }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.red)
                        }
                        .padding(.top, 16)
                        
                        Text(order.serviceName)
                            .font(.system(size: 20, weight: .black))
                            .foregroundColor(.textDark)
                        
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Assignment & Workflow")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            
                            HStack {
                                Text("Client Name:")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(order.clientName)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                            
                            HStack {
                                Text("Assign Employee:")
                                    .font(.system(size: 12))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(order.assignedEmployee?.name ?? "Unassigned")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.blue)
                            }
                            
                            Menu("Change Assignee") {
                                ForEach(viewModel.employees) { emp in
                                    Button(emp.name) {
                                        let fields: [String: AnyCodable] = ["assignedEmployee": AnyCodable(emp.idVal)]
                                        viewModel.createOrder(fields: fields) { _ in }
                                    }
                                }
                            }
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.red)
                        }
                        .glassCardStyle()
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 3. ADMIN CRM TICKETS TAB
// ==========================================
struct AdminCrmTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Support Ticket CRM Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search tickets...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    // Seed mock CRM cases/leads
                    let leads = [
                        ("GST Issue", "Raju Ventures", "High", "Open"),
                        ("Filing Clarification", "Navya Enterprises", "Medium", "Pending"),
                        ("Incorporation Speedup", "Venkata Corp", "Low", "Resolved"),
                        ("Invoice Query", "Sai Logistics", "High", "Open")
                    ]
                    
                    ForEach(leads, id: \.0) { title, client, priority, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Client: \(client) • Priority: \(priority)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Resolved" ? Color.green : Color.red)
                                .cornerRadius(6)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 4. ADMIN HRMS TAB
// ==========================================
struct AdminHrmsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @StateObject var hrmsViewModel = HrmsViewModel()
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("HRMS Leaves & Announcements")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Staff Leave Applications")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                    
                    if hrmsViewModel.adminLeaves.isEmpty {
                        Text("No pending leave applications.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(hrmsViewModel.adminLeaves) { leave in
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text(leave.employee?.name ?? "Employee")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text(leave.status)
                                        .font(.system(size: 10, weight: .bold))
                                }
                                Text("\(leave.type): \(leave.reason)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                
                                if leave.status == "Pending" {
                                    HStack(spacing: 16) {
                                        Button("Approve") {
                                            hrmsViewModel.approveLeave(leaveId: leave.id, status: "Approved", adminNotes: "Granted")
                                        }
                                        .foregroundColor(.green)
                                        
                                        Button("Reject") {
                                            hrmsViewModel.approveLeave(leaveId: leave.id, status: "Rejected", adminNotes: "Denied")
                                        }
                                        .foregroundColor(.red)
                                    }
                                    .font(.system(size: 11, weight: .bold))
                                }
                            }
                            .glassCardStyle()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .onAppear {
            hrmsViewModel.fetchAdminLeaves()
        }
    }
}

// ==========================================
// 5. ADMIN USERS TAB
// ==========================================
struct AdminUsersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("User Matrix Control")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                ForEach(viewModel.employees) { emp in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(emp.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(emp.email)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        Text(emp.role.capitalized)
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.blue)
                    }
                    .glassCardStyle()
                    .padding(.horizontal, 20)
                }
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 6. ADMIN TODO TAB
// ==========================================
struct AdminTodoTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var newTaskTitle = ""
    @State private var selectedPriority = "Medium"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Tasks Board")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                // Add Todo field
                VStack(spacing: 8) {
                    TextField("Enter task title...", text: $newTaskTitle)
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(10)
                    
                    HStack {
                        Text("Priority:")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                        Picker("Priority", selection: $selectedPriority) {
                            Text("Low").tag("Low")
                            Text("Medium").tag("Medium")
                            Text("High").tag("High")
                        }
                        .pickerStyle(SegmentedPickerStyle())
                        
                        Button("Add Task") {
                            guard !newTaskTitle.isEmpty else { return }
                            let req = CreateTodoRequest(title: newTaskTitle, description: "", priority: selectedPriority.lowercased(), assignedTo: nil, orderId: nil, dueDate: nil)
                            viewModel.createTodo(request: req) { _ in
                                newTaskTitle = ""
                            }
                        }
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.red)
                    }
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                // List Tasks
                VStack(spacing: 12) {
                    ForEach(viewModel.todos) { todo in
                        HStack {
                            Image(systemName: todo.completed ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(todo.completed ? .green : .gray)
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text(todo.title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                    .strikethrough(todo.completed)
                                Text("Priority: \(todo.priority.capitalized)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 7. ADMIN FINANCE TAB
// ==========================================
struct AdminFinanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Finance Ledger")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 8) {
                    Text("Total Operations Pipeline Value")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    Text("₹\(Int(viewModel.totalPipelineValue))")
                        .font(.system(size: 26, weight: .black))
                        .foregroundColor(.green)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                Text("Transactions Status")
                    .font(.system(size: 14, weight: .bold))
                    .padding(.horizontal, 20)
                
                if viewModel.payments.isEmpty {
                    Text("No transactions logged.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                        .padding(.horizontal, 20)
                } else {
                    ForEach(viewModel.payments) { pay in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Order #\(pay.paymentId.prefix(8))")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Mode: \(pay.method) • Status: \(pay.status)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("₹\(Int(pay.amount))")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.green)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 8. ADMIN COMPLIANCE TAB
// ==========================================
struct AdminComplianceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var activeCategory = "All"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Compliance Panel")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(["All", "GST", "MCA", "ESI", "TDS"], id: \.self) { cat in
                            Button(action: { activeCategory = cat }) {
                                Text(cat)
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(activeCategory == cat ? .white : .textMuted)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .background(activeCategory == cat ? Color.red : Color.white)
                                    .cornerRadius(20)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                VStack(spacing: 12) {
                    let items = [
                        ("GSTR-1 Return Filing", "GST", "2026-06-11", "Pending"),
                        ("SPICe+ Director DIN KYC", "MCA", "2026-05-31", "Filed"),
                        ("ESI Return Filing", "ESI", "2026-06-15", "Late"),
                        ("TDS Q4 Return", "TDS", "2026-05-24", "Missed")
                    ].filter { activeCategory == "All" || $0.1 == activeCategory }
                    
                    ForEach(items, id: \.0) { title, cat, date, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(title)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Category: \(cat) • Due: \(date)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Filed" ? Color.green : Color.red)
                                .cornerRadius(6)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 9. ADMIN PERFORMANCE TAB
// ==========================================
struct AdminPerformanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Performance Metrics")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    ForEach(viewModel.employees) { emp in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(emp.name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Assigned Tasks: \(Int.random(in: 2...8))")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 4) {
                                Text("95% SLA")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.green)
                            }
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 10. ADMIN REPORTS TAB
// ==========================================
struct AdminReportsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Business Reports")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Conversion Rate")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    Text("68.4%")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.blue)
                    
                    ProgressView(value: 0.68)
                        .tint(.blue)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("Monthly Goal Growth")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    Text("₹1,25,000 / ₹2,00,000")
                        .font(.system(size: 16, weight: .black))
                        .foregroundColor(.green)
                    
                    ProgressView(value: 0.62)
                        .tint(.green)
                }
                .glassCardStyle()
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 11. ADMIN NOTIFICATIONS TAB
// ==========================================
struct AdminNotificationsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("System Notifications")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    if viewModel.notifications.isEmpty {
                        Text("No notifications logged.")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.horizontal, 20)
                    } else {
                        ForEach(viewModel.notifications) { item in
                            HStack {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(item.title)
                                        .font(.system(size: 13, weight: .bold))
                                        .foregroundColor(item.isRead ? .textMuted : .textDark)
                                    Text(item.message)
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                if !item.isRead {
                                    Button("Mark Read") {
                                        viewModel.markNotificationAsRead(id: item.id)
                                    }
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.blue)
                                }
                            }
                            .glassCardStyle()
                            .padding(.horizontal, 20)
                        }
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 12. ADMIN KB (KNOWLEDGE BASE) TAB
// ==========================================
struct AdminKbTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("KB Hub & Documents")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let articles = [
                        ("Private Ltd Incorporation Checklist", "Step-by-step company registration verification"),
                        ("GST Registration Mandatory Docs", "State-wise document proof requirements"),
                        ("Trademark Class Finder Guideline", "Classes lookup and search tools description"),
                        ("ITR-3 Filing Instructions", "Income tax schedule for business partners")
                    ]
                    
                    ForEach(articles, id: \.0) { title, desc in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(title)
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(desc)
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 13. ADMIN SUPPORT TAB
// ==========================================
struct AdminSupportTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Client Support Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let chats = [
                        ("Manojh K.", "Where is my DIN certificate copy?", "Active"),
                        ("Vinitha S.", "Can I change my registered email?", "Waiting"),
                        ("Dora Raju", "Payment failed for IEC filing", "Resolved")
                    ]
                    
                    ForEach(chats, id: \.0) { client, msg, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(client)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(msg)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Resolved" ? Color.green : Color.blue)
                                .cornerRadius(6)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 14. ADMIN SERVICES TAB
// ==========================================
struct AdminServicesTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Services Master Catalog")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let catalogs = [
                        ("Pvt Ltd Registration", "₹5,499"),
                        ("GST Registration", "₹2,569"),
                        ("Partnership Firm", "₹4,899"),
                        ("Income Tax Return", "₹1,499")
                    ]
                    
                    ForEach(catalogs, id: \.0) { name, price in
                        HStack {
                            Text(name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                            Text(price)
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.red)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 15. ADMIN REFERRAL TAB
// ==========================================
struct AdminReferralTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Referral Commission Ledger")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let referrals = [
                        ("Pranav Kumar", "Referred 3 clients", "₹3,500 Paid"),
                        ("Nisha Reddy", "Referred 1 client", "₹1,000 Pending"),
                        ("Kiran Dev", "Referred 5 clients", "₹6,000 Paid")
                    ]
                    
                    ForEach(referrals, id: \.0) { partner, desc, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(partner)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(desc)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(status.contains("Paid") ? .green : .orange)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 16. ADMIN RECURRING TAB
// ==========================================
struct AdminRecurringTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Recurring Subscriptions")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                VStack(spacing: 12) {
                    let plans = [
                        ("Monthly Retainer Compliance", "₹15,000/mo", "4 Active Clients"),
                        ("Quarterly TDS Filing Pack", "₹6,500/quarter", "11 Active Clients"),
                        ("Yearly Business Compliance Suite", "₹45,000/year", "8 Active Clients")
                    ]
                    
                    ForEach(plans, id: \.0) { name, rate, stats in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Text(rate)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.blue)
                            }
                            Text(stats)
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 17. ADMIN SETTINGS TAB
// ==========================================
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

// ==========================================
// 18. ADMIN IT CHECKLIST TAB
// ==========================================
struct AdminITChecklistTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    @State private var selectedStatus = "Pending"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Income Tax Checklist Submissions")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search by client name or PAN...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    // Seed mock assessments matching Web IncomeTaxAssessmentModule
                    let assessments = [
                        ("Kalyan Chakravarthy", "ABCDE1234F", "2025-26", "2026-27", "Approved"),
                        ("Dora Raju Corp", "XYZAB5678C", "2025-26", "2026-27", "Pending"),
                        ("Chandra & Co", "QWERP9876D", "2024-25", "2025-26", "In Progress"),
                        ("Suneetha Ram", "LKJHG4321A", "2025-26", "2026-27", "Rejected")
                    ].filter {
                        searchQuery.isEmpty ||
                        $0.0.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.1.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    ForEach(assessments, id: \.0) { name, pan, fy, ay, status in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Spacer()
                                Text(status)
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(status == "Approved" ? Color.green : (status == "Rejected" ? Color.red : Color.orange))
                                    .cornerRadius(6)
                            }
                            
                            HStack {
                                Text("PAN: \(pan)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text("FY \(fy) / AY \(ay)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 19. ADMIN FREELANCERS TAB
// ==========================================
struct AdminFreelancersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var searchQuery = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Freelancer Hub Management")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                TextField("Search freelancers...", text: $searchQuery)
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(10)
                    .padding(.horizontal, 20)
                
                VStack(spacing: 12) {
                    // Seed mock freelancers matching Web FreelancersModule
                    let specialists = [
                        ("Rajesh Kumar", "rajesh.ca@gmail.com", "Accounting", "Active"),
                        ("Lakshmi Prasad", "lakshmi.cs@outlook.com", "Legal Compliance", "Pending Approval"),
                        ("Sai Teja", "saiteja.tax@gmail.com", "GST Filing", "Active"),
                        ("Priya Vardhan", "priya.v@gmail.com", "ITR Reviewer", "Suspended")
                    ].filter {
                        searchQuery.isEmpty ||
                        $0.0.localizedCaseInsensitiveContains(searchQuery) ||
                        $0.2.localizedCaseInsensitiveContains(searchQuery)
                    }
                    
                    ForEach(specialists, id: \.0) { name, email, domain, status in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Domain: \(domain) • \(email)")
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text(status)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundColor(.white)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(status == "Active" ? Color.green : (status == "Suspended" ? Color.red : Color.orange))
                                .cornerRadius(6)
                        }
                        .glassCardStyle()
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
    }
}
