import SwiftUI

// ==========================================
// 1. ADMIN OVERVIEW TAB
// ==========================================
struct AdminOverviewTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let userName: String
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 4) {
                    Text("Admin Dashboard")
                        .font(.system(size: 22, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Manage operations, hrms logs, and payments.")
                        .font(.system(size: 13))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Summary metrics cards
                VStack(spacing: 16) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Active Project Pipeline Value")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Text("₹\(Int(viewModel.totalPipelineValue))")
                            .font(.system(size: 28, weight: .black))
                            .foregroundColor(.primaryRed)
                    }
                    .padding(20)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.primaryRed.opacity(0.1))
                    .cornerRadius(16)
                    
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Total Orders")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.statTotalOrders)")
                                .font(.system(size: 20, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard()
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Active/Pending")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundColor(.textMuted)
                            Text("\(viewModel.statPending)")
                                .font(.system(size: 20, weight: .black))
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
// 2. ADMIN ORDERS MANAGEMENT TAB
// ==========================================
struct AdminOrdersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedOrderId = ""
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if selectedOrderId.isEmpty {
                    Text("All System Orders")
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                        .padding(.horizontal, 20)
                        .padding(.top, 16)
                    
                    VStack(spacing: 12) {
                        ForEach(viewModel.orders) { order in
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
                                        .foregroundColor(.primaryRed)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .background(Color.primaryRed.opacity(0.1))
                                        .cornerRadius(6)
                                }
                                .padding(14)
                                .glassCard()
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(.horizontal, 20)
                } else if let order = viewModel.orders.first(where: { $0.id == selectedOrderId }) {
                    // Order Detailed admin manager
                    VStack(alignment: .leading, spacing: 16) {
                        Button(action: { selectedOrderId = "" }) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.backward")
                                Text("Back to Orders")
                            }
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.primaryRed)
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
                            
                            // Re-assign dropdown trigger menu
                            Menu("Change Assignee") {
                                ForEach(viewModel.employees) { emp in
                                    Button(emp.name) {
                                        // Trigger assign call
                                        let fields: [String: AnyCodable] = ["assignedEmployee": AnyCodable(emp.idVal)]
                                        viewModel.createOrder(fields: fields) { _ in }
                                    }
                                }
                            }
                            .font(.system(size: 12, weight: .bold))
                        }
                        .padding(16)
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
// 3. ADMIN CRM TICKETS TAB
// ==========================================
struct AdminCrmTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Support Ticket CRM Desk")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                
                Text("Support center logs display here.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}

// ==========================================
// 4. ADMIN HRMS MANAGEMENT TAB
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
                
                // Leaves Approval list
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
                            .padding(12)
                            .glassCard()
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
                    .padding(12)
                    .glassCard()
                    .padding(.horizontal, 20)
                }
                Spacer().frame(height: 100)
            }
        }
    }
}
