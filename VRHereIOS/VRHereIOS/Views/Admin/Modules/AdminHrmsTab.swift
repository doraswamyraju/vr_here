import SwiftUI

struct AdminHrmsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @ObservedObject var hrmsViewModel: HrmsViewModel
    @State private var filterSelection = "Directory" // "Directory" | "Attendance" | "Leaves"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("HUMAN RESOURCE MANAGEMENT")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("HRMS Portal")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Manage system employees, attendance tracking, and operations staff.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 20/255, green: 40/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Segmented picker
                HStack(spacing: 0) {
                    ForEach(["Directory", "Attendance", "Leaves"], id: \.self) { tab in
                        Button(action: {
                            filterSelection = tab
                            refreshData()
                        }) {
                            Text(tab == "Directory" ? "Staff" : (tab == "Attendance" ? "Live" : "Leaves"))
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(filterSelection == tab ? .white : .textMuted)
                                .frame(maxWidth: .infinity)
                                .frame(height: 36)
                                .background(filterSelection == tab ? Color.primaryRed : Color.clear)
                                .cornerRadius(8)
                        }
                    }
                }
                .padding(4)
                .background(Color.bgInput)
                .cornerRadius(10)
                .padding(.horizontal, 20)
                
                // Content View
                VStack(spacing: 12) {
                    if filterSelection == "Directory" {
                        if viewModel.employees.isEmpty {
                            Text("No employees registered")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 30)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(viewModel.employees) { emp in
                                HStack(spacing: 14) {
                                    ZStack {
                                        Circle()
                                            .fill(Color.primaryRed.opacity(0.1))
                                            .frame(width: 38, height: 38)
                                        Text(String(emp.name.prefix(2)).uppercased())
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.primaryRed)
                                    }
                                    
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
                                        .font(.system(size: 9, weight: .bold))
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
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    } else if filterSelection == "Attendance" {
                        if let status = hrmsViewModel.liveStatus {
                            // Section: Clocked In
                            if !status.clockedIn.isEmpty {
                                attendanceHeader("CLOCKED IN (\(status.clockedIn.count))", color: .green)
                                ForEach(status.clockedIn) { emp in
                                    attendanceRow(name: emp.name, detail: "In at: \(emp.clockInAt?.prefix(16) ?? "") via \(emp.source ?? "web")", statusColor: .green, statusLabel: "ACTIVE")
                                }
                            }
                            
                            // Section: On Leave
                            if !status.onLeave.isEmpty {
                                attendanceHeader("ON LEAVE (\(status.onLeave.count))", color: .orange)
                                ForEach(status.onLeave) { emp in
                                    attendanceRow(name: emp.name, detail: "Leave: \(emp.leaveType ?? "") • \(emp.reason ?? "")", statusColor: .orange, statusLabel: "ON LEAVE")
                                }
                            }
                            
                            // Section: Offline
                            if !status.offline.isEmpty {
                                attendanceHeader("OFFLINE (\(status.offline.count))", color: .gray)
                                ForEach(status.offline) { emp in
                                    attendanceRow(name: emp.name, detail: emp.email, statusColor: .gray, statusLabel: "OFFLINE")
                                }
                            }
                            
                            if status.clockedIn.isEmpty && status.onLeave.isEmpty && status.offline.isEmpty {
                                Text("No attendance records found")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textMuted)
                                    .padding(.vertical, 35)
                                    .frame(maxWidth: .infinity, alignment: .center)
                            }
                        } else {
                            Text("Loading active attendance tracking...")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 35)
                                .frame(maxWidth: .infinity, alignment: .center)
                        }
                    } else {
                        // Leaves Section
                        if hrmsViewModel.adminLeaves.isEmpty {
                            Text("No leave requests found")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 35)
                                .frame(maxWidth: .infinity, alignment: .center)
                        } else {
                            ForEach(hrmsViewModel.adminLeaves) { leave in
                                VStack(alignment: .leading, spacing: 10) {
                                    HStack {
                                        Text(leave.employee?.name ?? "Unknown Employee")
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Spacer()
                                        
                                        Text(leave.status.uppercased())
                                            .font(.system(size: 8, weight: .bold))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .foregroundColor(leaveStatusColor(leave.status))
                                            .background(leaveStatusColor(leave.status).opacity(0.12))
                                            .cornerRadius(6)
                                    }
                                    
                                    Text("Duration: \(String(leave.startDate.prefix(10))) to \(String(leave.endDate.prefix(10)))")
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(.textDark.opacity(0.8))
                                    
                                    Text("Reason: \(leave.reason)")
                                        .font(.system(size: 11))
                                        .foregroundColor(.textMuted)
                                    
                                    if let notes = leave.adminNotes, !notes.isEmpty {
                                        Text("Admin Notes: \(notes)")
                                            .font(.system(size: 11, weight: .medium))
                                            .foregroundColor(.textMuted)
                                            .padding(6)
                                            .background(Color.bgInput)
                                            .cornerRadius(6)
                                    }
                                    
                                    if leave.status.lowercased() == "pending" {
                                        Divider().background(Color.borderLight)
                                        HStack(spacing: 12) {
                                            Button(action: {
                                                hrmsViewModel.approveLeave(leaveId: leave.idVal, status: "approved", adminNotes: "Approved via iOS")
                                            }) {
                                                Text("APPROVE")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.white)
                                                    .frame(maxWidth: .infinity)
                                                    .frame(height: 28)
                                                    .background(Color.green)
                                                    .cornerRadius(6)
                                            }
                                            
                                            Button(action: {
                                                hrmsViewModel.approveLeave(leaveId: leave.idVal, status: "rejected", adminNotes: "Rejected via iOS")
                                            }) {
                                                Text("REJECT")
                                                    .font(.system(size: 10, weight: .bold))
                                                    .foregroundColor(.white)
                                                    .frame(maxWidth: .infinity)
                                                    .frame(height: 28)
                                                    .background(Color.red)
                                                    .cornerRadius(6)
                                            }
                                        }
                                    }
                                }
                                .padding(14)
                                .background(Color.white)
                                .cornerRadius(16)
                                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 16)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                            }
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .onAppear {
            refreshData()
        }
    }
    
    private func refreshData() {
        if filterSelection == "Attendance" {
            hrmsViewModel.fetchLiveStatus()
        } else if filterSelection == "Leaves" {
            hrmsViewModel.fetchAdminLeaves()
        }
    }
    
    private func attendanceHeader(_ text: String, color: Color) -> some View {
        HStack {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(text)
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.textMuted)
                .tracking(0.5)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 8)
    }
    
    private func attendanceRow(name: String, detail: String, statusColor: Color, statusLabel: String) -> some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text(name)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.textDark)
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            }
            Spacer()
            
            Text(statusLabel)
                .font(.system(size: 8, weight: .bold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .foregroundColor(statusColor)
                .background(statusColor.opacity(0.12))
                .cornerRadius(6)
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color.borderLight, lineWidth: 1)
        )
    }
    
    private func leaveStatusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "approved":
            return .green
        case "rejected":
            return .red
        default:
            return .orange
        }
    }
}
