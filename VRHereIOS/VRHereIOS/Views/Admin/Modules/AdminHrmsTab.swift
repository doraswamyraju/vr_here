import SwiftUI

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
