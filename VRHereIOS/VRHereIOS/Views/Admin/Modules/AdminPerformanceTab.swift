import SwiftUI

struct AdminPerformanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("OPERATIONAL SPEED & METRICS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Performance Metrics")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Review operational processing speed, assigned task volumes, and execution ratios.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 15/255, green: 30/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Staff Performance Directory list
                VStack(spacing: 12) {
                    if viewModel.employees.isEmpty {
                        Text("No operational metrics available")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 30)
                            .frame(maxWidth: .infinity, alignment: .center)
                    } else {
                        ForEach(viewModel.employees) { emp in
                            // Calculate dynamic statistics
                            let assignedOrders = viewModel.orders.filter { $0.assignedEmployee?.idVal == emp.idVal }
                            let completedCount = assignedOrders.filter { $0.status == "Completed" }.count
                            let pendingCount = assignedOrders.count - completedCount
                            let successRate = assignedOrders.isEmpty ? 100 : Int((Double(completedCount) / Double(assignedOrders.count)) * 100)
                            
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(emp.name)
                                            .font(.system(size: 14, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text(emp.role.capitalized)
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    // Productivity Indicator Badge
                                    Text("\(successRate)% Completion")
                                        .font(.system(size: 9, weight: .bold))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(successRate > 70 ? .green : .orange)
                                        .background((successRate > 70 ? Color.green : Color.orange).opacity(0.12))
                                        .cornerRadius(6)
                                }
                                
                                Divider().background(Color.borderLight)
                                
                                HStack(spacing: 24) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("ASSIGNED PROJECTS")
                                            .font(.system(size: 8, weight: .bold))
                                            .foregroundColor(.textMuted)
                                        Text("\(assignedOrders.count)")
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.textDark)
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("ACTIVE CASES")
                                            .font(.system(size: 8, weight: .bold))
                                            .foregroundColor(.textMuted)
                                        Text("\(pendingCount)")
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.blue)
                                    }
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("FINISHED DELIVERIES")
                                            .font(.system(size: 8, weight: .bold))
                                            .foregroundColor(.textMuted)
                                        Text("\(completedCount)")
                                            .font(.system(size: 13, weight: .bold))
                                            .foregroundColor(.green)
                                    }
                                }
                            }
                            .padding(16)
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
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
}
