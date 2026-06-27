import SwiftUI

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
