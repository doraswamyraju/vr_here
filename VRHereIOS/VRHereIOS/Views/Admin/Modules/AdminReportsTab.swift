import SwiftUI

struct AdminReportsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header card
                VStack(alignment: .leading, spacing: 8) {
                    Text("CORPORATE INTELLIGENCE & ACQUISITIONS")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(.cyan)
                        .tracking(1)
                    Text("Business Reports")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                    Text("Analyze order volumes, pipeline valuations, and conversion metrics.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.7))
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 40/255, green: 20/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(20)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Analytics statistics overview
                VStack(alignment: .leading, spacing: 16) {
                    Text("CONVERSION INSIGHTS")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    let averageValue = viewModel.orders.isEmpty ? 0.0 : (viewModel.totalPipelineValue / Double(viewModel.orders.count))
                    
                    VStack(spacing: 12) {
                        metricReportRow(title: "Total Pipeline Value", value: "₹\(Int(viewModel.totalPipelineValue))", icon: "indianrupeesign.circle", color: .purple)
                        metricReportRow(title: "Average Deal Size", value: "₹\(Int(averageValue))", icon: "tag", color: .blue)
                        metricReportRow(title: "Registered Accounts", value: "\(viewModel.employees.count) users", icon: "person.2", color: .green)
                        metricReportRow(title: "Active Projects Ratio", value: "\(Int(Double(viewModel.statPending) / Double(max(1, viewModel.statTotalOrders)) * 100))%", icon: "arrow.triangle.2.circlepath", color: .orange)
                    }
                }
                .padding(18)
                .background(Color.white)
                .cornerRadius(18)
                .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                .overlay(
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
    
    private func metricReportRow(title: String, value: String, icon: String, color: Color) -> some View {
        HStack {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundColor(color)
                .frame(width: 24)
            Text(title)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.textDark)
            Spacer()
            Text(value)
                .font(.system(size: 13, weight: .black))
                .foregroundColor(.textDark)
        }
    }
}
