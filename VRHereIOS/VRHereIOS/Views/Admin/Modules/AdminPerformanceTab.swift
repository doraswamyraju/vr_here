import SwiftUI

struct AdminPerformanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedEmployeeId: String = ""
    @State private var selectedTimeframe: String = "30 Days"

    var selectedEmployee: EmployeeResponse? {
        viewModel.employees.first(where: { $0.idVal == selectedEmployeeId })
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Banner
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("WORKFORCE PRODUCTIVITY & SLA • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Performance Analytics")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Audit specialist turnaround times, SLA adherence, individual employee project completion ratios, and capacity load.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 15/255, green: 30/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Employee Selector Bar
                VStack(alignment: .leading, spacing: 6) {
                    Text("SELECT SPECIALIST")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(.textMuted)
                    
                    Menu {
                        Button("All Team Specialists") { selectedEmployeeId = "" }
                        ForEach(viewModel.employees) { emp in
                            Button(emp.name) { selectedEmployeeId = emp.idVal }
                        }
                    } label: {
                        HStack {
                            let title = selectedEmployee?.name ?? "All Team Specialists"
                            Text(title)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Spacer()
                            Image(systemName: "chevron.up.chevron.down")
                                .foregroundColor(.textMuted)
                        }
                        .padding(12)
                        .background(Color.white)
                        .cornerRadius(12)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                .padding(.horizontal, 20)
                
                // Summary KPI Cards
                performanceKPICards
                
                // Team Leaderboard List
                VStack(alignment: .leading, spacing: 12) {
                    Text("EMPLOYEE LEADERBOARD & CAPACITY")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textMuted)
                    
                    let targetEmployees = selectedEmployeeId.isEmpty ? viewModel.employees : viewModel.employees.filter { $0.idVal == selectedEmployeeId }
                    
                    if targetEmployees.isEmpty {
                        Text("No employees registered")
                            .font(.system(size: 12))
                            .foregroundColor(.textMuted)
                            .padding(.vertical, 20)
                    } else {
                        ForEach(targetEmployees) { emp in
                            let assignedOrders = viewModel.orders.filter { $0.assignedEmployee?.idVal == emp.idVal }
                            let completed = assignedOrders.filter { $0.status == "Completed" }.count
                            let pending = assignedOrders.count - completed
                            let completionRate = assignedOrders.isEmpty ? 100 : Int((Double(completed) / Double(assignedOrders.count)) * 100)
                            
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Circle()
                                        .fill(Color.blue.opacity(0.12))
                                        .frame(width: 40, height: 40)
                                        .overlay(
                                            Text(String(emp.name.prefix(1)).uppercased())
                                                .font(.system(size: 14, weight: .black))
                                                .foregroundColor(.blue)
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
                                    
                                    Text("\(completionRate)% SLA")
                                        .font(.system(size: 9, weight: .black))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 4)
                                        .foregroundColor(completionRate >= 75 ? .green : .orange)
                                        .background((completionRate >= 75 ? Color.green : Color.orange).opacity(0.12))
                                        .cornerRadius(6)
                                }
                                
                                // Progress Bar
                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        RoundedRectangle(cornerRadius: 6)
                                            .fill(Color(red: 241/255, green: 245/255, blue: 249/255))
                                            .frame(height: 8)
                                        
                                        RoundedRectangle(cornerRadius: 6)
                                            .fill(completionRate >= 75 ? Color.green : Color.orange)
                                            .frame(width: max(8, geo.size.width * CGFloat(completionRate) / 100), height: 8)
                                    }
                                }
                                .frame(height: 8)
                                
                                Divider().background(Color.borderLight)
                                
                                HStack {
                                    metricColumn(title: "TOTAL CASES", value: "\(assignedOrders.count)", color: .textDark)
                                    Spacer()
                                    metricColumn(title: "ACTIVE PIPELINE", value: "\(pending)", color: .blue)
                                    Spacer()
                                    metricColumn(title: "CLOSED DELIVERIES", value: "\(completed)", color: .green)
                                }
                            }
                            .padding(14)
                            .background(Color.white)
                            .cornerRadius(16)
                            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }

    private var performanceKPICards: some View {
        let totalAssigned = viewModel.orders.filter { $0.assignedEmployee != nil }.count
        let totalCompleted = viewModel.orders.filter { $0.assignedEmployee != nil && $0.status == "Completed" }.count
        let avgRate = totalAssigned == 0 ? 100 : Int((Double(totalCompleted) / Double(totalAssigned)) * 100)
        
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                kpiCard(title: "ASSIGNED JOBS", value: "\(totalAssigned)", sub: "Active Operations", color: .blue)
                kpiCard(title: "DELIVERIES", value: "\(totalCompleted)", sub: "Completed Orders", color: .green)
                kpiCard(title: "AVG SLA WIN", value: "\(avgRate)%", sub: "On-Time Fulfillment", color: .indigo)
            }
            .padding(.horizontal, 20)
        }
    }

    private func kpiCard(title: String, value: String, sub: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.system(size: 9, weight: .black))
                .foregroundColor(color)
            Text(value)
                .font(.system(size: 20, weight: .black))
                .foregroundColor(.textDark)
            Text(sub)
                .font(.system(size: 9))
                .foregroundColor(.textMuted)
        }
        .padding(12)
        .frame(width: 140, alignment: .leading)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(color.opacity(0.2), lineWidth: 1))
    }

    private func metricColumn(title: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 8, weight: .black))
                .foregroundColor(.textMuted)
            Text(value)
                .font(.system(size: 13, weight: .black))
                .foregroundColor(color)
        }
    }
}
