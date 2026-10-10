import SwiftUI

struct AdminPerformanceTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedEmployeeId: String = ""
    @State private var selectedTimeframe: String = "30 Days"
    @State private var fromDate: Date = Calendar.current.date(byAdding: .day, value: -30, to: Date()) ?? Date()
    @State private var toDate: Date = Date()
    
    // Detailed analysis states
    @State private var attendanceItems: [AttendanceSummaryItem] = []
    @State private var isLoadingData = false

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
                            Text("WORKFORCE PRODUCTIVITY & PERFORMANCE")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Performance Analytics")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Deep dive into employee time tracking, productivity ratios, task completion, and daily timesheet logs.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.8))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 15/255, green: 30/255, blue: 50/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Employee & Timeframe Controls
                VStack(alignment: .leading, spacing: 12) {
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
                    
                    // Timeframe Presets
                    HStack(spacing: 8) {
                        ForEach(["7 Days", "30 Days", "90 Days"], id: \.self) { tf in
                            let isSel = selectedTimeframe == tf
                            Button(action: {
                                selectedTimeframe = tf
                                let days = tf == "7 Days" ? -7 : (tf == "30 Days" ? -30 : -90)
                                fromDate = Calendar.current.date(byAdding: .day, value: days, to: Date()) ?? Date()
                            }) {
                                Text(tf)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                                    .foregroundColor(isSel ? .white : .textDark)
                                    .background(isSel ? Color.indigo : Color.white)
                                    .cornerRadius(8)
                                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(isSel ? Color.indigo : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                // Summary KPI Cards
                performanceKPICards
                
                // Deep-Dive Worksheet for Selected Employee
                if let emp = selectedEmployee {
                    employeeWorksheetDeepDive(emp: emp)
                }
                
                // Team Leaderboard & Capacity
                teamLeaderboardSection
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            loadAttendanceData()
        }
    }

    // MARK: - Summary KPI Cards
    private var performanceKPICards: some View {
        let targetOrders = selectedEmployeeId.isEmpty ? viewModel.orders : viewModel.orders.filter {
            $0.assignedEmployee?.idVal == selectedEmployeeId ||
            $0.assignedMaker?.idVal == selectedEmployeeId ||
            $0.assignedChecker?.idVal == selectedEmployeeId ||
            $0.assignedProjectManager?.idVal == selectedEmployeeId
        }
        let totalAssigned = targetOrders.count
        let totalCompleted = targetOrders.filter { $0.status == "Completed" }.count
        let avgRate = totalAssigned == 0 ? 100 : Int((Double(totalCompleted) / Double(totalAssigned)) * 100)
        
        let matchedAtt = attendanceItems.filter {
            selectedEmployeeId.isEmpty || $0.id == selectedEmployeeId
        }
        var totalMinutes = 0
        for att in matchedAtt {
            totalMinutes += att.trackedMinutes
        }
        
        let hours = totalMinutes / 60
        let mins = totalMinutes % 60
        
        return ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                kpiCard(title: "TRACKED TIME", value: "\(hours)h \(mins)m", sub: "Recorded Effort", color: .indigo)
                kpiCard(title: "ASSIGNED JOBS", value: "\(totalAssigned)", sub: "Active Operations", color: .blue)
                kpiCard(title: "DELIVERIES", value: "\(totalCompleted)", sub: "Completed Orders", color: .green)
                kpiCard(title: "AVG SLA WIN", value: "\(avgRate)%", sub: "Fulfillment Quality", color: .purple)
            }
            .padding(.horizontal, 20)
        }
    }
    
    // MARK: - Selected Employee Deep-Dive Worksheet
    private func employeeWorksheetDeepDive(emp: EmployeeResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("WORKSHEET & TIME LOG • \(emp.name.uppercased())")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            let empAttendance = attendanceItems.filter { $0.id == emp.idVal }
            
            if empAttendance.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "calendar.badge.clock")
                        .font(.system(size: 28))
                        .foregroundColor(.textMuted)
                    Text("No attendance or worksheet entries in this date range.")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(20)
                .background(Color.white)
                .cornerRadius(14)
            } else {
                ForEach(empAttendance) { att in
                    HStack {
                        Circle()
                            .fill(att.isClockedIn ? Color.green : Color.gray)
                            .frame(width: 8, height: 8)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(att.name)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(att.isClockedIn ? "Clocked In: \(att.clockInAt ?? "Active")" : "Offline")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        Text("\(att.trackedMinutes / 60)h \(att.trackedMinutes % 60)m")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.indigo)
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Team Leaderboard Section
    private var teamLeaderboardSection: some View {
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
                    let assignedOrders = viewModel.orders.filter {
                        $0.assignedEmployee?.idVal == emp.idVal ||
                        $0.assignedMaker?.idVal == emp.idVal ||
                        $0.assignedChecker?.idVal == emp.idVal ||
                        $0.assignedProjectManager?.idVal == emp.idVal
                    }
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
    
    private func loadAttendanceData() {
        isLoadingData = true
        Task {
            do {
                let res = try await NetworkManager.shared.getAttendanceSummary()
                attendanceItems = res.items ?? []
            } catch {
                print("Failed to load attendance summary: \(error)")
            }
            isLoadingData = false
        }
    }
}
