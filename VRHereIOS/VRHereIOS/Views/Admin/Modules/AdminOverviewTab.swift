import SwiftUI

struct AdminOverviewTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let userName: String
    var onOpenNewOrder: (() -> Void)? = nil
    var onOpenNewTodo: (() -> Void)? = nil
    let onNavigate: (String) -> Void
    
    // Status color helper matching web palette
    private func statusColor(_ status: String) -> Color {
        let s = status.lowercased()
        if s.contains("complete") || s.contains("verified") || s.contains("approved") {
            return Color.green
        } else if s.contains("pending doc") || s.contains("clarification") {
            return Color.orange
        } else if s.contains("in progress") || s.contains("processing") || s.contains("assigned") {
            return Color.blue
        } else {
            return Color.indigo
        }
    }
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 20) {
                
                // MARK: 1. Hero Operations Studio Card
                VStack(alignment: .leading, spacing: 12) {
                    Text("ADMIN COMMAND CENTER (V1.1.8 - POWER TOOLS)")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(Color.cyan)
                        .tracking(1)
                    
                    Text("Operations Studio")
                        .font(.system(size: 26, weight: .black))
                        .foregroundColor(.white)
                    
                    Text("Service delivery, consultation conversion, and execution status in one place.")
                        .font(.system(size: 13))
                        .foregroundColor(Color.white.opacity(0.85))
                        .lineLimit(2)
                    
                    HStack(spacing: 12) {
                        let activeCount = viewModel.orders.filter { $0.status != "Completed" }.count
                        let totalValue = viewModel.orders.reduce(0.0) { $0 + $1.price }
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("ACTIVE PIPELINE")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.cyan)
                            Text("\(activeCount) Projects")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.12))
                        .cornerRadius(10)
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TOTAL VALUE")
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.green)
                            Text("Rs. \(Int(totalValue).formatted())")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.12))
                        .cornerRadius(10)
                    }
                    .padding(.top, 6)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(
                        colors: [Color(red: 0.06, green: 0.10, blue: 0.24), Color(red: 0.12, green: 0.16, blue: 0.38)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // MARK: 2. Quick Action Grid (4 Buttons 1:1 Vertical Web Design)
                HStack(spacing: 10) {
                    quickActionVerticalButton(
                        title: "NEW ORDER",
                        icon: "plus",
                        bgColor: Color(red: 0.06, green: 0.72, blue: 0.51) // Emerald
                    ) {
                        if let onOpenNewOrder = onOpenNewOrder {
                            onOpenNewOrder()
                        } else {
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }
                    }
                    
                    quickActionVerticalButton(
                        title: "ADD TO-DO",
                        icon: "checkmark.square.fill",
                        bgColor: Color(red: 0.96, green: 0.62, blue: 0.08) // Amber
                    ) {
                        if let onOpenNewTodo = onOpenNewTodo {
                            onOpenNewTodo()
                        } else {
                            onNavigate("Todo")
                        }
                    }
                    
                    quickActionVerticalButton(
                        title: "ORDERS",
                        icon: "square.stack.3d.up.fill",
                        bgColor: Color(red: 0.39, green: 0.40, blue: 0.95) // Indigo
                    ) {
                        viewModel.selectedOrderFilter = "All"
                        viewModel.selectedOrderId = ""
                        onNavigate("Orders")
                    }
                    
                    quickActionVerticalButton(
                        title: "REFRESH",
                        icon: "arrow.clockwise",
                        bgColor: Color(red: 0.25, green: 0.30, blue: 0.38) // Slate
                    ) {
                        viewModel.syncDashboardData()
                    }
                }
                .padding(.horizontal, 20)
                
                // MARK: 3. Interactive KPI Metric Cards (1:1 with Web Filter on Click)
                let totalOrders = viewModel.orders.count
                let pendingCount = viewModel.orders.filter { $0.status != "Completed" }.count
                let completedCount = viewModel.orders.filter { $0.status == "Completed" }.count
                let totalVal = viewModel.orders.reduce(0.0) { $0 + $1.price }
                
                VStack(spacing: 12) {
                    HStack(spacing: 12) {
                        interactiveStatCard(
                            label: "TOTAL ORDERS",
                            value: "\(totalOrders)",
                            icon: "square.stack.3d.up.fill",
                            color: .blue
                        ) {
                            viewModel.selectedOrderFilter = "All"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }
                        
                        interactiveStatCard(
                            label: "PENDING",
                            value: "\(pendingCount)",
                            icon: "clock.fill",
                            color: .orange
                        ) {
                            viewModel.selectedOrderFilter = "Pending"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }
                    }
                    
                    HStack(spacing: 12) {
                        interactiveStatCard(
                            label: "COMPLETED",
                            value: "\(completedCount)",
                            icon: "checkmark.seal.fill",
                            color: .green
                        ) {
                            viewModel.selectedOrderFilter = "Completed"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }
                        
                        interactiveStatCard(
                            label: "ORDER VALUE",
                            value: "Rs. \(Int(totalVal).formatted())",
                            icon: "indianrupeesign.circle.fill",
                            color: .indigo
                        ) {
                            viewModel.selectedOrderFilter = "All"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                // MARK: 4. Latest Work Updates
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("LATEST WORK UPDATES")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: {
                            viewModel.selectedOrderFilter = "All"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }) {
                            Text("View All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let recentOrders = Array(viewModel.orders.prefix(5))
                    if recentOrders.isEmpty {
                        Text("No recent orders found")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 24)
                            .background(Color.white)
                            .cornerRadius(18)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(recentOrders) { order in
                                Button(action: {
                                    viewModel.selectedOrderId = order.id
                                    onNavigate("Orders")
                                }) {
                                    HStack(spacing: 12) {
                                        VStack(alignment: .leading, spacing: 4) {
                                            Text(order.serviceName)
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(.textDark)
                                                .lineLimit(1)
                                            Text(order.clientName.isEmpty ? "Guest" : order.clientName)
                                                .font(.system(size: 11))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        VStack(alignment: .trailing, spacing: 4) {
                                            Text(order.status.uppercased())
                                                .font(.system(size: 8.5, weight: .black))
                                                .padding(.horizontal, 7)
                                                .padding(.vertical, 3)
                                                .foregroundColor(statusColor(order.status))
                                                .background(statusColor(order.status).opacity(0.12))
                                                .cornerRadius(6)
                                            
                                            Text("Rs. \(Int(order.price).formatted())")
                                                .font(.system(size: 11, weight: .black))
                                                .foregroundColor(.textDark)
                                        }
                                    }
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 12)
                                }
                                .buttonStyle(PlainButtonStyle())
                                
                                if order.id != recentOrders.last?.id {
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                .padding(.horizontal, 20)
                
                // MARK: 5. Order Pipeline (Status Breakdown with proportional progress bars)
                VStack(alignment: .leading, spacing: 14) {
                    Text("ORDER PIPELINE")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.textDark)
                    
                    let statusGrouped = Dictionary(grouping: viewModel.orders, by: { $0.status })
                    let sortedPipeline = statusGrouped.map { (status: $0.key, count: $0.value.count) }
                        .sorted { $0.count > $1.count }
                    
                    VStack(spacing: 12) {
                        if sortedPipeline.isEmpty {
                            Text("No pipeline data available")
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 10)
                        } else {
                            ForEach(sortedPipeline, id: \.status) { item in
                                Button(action: {
                                    viewModel.selectedOrderFilter = item.status
                                    viewModel.selectedOrderId = ""
                                    onNavigate("Orders")
                                }) {
                                    VStack(alignment: .leading, spacing: 6) {
                                        HStack {
                                            Text(item.status.uppercased())
                                                .font(.system(size: 9.5, weight: .black))
                                                .foregroundColor(.textMuted)
                                            Spacer()
                                            Text("\(item.count)")
                                                .font(.system(size: 12, weight: .black))
                                                .foregroundColor(.textDark)
                                        }
                                        
                                        GeometryReader { geo in
                                            let ratio = totalOrders == 0 ? 0 : CGFloat(item.count) / CGFloat(totalOrders)
                                            ZStack(alignment: .leading) {
                                                Capsule()
                                                    .fill(Color.borderLight)
                                                    .frame(height: 6)
                                                Capsule()
                                                    .fill(statusColor(item.status))
                                                    .frame(width: geo.size.width * ratio, height: 6)
                                            }
                                        }
                                        .frame(height: 6)
                                    }
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }
                    .padding(18)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // MARK: 6. System Insights Banner
                let avgValue = totalOrders == 0 ? 0 : Int(totalVal / Double(totalOrders))
                VStack(alignment: .leading, spacing: 10) {
                    Text("SYSTEM INSIGHTS")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.white)
                    
                    Text("Average project value: Rs. \(avgValue.formatted())")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(.white.opacity(0.9))
                    
                    Button(action: { onNavigate("Reports") }) {
                        Text("View Analytics")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(.indigo)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                            .background(Color.white)
                            .cornerRadius(10)
                    }
                    .padding(.top, 4)
                }
                .padding(18)
                .background(
                    LinearGradient(
                        colors: [Color.indigo, Color.purple],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(18)
                .padding(.horizontal, 20)
                
                // MARK: 7. Recent Tasks (To-Do)
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("RECENT TASKS")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onNavigate("Todo") }) {
                            Text("Manage")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let recentTodos = Array(viewModel.todos.prefix(4))
                    if recentTodos.isEmpty {
                        Text("No tasks active")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 20)
                            .background(Color.white)
                            .cornerRadius(18)
                    } else {
                        VStack(spacing: 12) {
                            ForEach(recentTodos) { todo in
                                HStack(alignment: .top, spacing: 10) {
                                    Circle()
                                        .fill(todo.completed ? Color.green : Color.orange)
                                        .frame(width: 8, height: 8)
                                        .padding(.top, 4)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(todo.title)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                            .lineLimit(1)
                                        Text(todo.assignedTo?.name ?? "UNASSIGNED")
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                .padding(.horizontal, 20)
                
                // MARK: 8. Top Services Master
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("TOP SERVICES")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onNavigate("Services") }) {
                            Text("View Master")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let serviceGrouped = Dictionary(grouping: viewModel.orders, by: { $0.serviceName })
                    let topServices = serviceGrouped.map { (name: $0.key, count: $0.value.count) }
                        .sorted { $0.count > $1.count }
                        .prefix(4)
                    
                    VStack(spacing: 10) {
                        if topServices.isEmpty {
                            Text("No service metrics available")
                                .font(.system(size: 12))
                                .foregroundColor(.textMuted)
                                .padding(.vertical, 10)
                        } else {
                            ForEach(topServices, id: \.name) { s in
                                HStack {
                                    Text(s.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                        .lineLimit(1)
                                    Spacer()
                                    Text("\(s.count)")
                                        .font(.system(size: 10, weight: .black))
                                        .foregroundColor(.indigo)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 3)
                                        .background(Color.indigo.opacity(0.1))
                                        .cornerRadius(6)
                                }
                                .padding(.vertical, 3)
                                if s.name != topServices.last?.name {
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // MARK: 9. New Users (Community Matrix 1:1)
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("NEW USERS")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onNavigate("Users") }) {
                            Text("View All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    VStack(alignment: .leading, spacing: 14) {
                        let userList = viewModel.users
                        let totalMembers = userList.count
                        
                        // Avatars stack
                        HStack(spacing: -10) {
                            ForEach(Array(userList.prefix(6))) { u in
                                ZStack {
                                    Circle()
                                        .fill(
                                            LinearGradient(
                                                colors: [Color.indigo, Color.blue],
                                                startPoint: .topLeading,
                                                endPoint: .bottomTrailing
                                            )
                                        )
                                        .frame(width: 38, height: 38)
                                        .overlay(Circle().stroke(Color.white, lineWidth: 2.5))
                                    Text(String(u.name.prefix(1)).uppercased())
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(.white)
                                }
                            }
                            
                            if totalMembers > 6 {
                                ZStack {
                                    Circle()
                                        .fill(Color(red: 0.94, green: 0.95, blue: 0.98))
                                        .frame(width: 38, height: 38)
                                        .overlay(Circle().stroke(Color.white, lineWidth: 2.5))
                                    Text("+\(totalMembers - 6)")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                            }
                        }
                        
                        // Total community counter banner
                        Button(action: { onNavigate("Users") }) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("TOTAL COMMUNITY")
                                        .font(.system(size: 8.5, weight: .black))
                                        .foregroundColor(.textMuted)
                                    HStack(spacing: 4) {
                                        Text("\(totalMembers)")
                                            .font(.system(size: 18, weight: .black))
                                            .foregroundColor(.textDark)
                                        Text("Members")
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(.green)
                                    }
                                }
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textMuted)
                            }
                            .padding(12)
                            .background(Color(red: 0.96, green: 0.97, blue: 1.0))
                            .cornerRadius(12)
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // MARK: 10. Top Referrals (1:1 with Web)
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("TOP REFERRALS")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onNavigate("Referral") }) {
                            Text("Manage")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let refList = [
                        (name: "Pavan", value: 3998),
                        (name: "Vydehi", value: 2),
                        (name: "V R Here", value: 0)
                    ]
                    
                    VStack(spacing: 8) {
                        ForEach(refList, id: \.name) { ref in
                            Button(action: { onNavigate("Referral") }) {
                                HStack(spacing: 12) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color.red.opacity(0.1))
                                            .frame(width: 32, height: 32)
                                        Text(String(ref.name.prefix(1)))
                                            .font(.system(size: 13, weight: .black))
                                            .foregroundColor(.red)
                                    }
                                    
                                    Text(ref.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    
                                    Spacer()
                                    
                                    Text("Rs. \(ref.value.formatted())")
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(.textDark)
                                }
                                .padding(.vertical, 4)
                            }
                            .buttonStyle(PlainButtonStyle())
                            
                            if ref.name != refList.last?.name {
                                Divider().background(Color.borderLight)
                            }
                        }
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // MARK: 11. Revenue Trend & Service Mix (Charts 1:1)
                VStack(alignment: .leading, spacing: 14) {
                    // Revenue Trend Card
                    Button(action: { onNavigate("Reports") }) {
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("REVENUE TREND")
                                        .font(.system(size: 12, weight: .black))
                                        .foregroundColor(.textDark)
                                    Text("MONTHLY BILLING VOLUME")
                                        .font(.system(size: 8.5, weight: .bold))
                                        .foregroundColor(.textMuted)
                                }
                                Spacer()
                                HStack(spacing: 4) {
                                    Image(systemName: "arrow.up.right")
                                        .font(.system(size: 9, weight: .bold))
                                    Text("+12.5%")
                                        .font(.system(size: 10, weight: .black))
                                }
                                .foregroundColor(.green)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(Color.green.opacity(0.12))
                                .cornerRadius(8)
                            }
                            
                            // Visual bar chart
                            let monthlyData: [(month: String, val: CGFloat)] = [
                                ("May", 0.4), ("Jun", 0.65), ("Jul", 0.85), ("Aug", 0.55), ("Sep", 0.95), ("Oct", 0.75)
                            ]
                            HStack(alignment: .bottom, spacing: 12) {
                                ForEach(monthlyData, id: \.month) { m in
                                    VStack(spacing: 6) {
                                        ZStack(alignment: .bottom) {
                                            RoundedRectangle(cornerRadius: 6)
                                                .fill(Color(red: 0.92, green: 0.94, blue: 0.98))
                                                .frame(height: 70)
                                            RoundedRectangle(cornerRadius: 6)
                                                .fill(
                                                    LinearGradient(
                                                        colors: [Color.indigo, Color.blue],
                                                        startPoint: .top,
                                                        endPoint: .bottom
                                                    )
                                                )
                                                .frame(height: 70 * m.val)
                                        }
                                        Text(m.month)
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundColor(.textMuted)
                                    }
                                    .frame(maxWidth: .infinity)
                                }
                            }
                            .padding(.top, 6)
                        }
                        .padding(18)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                    }
                    .buttonStyle(PlainButtonStyle())
                    
                    // Service Mix Card
                    Button(action: { onNavigate("Services") }) {
                        VStack(alignment: .leading, spacing: 14) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("SERVICE MIX")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.textDark)
                                Text("TOP PERFORMING OFFERINGS")
                                    .font(.system(size: 8.5, weight: .bold))
                                    .foregroundColor(.textMuted)
                            }
                            
                            let mixItems: [(title: String, pct: CGFloat, color: Color)] = [
                                ("Tally & Accounting", 0.45, .blue),
                                ("Income Tax Filing", 0.30, .indigo),
                                ("Company Incorporation", 0.15, .green),
                                ("Compliance Audits", 0.10, .orange)
                            ]
                            
                            VStack(spacing: 10) {
                                ForEach(mixItems, id: \.title) { item in
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text(item.title)
                                                .font(.system(size: 11, weight: .bold))
                                                .foregroundColor(.textDark)
                                            Spacer()
                                            Text("\(Int(item.pct * 100))%")
                                                .font(.system(size: 10, weight: .black))
                                                .foregroundColor(item.color)
                                        }
                                        GeometryReader { geo in
                                            ZStack(alignment: .leading) {
                                                Capsule().fill(Color.borderLight).frame(height: 6)
                                                Capsule().fill(item.color).frame(width: geo.size.width * item.pct, height: 6)
                                            }
                                        }
                                        .frame(height: 6)
                                    }
                                }
                            }
                        }
                        .padding(18)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                    }
                    .buttonStyle(PlainButtonStyle())
                }
                .padding(.horizontal, 20)
                
                // MARK: 12. Pending Documents Card
                let pendingDocs = viewModel.orders.filter { $0.status.lowercased().contains("pending doc") }
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 12))
                                .foregroundColor(.orange)
                            Text("PENDING DOCUMENTS")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        Spacer()
                        Button(action: {
                            viewModel.selectedOrderFilter = "Pending Documents"
                            viewModel.selectedOrderId = ""
                            onNavigate("Orders")
                        }) {
                            Text("View All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    if pendingDocs.isEmpty {
                        HStack {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(.green)
                            Text("Excellent! No projects pending client documents.")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.textMuted)
                        }
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 20)
                        .background(Color.white)
                        .cornerRadius(18)
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(pendingDocs.prefix(3))) { o in
                                Button(action: {
                                    viewModel.selectedOrderId = o.id
                                    onNavigate("Orders")
                                }) {
                                    HStack(spacing: 12) {
                                        Image(systemName: "doc.text.fill")
                                            .font(.system(size: 16))
                                            .foregroundColor(.orange)
                                            .padding(8)
                                            .background(Color.orange.opacity(0.1))
                                            .cornerRadius(8)
                                        
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(o.serviceName)
                                                .font(.system(size: 12, weight: .bold))
                                                .foregroundColor(.textDark)
                                                .lineLimit(1)
                                            Text(o.clientName.isEmpty ? "Guest" : o.clientName)
                                                .font(.system(size: 10))
                                                .foregroundColor(.textMuted)
                                        }
                                        Spacer()
                                        
                                        Text("Rs. \(Int(o.price).formatted())")
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(.textDark)
                                    }
                                    .padding(.horizontal, 16)
                                    .padding(.vertical, 10)
                                }
                                .buttonStyle(PlainButtonStyle())
                                
                                if o.id != pendingDocs.prefix(3).last?.id {
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                    }
                }
                .padding(.horizontal, 20)
                
                // MARK: 13. Financial Health Breakdown
                let total = viewModel.orders.reduce(0.0) { $0 + $1.price }
                let paid = viewModel.orders.filter { $0.paymentStatus.lowercased() == "paid" }.reduce(0.0) { $0 + $1.price }
                let pending = total - paid
                let collectionRate = total == 0 ? 0.0 : (paid / total) * 100.0
                
                VStack(alignment: .leading, spacing: 14) {
                    Text("FINANCIAL HEALTH")
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.textDark)
                    
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("PAID INFLOW")
                                    .font(.system(size: 8.5, weight: .black))
                                    .foregroundColor(.green)
                                Text("Rs. \(Int(paid).formatted())")
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.green)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 4) {
                                Text("OUTSTANDING")
                                    .font(.system(size: 8.5, weight: .black))
                                    .foregroundColor(.red)
                                Text("Rs. \(Int(pending).formatted())")
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.red)
                            }
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("Collection Rate")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(String(format: "%.1f%%", collectionRate))
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(.textDark)
                            }
                            
                            GeometryReader { geometry in
                                ZStack(alignment: .leading) {
                                    Capsule()
                                        .fill(Color.borderLight)
                                        .frame(height: 6)
                                    Capsule()
                                        .fill(Color.green)
                                        .frame(width: geometry.size.width * CGFloat(collectionRate / 100.0), height: 6)
                                }
                            }
                            .frame(height: 6)
                        }
                    }
                    .padding(18)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // MARK: 14. Team Workload / Active Specialists (1:1 with Web)
                Button(action: { onNavigate("Performance") }) {
                    VStack(alignment: .leading, spacing: 14) {
                        HStack(spacing: 10) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 36, height: 36)
                                Image(systemName: "person.3.fill")
                                    .font(.system(size: 16))
                                    .foregroundColor(.cyan)
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("TEAM WORKLOAD")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(.white)
                                Text("ACTIVE SPECIALISTS")
                                    .font(.system(size: 8.5, weight: .black))
                                    .foregroundColor(.cyan)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white.opacity(0.7))
                        }
                        
                        let empList = viewModel.employees
                        if empList.isEmpty {
                            Text("No specialist workload data")
                                .font(.system(size: 12))
                                .foregroundColor(.white.opacity(0.7))
                        } else {
                            VStack(spacing: 8) {
                                ForEach(Array(empList.prefix(4))) { emp in
                                    HStack {
                                        Text(emp.name)
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(.white)
                                        Spacer()
                                        Text(emp.role.uppercased())
                                            .font(.system(size: 8.5, weight: .black))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color.white.opacity(0.15))
                                            .foregroundColor(.cyan)
                                            .cornerRadius(4)
                                    }
                                }
                            }
                        }
                    }
                    .padding(18)
                    .background(
                        LinearGradient(
                            colors: [Color(red: 0.08, green: 0.12, blue: 0.22), Color(red: 0.12, green: 0.18, blue: 0.32)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.05), radius: 8, x: 0, y: 4)
                }
                .buttonStyle(PlainButtonStyle())
                .padding(.horizontal, 20)
                
                // MARK: 15. Upcoming Renewals (30 Days Projection 1:1)
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        Text("UPCOMING RENEWALS")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Spacer()
                        Button(action: { onNavigate("Recurring") }) {
                            Text("Manage All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let activeRecurring = viewModel.recurring.filter { $0.isActive }
                    if activeRecurring.isEmpty {
                        Text("No active renewals scheduled")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 20)
                            .background(Color.white)
                            .cornerRadius(18)
                    } else {
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 12) {
                                ForEach(activeRecurring) { r in
                                    renewalCard(item: r)
                                }
                            }
                            .padding(.horizontal, 20)
                        }
                        .padding(.horizontal, -20)
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
    
    // 1:1 Vertical Quick Action Button
    private func quickActionVerticalButton(title: String, icon: String, bgColor: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(bgColor)
                        .frame(width: 40, height: 40)
                        .shadow(color: bgColor.opacity(0.3), radius: 4, x: 0, y: 2)
                    Image(systemName: icon)
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.white)
                }
                
                Text(title)
                    .font(.system(size: 8.5, weight: .black))
                    .foregroundColor(Color(red: 0.35, green: 0.40, blue: 0.50))
                    .tracking(0.5)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background(Color.white)
            .cornerRadius(16)
            .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.borderLight, lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // Interactive KPI Stat Card
    private func interactiveStatCard(label: String, value: String, icon: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(label)
                        .font(.system(size: 8.5, weight: .bold))
                        .foregroundColor(.textMuted)
                    Text(value)
                        .font(.system(size: 18, weight: .black))
                        .foregroundColor(.textDark)
                }
                Spacer()
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundColor(color)
                    .padding(10)
                    .background(color.opacity(0.12))
                    .cornerRadius(10)
            }
            .padding(14)
            .frame(maxWidth: .infinity)
            .background(Color.white)
            .cornerRadius(18)
            .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // Renewal card widget
    private func renewalCard(item: RecurringResponse) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .center, spacing: 2) {
                Text(item.frequency.prefix(3).uppercased())
                    .font(.system(size: 8, weight: .black))
                    .foregroundColor(.indigo)
                Image(systemName: "repeat")
                    .font(.system(size: 11, weight: .black))
                    .foregroundColor(.indigo)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
            .background(Color.indigo.opacity(0.1))
            .cornerRadius(8)
            
            VStack(alignment: .leading, spacing: 2) {
                Text(item.serviceName)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textDark)
                    .lineLimit(1)
                Text(item.clientName ?? item.user?.name ?? "Client")
                    .font(.system(size: 9))
                    .foregroundColor(.textMuted)
            }
            Spacer()
            
            Text("Rs. \(Int(item.price).formatted())")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textDark)
        }
        .padding(12)
        .frame(width: 220)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
}
