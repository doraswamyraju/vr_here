import SwiftUI

struct AdminOverviewTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    let userName: String
    let onNavigate: (String) -> Void
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Branded Top Header Card
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
                        .foregroundColor(Color.white.opacity(0.8))
                        .lineLimit(2)
                    
                    HStack(spacing: 12) {
                        let activeCount = viewModel.orders.filter { $0.status != "Completed" }.count
                        let totalValue = viewModel.orders.reduce(0.0) { $0 + $1.price }
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("ACTIVE PIPELINE")
                                .font(.system(size: 8, weight: .bold))
                                .foregroundColor(.cyan)
                            Text("\(activeCount) Projects")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.1))
                        .cornerRadius(8)
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TOTAL VALUE")
                                .font(.system(size: 8, weight: .bold))
                                .foregroundColor(.cyan)
                            Text("Rs. \(Int(totalValue))")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.white.opacity(0.1))
                        .cornerRadius(8)
                    }
                    .padding(.top, 8)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    LinearGradient(gradient: Gradient(colors: [Color(red: 0.08, green: 0.12, blue: 0.28), Color(red: 0.12, green: 0.08, blue: 0.32)]), startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Quick Action Grid
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
                
                // Analytics 4-card statistics
                let totalOrders = viewModel.orders.count
                let pendingCount = viewModel.orders.filter { $0.status != "Completed" }.count
                let completedCount = viewModel.orders.filter { $0.status == "Completed" }.count
                let totalVal = viewModel.orders.reduce(0.0) { $0 + $1.price }
                
                VStack(spacing: 12) {
                    HStack(spacing: 12) {
                        statReportWidget(label: "TOTAL ORDERS", value: "\(totalOrders)", icon: "square.stack.fill", color: .blue)
                        statReportWidget(label: "PENDING", value: "\(pendingCount)", icon: "clock.fill", color: .orange)
                    }
                    HStack(spacing: 12) {
                        statReportWidget(label: "COMPLETED", value: "\(completedCount)", icon: "checkmark.seal.fill", color: .green)
                        statReportWidget(label: "ORDER VALUE", value: "Rs.\(Int(totalVal))", icon: "indianrupeesign.circle.fill", color: .indigo)
                    }
                }
                .padding(.horizontal, 20)
                
                // Latest Work Updates
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("LATEST WORK UPDATES")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Button(action: { onNavigate("Orders") }) {
                            Text("View All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let latestOrders = Array(viewModel.orders.prefix(3))
                    
                    if latestOrders.isEmpty {
                        Text("No recent updates")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 20)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(latestOrders) { order in
                                HStack(spacing: 12) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(order.serviceName)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                            .lineLimit(1)
                                        Text("Client: \(order.clientName)")
                                            .font(.system(size: 10))
                                            .foregroundColor(.textMuted)
                                    }
                                    Spacer()
                                    
                                    VStack(alignment: .trailing, spacing: 3) {
                                        Text(order.status.uppercased())
                                            .font(.system(size: 8, weight: .bold))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .foregroundColor(statusColor(order.status))
                                            .background(statusColor(order.status).opacity(0.12))
                                            .cornerRadius(4)
                                        
                                        Text("Rs. \(Int(order.price))")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(.textMuted)
                                    }
                                }
                                .padding(.vertical, 6)
                                if order.id != latestOrders.last?.id {
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 20)
                
                // Financial Health Breakdown
                let total = viewModel.orders.reduce(0.0) { $0 + $1.price }
                let paid = viewModel.orders.filter { $0.paymentStatus.lowercased() == "paid" }.reduce(0.0) { $0 + $1.price }
                let pending = total - paid
                let collectionRate = total == 0 ? 0.0 : (paid / total) * 100.0
                
                VStack(alignment: .leading, spacing: 12) {
                    Text("FINANCIAL HEALTH")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    VStack(alignment: .leading, spacing: 16) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("PAID INFLOW")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundColor(.textMuted)
                                Text("Rs. \(Int(paid))")
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.green)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 4) {
                                Text("OUTSTANDING")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundColor(.textMuted)
                                Text("Rs. \(Int(pending))")
                                    .font(.system(size: 18, weight: .black))
                                    .foregroundColor(.red)
                            }
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text("Collection Rate")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textMuted)
                                Spacer()
                                Text(String(format: "%.1f%%", collectionRate))
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                            
                            // Collection Rate Progress Bar
                            GeometryReader { geometry in
                                ZStack(alignment: .leading) {
                                    RoundedRectangle(cornerRadius: 3)
                                        .fill(Color.borderLight)
                                        .frame(height: 6)
                                    RoundedRectangle(cornerRadius: 3)
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
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .stroke(Color.borderLight, lineWidth: 1)
                    )
                }
                .padding(.horizontal, 20)
                
                // Recent Tasks
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("RECENT TASKS")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Button(action: { onNavigate("Todo") }) {
                            Text("Manage")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    let activeTodos = Array(viewModel.todos.filter { !$0.completed }.prefix(4))
                    
                    if activeTodos.isEmpty {
                        Text("No active tasks")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 20)
                    } else {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(activeTodos) { todo in
                                HStack(alignment: .top, spacing: 8) {
                                    Circle()
                                        .fill(Color.orange)
                                        .frame(width: 6, height: 6)
                                        .padding(.top, 5)
                                    
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(todo.title)
                                            .font(.system(size: 12, weight: .bold))
                                            .foregroundColor(.textDark)
                                        Text("UNASSIGNED")
                                            .font(.system(size: 8, weight: .bold))
                                            .foregroundColor(.textMuted)
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 20)
                
                // Top Services
                VStack(alignment: .leading, spacing: 12) {
                    Text("TOP SERVICES")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.textMuted)
                    
                    let grouped = Dictionary(grouping: viewModel.orders, by: { $0.serviceName })
                    let sortedServices = grouped.map { (name: $0.key, count: $0.value.count) }
                        .sorted { $0.count > $1.count }
                        .prefix(4)
                    
                    if sortedServices.isEmpty {
                        Text("No service metrics available")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.textMuted)
                            .frame(maxWidth: .infinity, alignment: .center)
                            .padding(.vertical, 20)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(sortedServices, id: \.name) { service in
                                HStack {
                                    Text(service.name)
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(.textDark)
                                    Spacer()
                                    Text("\(service.count)")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(.blue)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 2)
                                        .background(Color.blue.opacity(0.1))
                                        .cornerRadius(6)
                                }
                                .padding(.vertical, 4)
                                if service.name != sortedServices.last?.name {
                                    Divider().background(Color.borderLight)
                                }
                            }
                        }
                        .padding(16)
                        .background(Color.white)
                        .cornerRadius(18)
                        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                        .overlay(
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(Color.borderLight, lineWidth: 1)
                        )
                    }
                }
                .padding(.horizontal, 20)
                
                // New Users
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("NEW USERS")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Button(action: { onNavigate("CRM") }) {
                            Text("View All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    HStack(spacing: -8) {
                        let uniqueClients = Dictionary(grouping: viewModel.orders, by: { $0.email }).values.compactMap { $0.first }.prefix(6)
                        
                        ForEach(uniqueClients) { client in
                            ZStack {
                                Circle()
                                    .fill(Color.blue)
                                    .frame(width: 32, height: 32)
                                    .overlay(Circle().stroke(Color.white, lineWidth: 2))
                                Text(String(client.clientName.prefix(1)).uppercased())
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                        
                        if uniqueClients.count > 0 {
                            ZStack {
                                Circle()
                                    .fill(Color.gray.opacity(0.2))
                                    .frame(width: 32, height: 32)
                                    .overlay(Circle().stroke(Color.white, lineWidth: 2))
                                Text("+35")
                                    .font(.system(size: 9, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                        }
                        
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            Text("TOTAL COMMUNITY")
                                .font(.system(size: 7, weight: .bold))
                                .foregroundColor(.textMuted)
                            Text("35 Members")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                        }
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
                    .overlay(
                        RoundedRectangle(cornerRadius: 18)
                            .stroke(Color.borderLight, lineWidth: 1)
                    )
                }
                .padding(.horizontal, 20)
                
                // Upcoming Renewals
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("UPCOMING RENEWALS")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textMuted)
                        Spacer()
                        Button(action: { onNavigate("Recurring") }) {
                            Text("Manage All")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.primaryRed)
                        }
                    }
                    
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 12) {
                            renewalWidget(date: "Apr 1", title: "ROC Annual Filings", desc: "Vydehi", amount: "4,530")
                            renewalWidget(date: "Jul 1", title: "GST Return Filing", desc: "Blue Cat", amount: "4,200")
                            renewalWidget(date: "Jul 1", title: "Cloud Accounting", desc: "Mark", amount: "9,999")
                        }
                        .padding(.horizontal, 20)
                    }
                    .padding(.horizontal, -20)
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
    }
    
    private func statReportWidget(label: String, value: String, icon: String, color: Color) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(label)
                    .font(.system(size: 8, weight: .bold))
                    .foregroundColor(.textMuted)
                Text(value)
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
            }
            Spacer()
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(color)
                .padding(8)
                .background(color.opacity(0.1))
                .cornerRadius(8)
        }
        .padding(14)
        .frame(maxWidth: .infinity)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.02), radius: 6, x: 0, y: 3)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func renewalWidget(date: String, title: String, desc: String, amount: String) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .center, spacing: 2) {
                Text(date.components(separatedBy: " ").first ?? "")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundColor(.blue)
                Text(date.components(separatedBy: " ").last ?? "")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.blue)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(Color.blue.opacity(0.08))
            .cornerRadius(8)
            
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.textDark)
                    .lineLimit(1)
                Text(desc)
                    .font(.system(size: 9))
                    .foregroundColor(.textMuted)
            }
            Spacer()
            
            Text("Rs. \(amount)")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textDark)
        }
        .padding(12)
        .frame(width: 220)
        .background(Color.white)
        .cornerRadius(14)
        .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func statusColor(_ status: String) -> Color {
        switch status.lowercased() {
        case "completed", "documents verified":
            return .green
        case "in progress", "processing", "pending documents":
            return .blue
        case "pending":
            return .orange
        default:
            return .red
        }
    }
}
