import SwiftUI

struct AdminFreelancersTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var activeTab: FreelancerSubTab = .directory
    @State private var broadcastPayoutAmounts: [String: String] = [:]
    @State private var searchQuery = ""
    
    enum FreelancerSubTab: String, CaseIterable {
        case directory = "Active Specialists"
        case broadcast = "Work Broadcasts"
        case payouts = "Payouts Ledger"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("GIG ECONOMY & CONTRACTORS • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Freelancer Hub")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Outsource execution tasks, manage specialized chartered accountants, broadcast projects, and process payouts.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 10/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Sub-Tabs Switcher
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(FreelancerSubTab.allCases, id: \.self) { tab in
                            let isSelected = activeTab == tab
                            Button(action: { activeTab = tab }) {
                                Text(tab.rawValue)
                                    .font(.system(size: 12, weight: .bold))
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 8)
                                    .foregroundColor(isSelected ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSelected ? Color.orange : Color.white)
                                    .cornerRadius(12)
                                    .shadow(color: isSelected ? Color.orange.opacity(0.3) : Color.clear, radius: 4, y: 2)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12)
                                            .stroke(isSelected ? Color.orange : Color.borderLight, lineWidth: 1)
                                    )
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Sub-Tab Content
                VStack {
                    switch activeTab {
                    case .directory:
                        freelancerDirectoryView
                    case .broadcast:
                        workBroadcastView
                    case .payouts:
                        payoutsLedgerView
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }

    // MARK: - Tab 1: Directory
    private var freelancerDirectoryView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("REGISTERED FREELANCERS (\(viewModel.freelancers.count))")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            if viewModel.freelancers.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "briefcase")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No external freelancers registered")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(viewModel.freelancers) { free in
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Circle()
                                .fill(Color.orange.opacity(0.15))
                                .frame(width: 40, height: 40)
                                .overlay(
                                    Text(String(free.name.prefix(1)).uppercased())
                                        .font(.system(size: 14, weight: .black))
                                        .foregroundColor(.orange)
                                )
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(free.name)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text(free.email)
                                    .font(.system(size: 11))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            
                            Text("ACTIVE")
                                .font(.system(size: 8, weight: .black))
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .foregroundColor(.green)
                                .background(Color.green.opacity(0.12))
                                .cornerRadius(6)
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        HStack {
                            Text("Role: \(free.role.capitalized)")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                            Spacer()
                            HStack(spacing: 2) {
                                Image(systemName: "star.fill")
                                    .font(.system(size: 10))
                                    .foregroundColor(.yellow)
                                Text("5.0 Rating")
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(.textDark)
                            }
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }

    // MARK: - Tab 2: Work Broadcast
    private var workBroadcastView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("BROADCAST PROJECTS TO FREELANCER NETWORK")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            let pendingOrders = viewModel.orders.filter { $0.status.lowercased() != "completed" }
            
            if pendingOrders.isEmpty {
                Text("No active orders available for external broadcast.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(.vertical, 20)
            } else {
                ForEach(pendingOrders) { ord in
                    BroadcastCardView(order: ord) { payoutAmt in
                        Task {
                            do {
                                let payload: [String: AnyCodable] = [
                                    "broadcastStatus": AnyCodable("Broadcasted"),
                                    "freelancerPayout": AnyCodable(payoutAmt)
                                ]
                                let bodyData = try JSONEncoder().encode(payload)
                                let _: OrderResponse = try await NetworkManager.shared.performRequest(path: "api/orders/\(ord.id)", method: "PUT", body: bodyData)
                                viewModel.syncDashboardData()
                                viewModel.toastMessage = "Project broadcasted to freelancers!"
                            } catch {
                                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Tab 3: Payouts Ledger
    private var payoutsLedgerView: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("COMMISSION & SERVICE PAYOUTS")
                .font(.system(size: 11, weight: .black))
                .foregroundColor(.textMuted)
            
            let broadcastedOrders = viewModel.orders.filter { $0.freelancerPayout != nil && ($0.freelancerPayout ?? 0) > 0 }
            
            if broadcastedOrders.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "creditcard")
                        .font(.system(size: 30))
                        .foregroundColor(.textMuted)
                    Text("No freelance payouts recorded")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(30)
            } else {
                ForEach(broadcastedOrders) { ord in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(ord.serviceName)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Payout: ₹\(Int(ord.freelancerPayout ?? 0)) • Client: \(ord.clientName)")
                                .font(.system(size: 11))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        Text("PENDING")
                            .font(.system(size: 8, weight: .black))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .foregroundColor(.orange)
                            .background(Color.orange.opacity(0.12))
                            .cornerRadius(6)
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(16)
                    .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
}

struct BroadcastCardView: View {
    let order: OrderResponse
    let onBroadcast: (Double) -> Void
    
    @State private var payoutText: String = ""
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(order.serviceName)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    Text("Client: \(order.clientName) • Total Value: ₹\(Int(order.price))")
                        .font(.system(size: 11))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                if order.broadcastStatus == "Broadcasted" {
                    Text("BROADCASTED")
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(.purple)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 3)
                        .background(Color.purple.opacity(0.12))
                        .cornerRadius(6)
                }
            }
            
            HStack(spacing: 8) {
                HStack {
                    Text("₹")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                    TextField("Payout INR", text: $payoutText)
                        .font(.system(size: 12))
                        .keyboardType(.numberPad)
                }
                .padding(8)
                .background(Color.bgInput)
                .cornerRadius(8)
                .frame(width: 120)
                
                Button(action: {
                    let defaultPrice = order.price * 0.4
                    let amt = Double(payoutText) ?? defaultPrice
                    onBroadcast(amt)
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "bolt.fill")
                        Text("Broadcast")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(Color.orange)
                    .cornerRadius(8)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
        .onAppear {
            if payoutText.isEmpty {
                payoutText = "\(Int(order.price * 0.4))"
            }
        }
    }
}
