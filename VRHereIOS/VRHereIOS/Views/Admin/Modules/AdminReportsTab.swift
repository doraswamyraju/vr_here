import SwiftUI

struct AdminReportsTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    @State private var selectedPeriod: String = "FY 2026-27"
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("EXECUTIVE ANALYTICS & EXPORTS • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Business Reports")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        
                        Button(action: { viewModel.syncDashboardData() }) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .padding(10)
                                .background(Color.white.opacity(0.15))
                                .cornerRadius(10)
                        }
                    }
                    
                    Text("Executive metrics, statutory service distribution, pipeline conversion velocity, and financial report exports.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 25/255, green: 20/255, blue: 40/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Executive KPIs Grid
                let totalRev = viewModel.orders.reduce(0.0) { $0 + $1.price }
                let completedCount = viewModel.orders.filter { $0.status.lowercased() == "completed" }.count
                let clientsCount = viewModel.users.filter { $0.role.lowercased() == "client" || $0.role.lowercased() == "user" }.count
                
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    metricCard(title: "GROSS VOLUME", value: "₹\(Int(totalRev))", subtitle: "\(viewModel.orders.count) Orders", icon: "indianrupeesign.circle.fill", color: .indigoCustom)
                    metricCard(title: "COMPLETED FILINGS", value: "\(completedCount)", subtitle: "Statutory Sign-offs", icon: "checkmark.seal.fill", color: .green)
                    metricCard(title: "ACTIVE CLIENTS", value: "\(clientsCount)", subtitle: "Enterprise Accounts", icon: "person.3.fill", color: .teal)
                    metricCard(title: "CRM LEADS", value: "\(viewModel.leads.count)", subtitle: "Hot Inquiries", icon: "bolt.fill", color: .purple)
                }
                .padding(.horizontal, 20)
                
                // Service Revenue Mix Breakdown
                VStack(alignment: .leading, spacing: 14) {
                    Text("SERVICE MIX & REVENUE CONTRIBUTION")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textMuted)
                    
                    VStack(spacing: 12) {
                        serviceMixBar(title: "Corporate & LLP Incorp", count: viewModel.orders.filter { $0.serviceName.contains("Registration") || $0.serviceName.contains("Company") }.count, total: max(viewModel.orders.count, 1), color: .indigoCustom)
                        serviceMixBar(title: "GST Returns & Advisory", count: viewModel.orders.filter { $0.serviceName.contains("GST") }.count, total: max(viewModel.orders.count, 1), color: .teal)
                        serviceMixBar(title: "Income Tax & Assessments", count: viewModel.orders.filter { $0.serviceName.contains("Tax") || $0.serviceName.contains("ITR") }.count, total: max(viewModel.orders.count, 1), color: .green)
                        serviceMixBar(title: "Bookkeeping & AaaS", count: viewModel.orders.filter { $0.serviceName.contains("Accounting") || $0.serviceName.contains("Bookkeeping") }.count, total: max(viewModel.orders.count, 1), color: .purple)
                    }
                    .padding(16)
                    .background(Color.white)
                    .cornerRadius(18)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.borderLight, lineWidth: 1))
                }
                .padding(.horizontal, 20)
                
                // Export Data Packs
                VStack(alignment: .leading, spacing: 14) {
                    Text("DATA EXPORTS & COMPLIANCE REGISTERS")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(.textMuted)
                    
                    VStack(spacing: 10) {
                        exportRow(title: "Orders Master Register (CSV)", subtitle: "\(viewModel.orders.count) records with payment logs", icon: "tablecells") {
                            viewModel.toastMessage = "Exporting Orders CSV..."
                        }
                        
                        exportRow(title: "Statutory Compliance Matrix (CSV)", subtitle: "\(viewModel.complianceRecords.count) statutory filing deadlines", icon: "doc.text") {
                            viewModel.toastMessage = "Exporting Compliance Matrix CSV..."
                        }
                        
                        exportRow(title: "Referral Channel Payouts Ledger (CSV)", subtitle: "Affiliate commissions and UTR logs", icon: "arrow.up.right.square") {
                            viewModel.toastMessage = "Exporting Referral Ledger CSV..."
                        }
                    }
                }
                .padding(.horizontal, 20)
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
    }
    
    private func metricCard(title: String, value: String, subtitle: String, icon: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title)
                    .font(.system(size: 8, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .foregroundColor(color)
            }
            Text(value)
                .font(.system(size: 18, weight: .black))
                .foregroundColor(.textDark)
            Text(subtitle)
                .font(.system(size: 9))
                .foregroundColor(color)
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func serviceMixBar(title: String, count: Int, total: Int, color: Color) -> some View {
        let pct = Double(count) / Double(total)
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.textDark)
                Spacer()
                Text("\(count) orders (\(Int(pct * 100))%)")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(.textMuted)
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.bgLight)
                        .frame(height: 6)
                    RoundedRectangle(cornerRadius: 4)
                        .fill(color)
                        .frame(width: max(geo.size.width * CGFloat(pct), 4), height: 6)
                }
            }
            .frame(height: 6)
        }
    }
    
    private func exportRow(title: String, subtitle: String, icon: String, onExport: @escaping () -> Void) -> some View {
        Button(action: onExport) {
            HStack(spacing: 12) {
                Circle()
                    .fill(Color.indigoCustom.opacity(0.1))
                    .frame(width: 36, height: 36)
                    .overlay(
                        Image(systemName: icon)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.indigoCustom)
                    )
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textDark)
                    Text(subtitle)
                        .font(.system(size: 10))
                        .foregroundColor(.textMuted)
                }
                Spacer()
                Image(systemName: "arrow.down.doc.fill")
                    .font(.system(size: 13))
                    .foregroundColor(.indigoCustom)
            }
            .padding(12)
            .background(Color.white)
            .cornerRadius(14)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
        }
        .buttonStyle(PlainButtonStyle())
    }
}
