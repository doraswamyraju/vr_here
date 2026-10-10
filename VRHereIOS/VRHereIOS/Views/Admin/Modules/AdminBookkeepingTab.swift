import SwiftUI

struct AdminBookkeepingTab: View {
    @ObservedObject var viewModel: AdminDashboardViewModel
    
    @State private var selectedMonth: String = "September 2026"
    @State private var matrixData: FilingsMatrixResponse? = nil
    @State private var isLoadingMatrix: Bool = false
    
    @State private var selectedClient: FilingsMatrixClientUser? = nil
    @State private var activeAuditStep: AuditStep = .bank
    @State private var clientTransactions: [AccountingTransaction] = []
    @State private var clientPayroll: [AccountingPayrollRecord] = []
    @State private var gstr3bData: Gstr3bResponseData? = nil
    @State private var isLoadingClientData: Bool = false
    @State private var searchQuery: String = ""
    @State private var statusFilter: String = "All"
    
    // Add Payroll Sheet state
    @State private var isAddPayrollOpen: Bool = false
    
    enum AuditStep: String, CaseIterable {
        case bank = "1. Bank Recon"
        case ledger = "2. Vouchers Audit"
        case gst = "3. GST Returns"
        case tally = "4. Tally ERP"
        case payroll = "5. Payroll & TDS"
    }
    
    private let monthsList = [
        "April 2026", "May 2026", "June 2026", "July 2026", "August 2026", "September 2026",
        "October 2026", "November 2026", "December 2026", "January 2027", "February 2027", "March 2027", "ALL"
    ]
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                // Header Console
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("ACCOUNTING AS A SERVICE (AaaS) • v1.1")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.cyan)
                                .tracking(1.5)
                            Text("Bookkeeping Desk")
                                .font(.system(size: 24, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                    }
                    
                    Text("Monthly compliance matrix, bank reconciliation audits, GSTR-3B tax computations, and Tally ERP synchronization.")
                        .font(.system(size: 12))
                        .foregroundColor(.white.opacity(0.75))
                }
                .padding(20)
                .background(
                    LinearGradient(colors: [Color.darkSlate, Color(red: 15/255, green: 30/255, blue: 45/255)], startPoint: .topLeading, endPoint: .bottomTrailing)
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Month Period Switcher Bar
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(monthsList, id: \.self) { m in
                            let isSel = selectedMonth == m
                            Button(action: {
                                selectedMonth = m
                                fetchMatrix()
                            }) {
                                Text(m == "ALL" ? "All Months" : m)
                                    .font(.system(size: 11, weight: .bold))
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 7)
                                    .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                    .background(isSel ? Color.indigoCustom : Color.white)
                                    .cornerRadius(10)
                                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Main Content: Mode 1 (Matrix) vs Mode 2 (Dedicated Client Desk)
                if let client = selectedClient {
                    clientAuditDeskView(client: client)
                        .padding(.horizontal, 20)
                } else {
                    allClientsMatrixView
                        .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .onAppear {
            fetchMatrix()
        }
    }
    
    // MARK: - Mode 1: All Clients Filings Matrix View
    private var allClientsMatrixView: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Summary KPI Cards
            if let summary = matrixData?.summary {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    summaryCard(title: "ACTIVE PORTFOLIOS", value: "\(summary.totalClients ?? 0)", subtitle: "Assigned Businesses", icon: "building.2.fill", color: .indigoCustom)
                    summaryCard(title: "BANK RECON RATE", value: "\(summary.fullyReconciledBankCount ?? 0) / \(summary.totalClients ?? 0)", subtitle: "100% Tagged", icon: "building.columns.fill", color: .teal)
                    summaryCard(title: "GSTR-1 FILED", value: "\(Int(summary.gstr1FiledPercentage ?? 0))%", subtitle: "\(summary.gstr1FiledCount ?? 0) Signed Off", icon: "checkmark.seal.fill", color: .green)
                    summaryCard(title: "GSTR-3B CASH PAID", value: "\(Int(summary.gstr3bFiledPercentage ?? 0))%", subtitle: "\(summary.gstr3bFiledCount ?? 0) Settled", icon: "banknote.fill", color: .purple)
                }
            }
            
            // Search & Filter Bar
            HStack(spacing: 8) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textMuted)
                    TextField("Search client, company, GSTIN...", text: $searchQuery)
                        .font(.system(size: 12))
                }
                .padding(10)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                
                Button(action: { fetchMatrix() }) {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                        .padding(10)
                        .background(Color.white)
                        .cornerRadius(12)
                        .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
            
            // Portfolios List
            let clientsList = matrixData?.clients ?? []
            let filtered = clientsList.filter { item in
                let c = item.client
                let matchesSearch = searchQuery.isEmpty ||
                    c.name.localizedCaseInsensitiveContains(searchQuery) ||
                    (c.companyName ?? "").localizedCaseInsensitiveContains(searchQuery) ||
                    (c.gstin ?? "").localizedCaseInsensitiveContains(searchQuery)
                return matchesSearch
            }
            
            if isLoadingMatrix {
                HStack {
                    Spacer()
                    ProgressView()
                    Spacer()
                }
                .padding(40)
            } else if filtered.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "folder")
                        .font(.system(size: 32))
                        .foregroundColor(.textMuted)
                    Text("No bookkeeping client portfolios found for this month.")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.textMuted)
                }
                .frame(maxWidth: .infinity)
                .padding(40)
                .background(Color.white)
                .cornerRadius(16)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
            } else {
                ForEach(filtered) { item in
                    ClientMatrixRowCard(item: item) {
                        selectedClient = item.client
                        fetchClientBookkeeping(client: item.client)
                    }
                }
            }
        }
    }
    
    // MARK: - Mode 2: Client Audit Desk View
    private func clientAuditDeskView(client: FilingsMatrixClientUser) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            // Client Desk Header
            VStack(alignment: .leading, spacing: 8) {
                Button(action: { selectedClient = nil }) {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.backward")
                        Text("Back to All Clients")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white.opacity(0.8))
                }
                
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(client.companyName ?? client.name)
                            .font(.system(size: 18, weight: .black))
                            .foregroundColor(.white)
                        if let g = client.gstin {
                            Text("GSTIN: \(g)")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.cyan)
                        }
                    }
                    Spacer()
                    Button(action: { fetchClientBookkeeping(client: client) }) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.white)
                            .padding(8)
                            .background(Color.white.opacity(0.15))
                            .cornerRadius(8)
                    }
                }
            }
            .padding(16)
            .background(Color.darkSlate)
            .cornerRadius(18)
            
            // Workflow Stepper Switcher
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(AuditStep.allCases, id: \.self) { step in
                        let isSel = activeAuditStep == step
                        Button(action: { activeAuditStep = step }) {
                            Text(step.rawValue)
                                .font(.system(size: 11, weight: .bold))
                                .padding(.horizontal, 12)
                                .padding(.vertical, 7)
                                .foregroundColor(isSel ? .white : Color(red: 60/255, green: 75/255, blue: 95/255))
                                .background(isSel ? Color.indigoCustom : Color.white)
                                .cornerRadius(10)
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(isSel ? Color.indigoCustom : Color.borderLight, lineWidth: 1))
                        }
                    }
                }
            }
            
            // Step Content
            if isLoadingClientData {
                HStack {
                    Spacer()
                    ProgressView()
                    Spacer()
                }
                .padding(40)
            } else {
                switch activeAuditStep {
                case .bank:
                    bankReconSubView
                case .ledger:
                    vouchersAuditSubView
                case .gst:
                    gstReturnsSubView
                case .tally:
                    tallyExportSubView(client: client)
                case .payroll:
                    payrollSubView(client: client)
                }
            }
        }
    }
    
    // MARK: - Sub-Step 1: Bank Recon
    private var bankReconSubView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("BANK RECONCILIATION & STATEMENT TAGGING")
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.textMuted)
            
            let bankTxs = clientTransactions.filter { ($0.type ?? "").lowercased().contains("bank") }
            if bankTxs.isEmpty {
                Text("No bank statement entries synced for this client.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(20)
                    .frame(maxWidth: .infinity)
                    .background(Color.white)
                    .cornerRadius(12)
            } else {
                ForEach(bankTxs) { tx in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(tx.partyName ?? "Bank Transaction")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Date: \(tx.docDate?.prefix(10) ?? "-") • Ref: \(tx.docNumber ?? "-")")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            Text("₹\(Int(tx.totalAmount ?? 0))")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                            Text((tx.status ?? "PENDING").uppercased())
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(tx.status == "Verified" ? .green : .orange)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Sub-Step 2: Vouchers Audit
    private var vouchersAuditSubView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("SALES & PURCHASES VOUCHERS AUDIT")
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.textMuted)
            
            if clientTransactions.isEmpty {
                Text("No sales invoices or vendor bills recorded.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(20)
                    .frame(maxWidth: .infinity)
                    .background(Color.white)
                    .cornerRadius(12)
            } else {
                ForEach(clientTransactions) { tx in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(tx.partyName ?? "Tax Invoice")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.textDark)
                                Text("Doc #\(tx.docNumber ?? "-") • \(tx.docDate?.prefix(10) ?? "")")
                                    .font(.system(size: 10))
                                    .foregroundColor(.textMuted)
                            }
                            Spacer()
                            Text("₹\(Int(tx.totalAmount ?? 0))")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.textDark)
                        }
                        
                        Divider().background(Color.borderLight)
                        
                        HStack {
                            Text("Tax: ₹\(Int((tx.cgst ?? 0) + (tx.sgst ?? 0) + (tx.igst ?? 0)))")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                            Spacer()
                            HStack(spacing: 6) {
                                Button("Flag") {
                                    updateTxStatus(id: tx.idVal, status: "Flagged")
                                }
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.red)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(6)
                                
                                Button("Verify") {
                                    updateTxStatus(id: tx.idVal, status: "Verified")
                                }
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(.green)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(Color.green.opacity(0.1))
                                .cornerRadius(6)
                            }
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
    }
    
    // MARK: - Sub-Step 3: GST Returns
    private var gstReturnsSubView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("GSTR-3B STATUTORY TAX COMPUTATION")
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.textMuted)
            
            VStack(alignment: .leading, spacing: 10) {
                taxRow(title: "Taxable Outward Supplies", value: "₹\(Int(gstr3bData?.taxableOutward ?? 0))")
                taxRow(title: "Eligible ITC (Input Tax Credit)", value: "₹\(Int(gstr3bData?.itcEligible ?? 0))")
                Divider().background(Color.borderLight)
                taxRow(title: "Net Tax Payable (Cash Ledger)", value: "₹\(Int(gstr3bData?.netTaxPayable ?? 0))", isBold: true)
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(14)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
        }
    }
    
    // MARK: - Sub-Step 4: Tally Export
    private func tallyExportSubView(client: FilingsMatrixClientUser) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("TALLY PRIME XML & ERP EXPORTER")
                .font(.system(size: 10, weight: .black))
                .foregroundColor(.textMuted)
            
            VStack(alignment: .leading, spacing: 8) {
                Text("Generate XML payload containing all sales, purchase, and bank reconciliation vouchers for 1-click import into Tally Prime.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                
                Text("Ready Vouchers: \(clientTransactions.count)")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.textDark)
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.white)
            .cornerRadius(14)
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
        }
    }
    
    // MARK: - Sub-Step 5: Payroll
    private func payrollSubView(client: FilingsMatrixClientUser) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("STAFF PAYROLL, TDS & SALARY REGISTER")
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.textMuted)
                Spacer()
                Button(action: { isAddPayrollOpen = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Add Salary")
                    }
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Color.indigoCustom)
                    .cornerRadius(8)
                }
            }
            
            if clientPayroll.isEmpty {
                Text("No payroll records logged for this client.")
                    .font(.system(size: 12))
                    .foregroundColor(.textMuted)
                    .padding(20)
                    .frame(maxWidth: .infinity)
                    .background(Color.white)
                    .cornerRadius(12)
            } else {
                ForEach(clientPayroll) { p in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.employeeName)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.textDark)
                            Text("Month: \(p.month ?? "-") • Designation: \(p.designation ?? "-")")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) {
                            Text("Net: ₹\(Int(p.netSalary ?? 0))")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(.textDark)
                            Text("TDS: ₹\(Int(p.tdsDeduction ?? 0))")
                                .font(.system(size: 9))
                                .foregroundColor(.textMuted)
                        }
                    }
                    .padding(12)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.borderLight, lineWidth: 1))
                }
            }
        }
        .sheet(isPresented: $isAddPayrollOpen) {
            AddPayrollSheet(clientId: client.idVal) { newRecord in
                clientPayroll.insert(newRecord, at: 0)
                viewModel.toastMessage = "Payroll record added"
            }
        }
    }
    
    // MARK: - Helpers & Network Calls
    private func fetchMatrix() {
        isLoadingMatrix = true
        Task {
            do {
                matrixData = try await NetworkManager.shared.getAdminFilingsMatrix(month: selectedMonth)
            } catch {
                print("Matrix load error: \(error)")
            }
            isLoadingMatrix = false
        }
    }
    
    private func fetchClientBookkeeping(client: FilingsMatrixClientUser) {
        isLoadingClientData = true
        Task {
            do {
                async let txs = NetworkManager.shared.getClientAccountingTransactions(clientId: client.idVal)
                async let pay = NetworkManager.shared.getClientPayrollRecords(clientId: client.idVal)
                async let gstr = NetworkManager.shared.getGstr3bExport(clientId: client.idVal)
                
                clientTransactions = (try? await txs) ?? []
                clientPayroll = (try? await pay) ?? []
                gstr3bData = try? await gstr
            }
            isLoadingClientData = false
        }
    }
    
    private func updateTxStatus(id: String, status: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.updateAccountingTransactionStatus(id: id, status: status)
                if let idx = clientTransactions.firstIndex(where: { $0.idVal == id }) {
                    // Update locally
                    viewModel.toastMessage = "Transaction \(status)"
                }
            } catch {
                viewModel.toastMessage = "Failed: \(error.localizedDescription)"
            }
        }
    }
    
    private func summaryCard(title: String, value: String, subtitle: String, icon: String, color: Color) -> some View {
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
        .padding(12)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.borderLight, lineWidth: 1))
    }
    
    private func taxRow(title: String, value: String, isBold: Bool = false) -> some View {
        HStack {
            Text(title)
                .font(.system(size: 11, weight: isBold ? .bold : .medium))
                .foregroundColor(isBold ? .textDark : .textMuted)
            Spacer()
            Text(value)
                .font(.system(size: 12, weight: isBold ? .black : .bold))
                .foregroundColor(isBold ? .primaryRed : .textDark)
        }
    }
}

// MARK: - Client Matrix Row Card Subview
struct ClientMatrixRowCard: View {
    let item: FilingsMatrixClientItem
    let onOpenDesk: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Circle()
                    .fill(Color.indigoCustom.opacity(0.12))
                    .frame(width: 36, height: 36)
                    .overlay(
                        Text(String((item.client.companyName ?? item.client.name).prefix(1)).uppercased())
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(.indigoCustom)
                    )
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.client.companyName ?? item.client.name)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.textDark)
                    if let g = item.client.gstin {
                        Text(g)
                            .font(.system(size: 9, weight: .bold))
                            .foregroundColor(.textMuted)
                    }
                }
                Spacer()
                
                Button(action: onOpenDesk) {
                    HStack(spacing: 4) {
                        Text("Open Desk")
                        Image(systemName: "arrow.right")
                    }
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color.indigoCustom)
                    .cornerRadius(8)
                }
            }
            
            Divider().background(Color.borderLight)
            
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Bank Recon")
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(.textMuted)
                    Text("\(Int(item.metrics.bankReconPercentage))%")
                        .font(.system(size: 11, weight: .black))
                        .foregroundColor(item.metrics.bankReconPercentage == 100 ? .green : .orange)
                }
                Spacer()
                VStack(alignment: .leading, spacing: 1) {
                    Text("GSTR-1")
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(.textMuted)
                    Text(item.filing.gstr1Status ?? "Pending")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(item.filing.gstr1Status == "Filed" ? .green : .orange)
                }
                Spacer()
                VStack(alignment: .leading, spacing: 1) {
                    Text("GSTR-3B")
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(.textMuted)
                    Text(item.filing.gstr3bStatus ?? "Pending")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(item.filing.gstr3bStatus == "Filed" ? .green : .orange)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.borderLight, lineWidth: 1))
    }
}

// MARK: - Add Payroll Sheet
struct AddPayrollSheet: View {
    let clientId: String
    let onAdded: (AccountingPayrollRecord) -> Void
    
    @Environment(\.presentationMode) var presentationMode
    @State private var employeeName: String = ""
    @State private var designation: String = ""
    @State private var month: String = "September 2026"
    @State private var basicSalary: String = ""
    @State private var hra: String = ""
    @State private var allowances: String = ""
    @State private var pfDeduction: String = ""
    @State private var tdsDeduction: String = ""
    @State private var isSubmitting: Bool = false
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("EMPLOYEE INFO").font(.system(size: 10, weight: .black))) {
                    TextField("Employee Name *", text: $employeeName)
                        .font(.system(size: 13))
                    TextField("Designation", text: $designation)
                        .font(.system(size: 13))
                    TextField("Month", text: $month)
                        .font(.system(size: 13))
                }
                
                Section(header: Text("SALARY BREAKDOWN (INR)").font(.system(size: 10, weight: .black))) {
                    TextField("Basic Salary", text: $basicSalary).keyboardType(.decimalPad).font(.system(size: 13))
                    TextField("HRA", text: $hra).keyboardType(.decimalPad).font(.system(size: 13))
                    TextField("Special Allowances", text: $allowances).keyboardType(.decimalPad).font(.system(size: 13))
                    TextField("PF Deduction", text: $pfDeduction).keyboardType(.decimalPad).font(.system(size: 13))
                    TextField("TDS Deduction", text: $tdsDeduction).keyboardType(.decimalPad).font(.system(size: 13))
                }
            }
            .navigationTitle("Add Payroll Record")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { presentationMode.wrappedValue.dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") {
                        isSubmitting = true
                        Task {
                            do {
                                let b = Double(basicSalary) ?? 0
                                let h = Double(hra) ?? 0
                                let a = Double(allowances) ?? 0
                                let pf = Double(pfDeduction) ?? 0
                                let tds = Double(tdsDeduction) ?? 0
                                let net = (b + h + a) - (pf + tds)
                                
                                let payload: [String: AnyCodable] = [
                                    "clientId": AnyCodable(clientId),
                                    "employeeName": AnyCodable(employeeName),
                                    "designation": AnyCodable(designation),
                                    "month": AnyCodable(month),
                                    "basicSalary": AnyCodable(b),
                                    "hra": AnyCodable(h),
                                    "allowances": AnyCodable(a),
                                    "pfDeduction": AnyCodable(pf),
                                    "tdsDeduction": AnyCodable(tds),
                                    "netSalary": AnyCodable(net),
                                    "status": AnyCodable("Processed")
                                ]
                                let rec = try await NetworkManager.shared.createClientPayrollRecord(payload: payload)
                                onAdded(rec)
                                presentationMode.wrappedValue.dismiss()
                            } catch {
                                print("Payroll error: \(error)")
                            }
                            isSubmitting = false
                        }
                    }
                    .font(.system(size: 13, weight: .black))
                    .disabled(employeeName.isEmpty || isSubmitting)
                }
            }
        }
    }
}
