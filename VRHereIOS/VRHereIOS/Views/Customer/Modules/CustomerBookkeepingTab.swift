import SwiftUI

// MARK: - Main Bookkeeping & AaaS Host Screen (iOS 1:1 Matching Android)

struct CustomerBookkeepingTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel

    @State private var selectedSubTab = "Dashboard"
    @State private var selectedMonth = "All Months"
    @State private var searchQuery = ""
    @State private var selectedStatusFilter = "All"

    private let monthsList = [
        "All Months", "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026", "Sep 2026",
        "Oct 2026", "Nov 2026", "Dec 2026", "Jan 2027", "Feb 2027", "Mar 2027"
    ]

    private let subModules: [(id: String, icon: String, label: String)] = [
        ("Dashboard", "square.grid.2x2.fill", "Overview"),
        ("Sales", "doc.text.fill", "Sales Invoices"),
        ("Purchases", "cart.fill", "Purchase Bills"),
        ("Expenses", "arrow.down.right.circle.fill", "Income & Expense"),
        ("Banking", "building.columns.fill", "Bank Sync"),
        ("Parties", "person.2.fill", "Customers & Vendors"),
        ("Reports", "chart.pie.fill", "Reports & P&L")
    ]

    // Master Datasets from Server
    @State private var transactions: [TransactionDto] = []
    @State private var parties: [PartyDto] = []
    @State private var bankStatements: [BankStatementDto] = []
    @State private var companyDetails: CompanyDetailsDto? = nil
    @State private var isLoading: Bool = false
    @State private var toastMessage: String? = nil

    // Dialogs & Sheets State
    @State private var transactionFormType: String? = nil // "Sales", "Purchase", "Expense", "Income"
    @State private var editingTransaction: TransactionDto? = nil
    @State private var previewInvoice: TransactionDto? = nil
    @State private var taggingBankTx: BankTransactionDto? = nil
    @State private var showPartyDialog: Bool = false
    @State private var editingParty: PartyDto? = nil
    @State private var showCompanySettingsDialog: Bool = false
    @State private var showUploadNotice: Bool = false

    init(viewModel: CustomerDashboardViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        ZStack {
            Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea()

            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 14) {
                    // 1. Suite Header & Company Settings Trigger
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Bookkeeping & AaaS")
                                    .font(.system(size: 19, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text("Live GST Invoicing, Bills & Banking")
                                    .font(.system(size: 11.5))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }

                            Spacer()

                            HStack(spacing: 8) {
                                // Refresh Button
                                Button(action: { reloadAccountingData(silent: false) }) {
                                    ZStack {
                                        Circle()
                                            .fill(Color.white)
                                            .frame(width: 36, height: 36)
                                            .shadow(color: Color.black.opacity(0.04), radius: 3, y: 1)
                                        Image(systemName: "arrow.clockwise")
                                            .font(.system(size: 14, weight: .bold))
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                    }
                                }
                                .buttonStyle(PlainButtonStyle())

                                // Company Settings Button
                                Button(action: { showCompanySettingsDialog = true }) {
                                    ZStack {
                                        Circle()
                                            .fill(Color.white)
                                            .frame(width: 36, height: 36)
                                            .shadow(color: Color.black.opacity(0.04), radius: 3, y: 1)
                                        Image(systemName: "gearshape.fill")
                                            .font(.system(size: 14, weight: .bold))
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                    }
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }

                        // Date & FY Filter Bar
                        BookkeepingDateFilterBar(
                            financialYear: "FY 2026-27",
                            selectedMonth: $selectedMonth,
                            monthsList: monthsList
                        )
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 14)

                    // 2. Sub-Modules Navigation Tabs Carousel
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(subModules, id: \.id) { mod in
                                let isSelected = selectedSubTab == mod.id
                                Button(action: {
                                    selectedSubTab = mod.id
                                    searchQuery = ""
                                    selectedStatusFilter = "All"
                                }) {
                                    HStack(spacing: 6) {
                                        Image(systemName: mod.icon)
                                            .font(.system(size: 12))
                                            .foregroundColor(isSelected ? .white : Color(red: 79/255, green: 70/255, blue: 229/255))
                                        Text(mod.label)
                                            .font(.system(size: 12, weight: isSelected ? .black : .bold))
                                            .foregroundColor(isSelected ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 10)
                                    .background(isSelected ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color.white)
                                    .cornerRadius(12)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12)
                                            .stroke(isSelected ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                    )
                                    .shadow(color: Color.black.opacity(isSelected ? 0.12 : 0.02), radius: 4, y: 1)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 16)
                    }

                    // Loading Indicator Bar
                    if isLoading {
                        HStack(spacing: 8) {
                            ProgressView()
                                .scaleEffect(0.8)
                            Text("Syncing live database...")
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 2)
                    }

                    // 3. Sub-Module Content Areas
                    Group {
                        switch selectedSubTab {
                        case "Dashboard":
                            ExecutiveDashboardScreen(
                                transactions: filteredTransactions,
                                bankStatements: bankStatements,
                                selectedMonth: selectedMonth,
                                onNavigateTab: { selectedSubTab = $0 },
                                onCreateSales: {
                                    editingTransaction = nil
                                    transactionFormType = "Sales"
                                },
                                onCreatePurchase: {
                                    editingTransaction = nil
                                    transactionFormType = "Purchase"
                                },
                                onCreateExpense: {
                                    editingTransaction = nil
                                    transactionFormType = "Expense"
                                },
                                onViewTransaction: { previewInvoice = $0 }
                            )

                        case "Sales":
                            SalesInvoicesScreen(
                                salesTransactions: filteredTransactions.filter { $0.transactionType.caseInsensitiveCompare("Sales") == .orderedSame },
                                selectedStatusFilter: $selectedStatusFilter,
                                searchQuery: $searchQuery,
                                onCreateInvoice: {
                                    editingTransaction = nil
                                    transactionFormType = "Sales"
                                },
                                onViewInvoice: { previewInvoice = $0 },
                                onDeleteInvoice: { tx in
                                    deleteTransaction(tx)
                                }
                            )

                        case "Purchases":
                            PurchaseBillsScreen(
                                purchaseTransactions: filteredTransactions.filter { $0.transactionType.caseInsensitiveCompare("Purchase") == .orderedSame },
                                selectedStatusFilter: $selectedStatusFilter,
                                searchQuery: $searchQuery,
                                onCreateBill: {
                                    editingTransaction = nil
                                    transactionFormType = "Purchase"
                                },
                                onViewBill: { previewInvoice = $0 },
                                onDeleteBill: { tx in
                                    deleteTransaction(tx)
                                }
                            )

                        case "Expenses":
                            IncomeExpensesScreen(
                                expenseTransactions: filteredTransactions.filter {
                                    $0.transactionType.caseInsensitiveCompare("Expense") == .orderedSame || $0.transactionType.caseInsensitiveCompare("Income") == .orderedSame
                                },
                                selectedTypeFilter: $selectedStatusFilter,
                                searchQuery: $searchQuery,
                                onCreateExpense: {
                                    editingTransaction = nil
                                    transactionFormType = "Expense"
                                },
                                onViewExpense: { previewInvoice = $0 },
                                onDeleteExpense: { tx in
                                    deleteTransaction(tx)
                                }
                            )

                        case "Banking":
                            BankStatementsScreen(
                                bankStatements: bankStatements,
                                selectedStatusFilter: $selectedStatusFilter,
                                onUploadStatement: { showUploadNotice = true },
                                onTagTransaction: { tx in taggingBankTx = tx }
                            )

                        case "Parties":
                            PartiesScreen(
                                parties: parties,
                                selectedTypeFilter: $selectedStatusFilter,
                                searchQuery: $searchQuery,
                                onAddParty: {
                                    editingParty = nil
                                    showPartyDialog = true
                                },
                                onEditParty: { p in
                                    editingParty = p
                                    showPartyDialog = true
                                },
                                onDeleteParty: { p in
                                    deleteParty(p)
                                }
                            )

                        case "Reports":
                            ReportsScreen(
                                transactions: filteredTransactions,
                                selectedMonth: selectedMonth
                            )

                        default:
                            EmptyView()
                        }
                    }
                    .padding(.horizontal, 16)

                    Spacer().frame(height: 100)
                }
            }

            // Floating Toast
            if let toast = toastMessage {
                VStack {
                    Spacer()
                    Text(toast)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.95))
                        .cornerRadius(20)
                        .shadow(radius: 6)
                        .padding(.bottom, 90)
                }
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .animation(.spring(), value: toastMessage)
            }
        }
        .onAppear {
            reloadAccountingData()
        }
        // 1. Transaction Form Sheet
        .sheet(isPresented: Binding(
            get: { transactionFormType != nil },
            set: { if !$0 { transactionFormType = nil; editingTransaction = nil } }
        )) {
            if let type = transactionFormType {
                TransactionFormBottomSheet(
                    transactionType: type,
                    existingTransaction: editingTransaction,
                    parties: parties,
                    onDismiss: {
                        transactionFormType = nil
                        editingTransaction = nil
                    },
                    onSubmit: { payload in
                        saveTransaction(payload, type: type)
                    }
                )
            }
        }
        // 2. Tag Payment Sheet
        .sheet(isPresented: Binding(
            get: { taggingBankTx != nil },
            set: { if !$0 { taggingBankTx = nil } }
        )) {
            if let bankTx = taggingBankTx {
                let isCredit = bankTx.type.caseInsensitiveCompare("CREDIT") == .orderedSame
                let openVouchers = transactions.filter {
                    if isCredit {
                        return $0.transactionType.caseInsensitiveCompare("Sales") == .orderedSame && $0.paymentStatus.caseInsensitiveCompare("Paid") != .orderedSame
                    } else {
                        return $0.transactionType.caseInsensitiveCompare("Purchase") == .orderedSame && $0.paymentStatus.caseInsensitiveCompare("Paid") != .orderedSame
                    }
                }

                TagPaymentBottomSheet(
                    bankTransaction: bankTx,
                    openInvoicesOrBills: openVouchers,
                    onDismiss: { taggingBankTx = nil },
                    onTagSubmitted: { voucherId, category, notes in
                        tagBankTx(bankTx: bankTx, voucherId: voucherId, category: category, notes: notes)
                    }
                )
            }
        }
        // 3. Party Form Sheet
        .sheet(isPresented: $showPartyDialog) {
            PartyFormBottomSheet(
                existingParty: editingParty,
                onDismiss: {
                    showPartyDialog = false
                    editingParty = nil
                },
                onSubmit: { party in
                    saveParty(party)
                }
            )
        }
        // 4. Company Settings Sheet
        .sheet(isPresented: $showCompanySettingsDialog) {
            CompanySettingsBottomSheet(
                currentDetails: companyDetails,
                onDismiss: { showCompanySettingsDialog = false },
                onSubmit: { updated in
                    saveCompanySettings(updated)
                }
            )
        }
        // 5. GST Invoice Full-screen Preview
        .sheet(isPresented: Binding(
            get: { previewInvoice != nil },
            set: { if !$0 { previewInvoice = nil } }
        )) {
            if let inv = previewInvoice {
                GSTInvoicePreviewDialog(
                    transaction: inv,
                    companyDetails: companyDetails,
                    onDismiss: { previewInvoice = nil }
                )
            }
        }
        .alert("Upload Statement", isPresented: $showUploadNotice) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Please upload CSV or PDF bank statement files via the web dashboard or document vault for auto-tagging.")
        }
    }

    // Filter transactions by selected month
    private var filteredTransactions: [TransactionDto] {
        transactions.filter { isDateInSelectedMonth(docDateStr: $0.docDate, targetMonth: selectedMonth) }
    }

    private func isDateInSelectedMonth(docDateStr: String?, targetMonth: String) -> Bool {
        if targetMonth == "All Months" || targetMonth.lowercased().hasPrefix("all") { return true }
        guard let docDateStr = docDateStr, !docDateStr.isEmpty else { return false }
        let cleanDate = String(docDateStr.prefix(10))
        let parts = cleanDate.split(separator: "-")
        if parts.count >= 2 {
            let year = String(parts[0])
            guard let monthNum = Int(parts[1]) else { return false }
            let monthAbbr: String
            switch monthNum {
            case 1: monthAbbr = "Jan"
            case 2: monthAbbr = "Feb"
            case 3: monthAbbr = "Mar"
            case 4: monthAbbr = "Apr"
            case 5: monthAbbr = "May"
            case 6: monthAbbr = "Jun"
            case 7: monthAbbr = "Jul"
            case 8: monthAbbr = "Aug"
            case 9: monthAbbr = "Sep"
            case 10: monthAbbr = "Oct"
            case 11: monthAbbr = "Nov"
            case 12: monthAbbr = "Dec"
            default: monthAbbr = ""
            }
            return targetMonth.localizedCaseInsensitiveContains(monthAbbr) && targetMonth.localizedCaseInsensitiveContains(year)
        }
        return true
    }

    // MARK: - API Calls

    private func reloadAccountingData(silent: Bool = false) {
        if !silent { isLoading = true }
        Task {
            do {
                async let fetchedTx = NetworkManager.shared.getAccountingTransactions()
                async let fetchedParties = NetworkManager.shared.getAccountingParties()
                async let fetchedBank = NetworkManager.shared.getBankStatements()
                async let fetchedComp = NetworkManager.shared.getCompanyDetails()

                let (tx, p, b, c) = try await (fetchedTx, fetchedParties, fetchedBank, fetchedComp)

                await MainActor.run {
                    self.transactions = tx
                    self.parties = p
                    self.bankStatements = b
                    self.companyDetails = c
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.isLoading = false
                    if !silent {
                        showToast("Sync error: \(error.localizedDescription)")
                    }
                }
            }
        }
    }

    private func saveTransaction(_ payload: TransactionDto, type: String) {
        Task {
            do {
                if let existing = editingTransaction, let id = existing._id, !id.isEmpty {
                    _ = try await NetworkManager.shared.updateAccountingTransaction(id: id, transaction: payload)
                } else {
                    _ = try await NetworkManager.shared.createAccountingTransaction(transaction: payload)
                }
                await MainActor.run {
                    showToast("\(type) recorded successfully!")
                    transactionFormType = nil
                    editingTransaction = nil
                    reloadAccountingData(silent: true)
                }
            } catch {
                await MainActor.run {
                    showToast("Failed to save \(type): \(error.localizedDescription)")
                }
            }
        }
    }

    private func deleteTransaction(_ tx: TransactionDto) {
        guard let id = tx._id, !id.isEmpty else { return }
        Task {
            do {
                _ = try await NetworkManager.shared.deleteAccountingTransaction(id: id)
                await MainActor.run {
                    showToast("Transaction deleted")
                    reloadAccountingData(silent: true)
                }
            } catch {
                await MainActor.run {
                    showToast("Failed to delete: \(error.localizedDescription)")
                }
            }
        }
    }

    private func saveParty(_ party: PartyDto) {
        Task {
            do {
                if let existing = editingParty, let id = existing._id, !id.isEmpty {
                    _ = try await NetworkManager.shared.updateAccountingParty(id: id, party: party)
                } else {
                    _ = try await NetworkManager.shared.createAccountingParty(party: party)
                }
                await MainActor.run {
                    showToast("Party saved successfully!")
                    showPartyDialog = false
                    editingParty = nil
                    reloadAccountingData(silent: true)
                }
            } catch {
                await MainActor.run {
                    showToast("Failed to save party: \(error.localizedDescription)")
                }
            }
        }
    }

    private func deleteParty(_ party: PartyDto) {
        guard let id = party._id, !id.isEmpty else { return }
        Task {
            do {
                _ = try await NetworkManager.shared.deleteAccountingParty(id: id)
                await MainActor.run {
                    showToast("Party deleted")
                    reloadAccountingData(silent: true)
                }
            } catch {
                await MainActor.run {
                    showToast("Failed to delete party: \(error.localizedDescription)")
                }
            }
        }
    }

    private func saveCompanySettings(_ updated: CompanyDetailsDto) {
        Task {
            do {
                let res = try await NetworkManager.shared.updateCompanyDetails(details: updated)
                await MainActor.run {
                    showToast("Company settings updated!")
                    self.companyDetails = res
                    showCompanySettingsDialog = false
                }
            } catch {
                await MainActor.run {
                    showToast("Failed to update settings: \(error.localizedDescription)")
                }
            }
        }
    }

    private func tagBankTx(bankTx: BankTransactionDto, voucherId: String?, category: String?, notes: String?) {
        guard let statement = bankStatements.first(where: { $0.transactions.contains(where: { $0.id == bankTx.id }) }),
              let stmtId = statement._id else {
            showToast("Statement record not found")
            return
        }

        let req = TagBankTransactionRequest(
            transactionId: bankTx.id,
            voucherId: voucherId,
            category: category,
            notes: notes
        )

        Task {
            do {
                _ = try await NetworkManager.shared.tagBankTransaction(statementId: stmtId, request: req)
                await MainActor.run {
                    showToast("Payment tagged & reconciled!")
                    taggingBankTx = nil
                    reloadAccountingData(silent: true)
                }
            } catch {
                await MainActor.run {
                    showToast("Tagging error: \(error.localizedDescription)")
                }
            }
        }
    }

    private func showToast(_ msg: String) {
        toastMessage = msg
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            if toastMessage == msg {
                toastMessage = nil
            }
        }
    }
}
