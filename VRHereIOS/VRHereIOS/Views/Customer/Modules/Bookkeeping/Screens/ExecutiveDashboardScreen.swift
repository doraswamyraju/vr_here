import SwiftUI

public struct ExecutiveDashboardScreen: View {
    public let transactions: [TransactionDto]
    public let bankStatements: [BankStatementDto]
    public let selectedMonth: String
    public let onNavigateTab: (String) -> Void
    public let onCreateSales: () -> Void
    public let onCreatePurchase: () -> Void
    public let onCreateExpense: () -> Void
    public let onViewTransaction: (TransactionDto) -> Void

    private var salesTx: [TransactionDto] { transactions.filter { $0.transactionType.caseInsensitiveCompare("Sales") == .orderedSame } }
    private var purchaseTx: [TransactionDto] { transactions.filter { $0.transactionType.caseInsensitiveCompare("Purchase") == .orderedSame } }
    private var expenseTx: [TransactionDto] { transactions.filter { $0.transactionType.caseInsensitiveCompare("Expense") == .orderedSame } }

    private var totalTurnover: Double { salesTx.reduce(0) { $0 + $1.summary.totalAmount } }
    private var totalPurchases: Double { purchaseTx.reduce(0) { $0 + $1.summary.totalAmount } }
    private var totalExpenses: Double { expenseTx.reduce(0) { $0 + $1.summary.totalAmount } }

    private var outputGst: Double { salesTx.reduce(0) { $0 + $1.summary.totalCgst + $1.summary.totalSgst + $1.summary.totalIgst } }
    private var inputItc: Double { purchaseTx.reduce(0) { $0 + $1.summary.totalCgst + $1.summary.totalSgst + $1.summary.totalIgst } }
    private var netGstPayable: Double { max(0.0, outputGst - inputItc) }

    public init(
        transactions: [TransactionDto],
        bankStatements: [BankStatementDto],
        selectedMonth: String,
        onNavigateTab: @escaping (String) -> Void,
        onCreateSales: @escaping () -> Void,
        onCreatePurchase: @escaping () -> Void,
        onCreateExpense: @escaping () -> Void,
        onViewTransaction: @escaping (TransactionDto) -> Void
    ) {
        self.transactions = transactions
        self.bankStatements = bankStatements
        self.selectedMonth = selectedMonth
        self.onNavigateTab = onNavigateTab
        self.onCreateSales = onCreateSales
        self.onCreatePurchase = onCreatePurchase
        self.onCreateExpense = onCreateExpense
        self.onViewTransaction = onViewTransaction
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. Quick Action Launchers
            HStack(spacing: 8) {
                Button(action: onCreateSales) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("+ Sales Inv")
                            .font(.system(size: 11.5, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                    .cornerRadius(12)
                }

                Button(action: onCreatePurchase) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("+ Bill")
                            .font(.system(size: 11.5, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color(red: 5/255, green: 150/255, blue: 105/255))
                    .cornerRadius(12)
                }

                Button(action: onCreateExpense) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("+ Expense")
                            .font(.system(size: 11.5, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(Color(red: 217/255, green: 119/255, blue: 6/255))
                    .cornerRadius(12)
                }
            }

            // 2. Executive KPI Grid (2x2)
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)], spacing: 10) {
                BookkeepingKPICard(
                    title: "Monthly Revenue",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalTurnover),
                    subtitle: "\(salesTx.count) Invoices in \(selectedMonth)",
                    icon: "chart.line.uptrend.xyaxis",
                    accentColor: Color(red: 79/255, green: 70/255, blue: 229/255)
                )

                BookkeepingKPICard(
                    title: "Net GST Liability",
                    value: IndianCurrencyFormatter.formatNoDecimals(netGstPayable),
                    subtitle: "Output: ₹\(Int(outputGst)) | ITC: ₹\(Int(inputItc))",
                    icon: "building.columns.fill",
                    accentColor: Color(red: 239/255, green: 68/255, blue: 68/255)
                )

                BookkeepingKPICard(
                    title: "Total Purchases",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalPurchases),
                    subtitle: "\(purchaseTx.count) Bills Logged",
                    icon: "cart.fill",
                    accentColor: Color(red: 5/255, green: 150/255, blue: 105/255)
                )

                BookkeepingKPICard(
                    title: "Operational Expenses",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalExpenses),
                    subtitle: "\(expenseTx.count) Vouchers Logged",
                    icon: "arrow.down.right.circle.fill",
                    accentColor: Color(red: 217/255, green: 119/255, blue: 6/255)
                )
            }

            // 3. Bank Account Snapshot
            Button(action: { onNavigateTab("Banking") }) {
                HStack {
                    HStack(spacing: 10) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10)
                                .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .frame(width: 36, height: 36)
                            Image(systemName: "building.columns.fill")
                                .font(.system(size: 16))
                                .foregroundColor(.white)
                        }

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Connected Bank Accounts")
                                .font(.system(size: 12.5, weight: .bold))
                                .foregroundColor(.white)
                            Text("\(bankStatements.count) Bank Statement Files Uploaded")
                                .font(.system(size: 10.5))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                    }

                    Spacer()

                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                }
                .padding(16)
                .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                .cornerRadius(16)
            }
            .buttonStyle(PlainButtonStyle())

            // 4. Recent Transactions Section
            HStack {
                Text("Recent Transactions")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                Spacer()
                Button(action: { onNavigateTab("Sales") }) {
                    Text("View All")
                        .font(.system(size: 11.5, weight: .bold))
                        .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                }
            }
            .padding(.top, 4)

            if transactions.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "doc.text")
                        .font(.system(size: 28))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No transactions in \(selectedMonth)")
                        .font(.system(size: 12.5, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Tap '+ Sales Inv' above to record your first transaction.")
                        .font(.system(size: 11))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                .frame(maxWidth: .infinity)
                .padding(24)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
            } else {
                VStack(spacing: 10) {
                    ForEach(transactions.prefix(6)) { tx in
                        TransactionItemCard(
                            transaction: tx,
                            onView: { onViewTransaction(tx) }
                        )
                    }
                }
            }
        }
    }
}
