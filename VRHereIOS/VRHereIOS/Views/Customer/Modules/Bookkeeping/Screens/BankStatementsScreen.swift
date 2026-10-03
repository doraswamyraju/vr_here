import SwiftUI

public struct BankStatementsScreen: View {
    public let bankStatements: [BankStatementDto]
    @Binding public var selectedStatusFilter: String // "All", "Unreconciled", "Tagged"
    public let onUploadStatement: () -> Void
    public let onTagTransaction: (BankTransactionDto) -> Void

    private var allTransactions: [BankTransactionDto] {
        bankStatements.flatMap { $0.transactions }
    }

    private var unreconciledCount: Int {
        allTransactions.count { $0.reconciliationStatus.caseInsensitiveCompare("TAGGED") != .orderedSame }
    }

    private var taggedCount: Int {
        allTransactions.count { $0.reconciliationStatus.caseInsensitiveCompare("TAGGED") == .orderedSame }
    }

    private var latestBalance: Double {
        allTransactions.last?.balance ?? 0.0
    }

    private var filtered: [BankTransactionDto] {
        allTransactions.filter { tx in
            switch selectedStatusFilter.lowercased() {
            case "tagged":
                return tx.reconciliationStatus.caseInsensitiveCompare("TAGGED") == .orderedSame
            case "unreconciled":
                return tx.reconciliationStatus.caseInsensitiveCompare("TAGGED") != .orderedSame
            default:
                return true
            }
        }
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. KPI Summaries
            HStack(spacing: 10) {
                BookkeepingKPICard(
                    title: "Total Bank Balance",
                    value: IndianCurrencyFormatter.formatNoDecimals(latestBalance),
                    subtitle: "\(bankStatements.count) Connected Statements",
                    icon: "building.columns.fill",
                    accentColor: Color(red: 79/255, green: 70/255, blue: 229/255)
                )

                BookkeepingKPICard(
                    title: "Unreconciled Lines",
                    value: "\(unreconciledCount) Entries",
                    subtitle: "\(taggedCount) Tagged & Settled",
                    icon: "checkmark.circle.fill",
                    accentColor: unreconciledCount > 0 ? Color(red: 217/255, green: 119/255, blue: 6/255) : Color(red: 22/255, green: 163/255, blue: 74/255)
                )
            }

            // 2. Action Bar
            HStack {
                Text("Statement Ledger Lines")
                    .font(.system(size: 13.5, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                Spacer()
                Button(action: onUploadStatement) {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.badge.plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("Upload Statement")
                            .font(.system(size: 11.5, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                    .cornerRadius(10)
                }
            }

            // 3. Status Filter Chips
            HStack(spacing: 6) {
                ForEach(["All", "Unreconciled", "Tagged"], id: \.self) { s in
                    let isSel = selectedStatusFilter.caseInsensitiveCompare(s) == .orderedSame
                    Button(action: { selectedStatusFilter = s }) {
                        Text(s)
                            .font(.system(size: 11, weight: isSel ? .black : .bold))
                            .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color.white)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(isSel ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                }
                Spacer()
            }

            // 4. Ledger Entries List
            if filtered.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "building.columns")
                        .font(.system(size: 30))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No Bank Statement Transactions")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Upload your bank statement Excel/PDF to reconcile payments.")
                        .font(.system(size: 11))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                .frame(maxWidth: .infinity)
                .padding(28)
                .background(Color.white)
                .cornerRadius(14)
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )
            } else {
                VStack(spacing: 10) {
                    ForEach(filtered) { tx in
                        BankTransactionCard(
                            transaction: tx,
                            onTagClick: { onTagTransaction(tx) }
                        )
                    }
                }
            }
        }
    }
}
