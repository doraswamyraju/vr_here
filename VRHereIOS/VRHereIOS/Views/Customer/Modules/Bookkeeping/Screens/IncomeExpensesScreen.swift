import SwiftUI

public struct IncomeExpensesScreen: View {
    public let expenseTransactions: [TransactionDto]
    @Binding public var selectedTypeFilter: String
    @Binding public var searchQuery: String
    public let onCreateExpense: () -> Void
    public let onViewExpense: (TransactionDto) -> Void
    public let onDeleteExpense: (TransactionDto) -> Void

    private var expensesList: [TransactionDto] {
        expenseTransactions.filter { $0.transactionType.caseInsensitiveCompare("Expense") == .orderedSame }
    }
    private var incomeList: [TransactionDto] {
        expenseTransactions.filter { $0.transactionType.caseInsensitiveCompare("Income") == .orderedSame }
    }

    private var totalExpenses: Double { expensesList.reduce(0) { $0 + $1.summary.totalAmount } }
    private var totalIncome: Double { incomeList.reduce(0) { $0 + $1.summary.totalAmount } }

    private var filtered: [TransactionDto] {
        expenseTransactions.filter { tx in
            let typeMatch = selectedTypeFilter.caseInsensitiveCompare("All") == .orderedSame ||
                tx.transactionType.caseInsensitiveCompare(selectedTypeFilter) == .orderedSame ||
                tx.paymentStatus.caseInsensitiveCompare(selectedTypeFilter) == .orderedSame
            let searchMatch = searchQuery.trimmingCharacters(in: .whitespaces).isEmpty ||
                tx.docNumber.localizedCaseInsensitiveContains(searchQuery) ||
                tx.partyName.localizedCaseInsensitiveContains(searchQuery)
            return typeMatch && searchMatch
        }
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. KPI Summaries
            HStack(spacing: 10) {
                BookkeepingKPICard(
                    title: "Operational Expenses",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalExpenses),
                    subtitle: "\(expensesList.count) Payment Vouchers",
                    icon: "arrow.down.right.circle.fill",
                    accentColor: Color(red: 217/255, green: 119/255, blue: 6/255)
                )

                BookkeepingKPICard(
                    title: "Other Income",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalIncome),
                    subtitle: "\(incomeList.count) Receipt Vouchers",
                    icon: "arrow.up.left.circle.fill",
                    accentColor: Color(red: 5/255, green: 150/255, blue: 105/255)
                )
            }

            // 2. Search & Create Button Bar
            HStack(spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .font(.system(size: 14))
                    TextField("Search voucher / head...", text: $searchQuery)
                        .font(.system(size: 13))
                }
                .padding(.horizontal, 12)
                .frame(height: 44)
                .background(Color.white)
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                )

                Button(action: onCreateExpense) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 12, weight: .bold))
                        Text("Add Voucher")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .frame(height: 44)
                    .background(Color(red: 217/255, green: 119/255, blue: 6/255))
                    .cornerRadius(12)
                }
            }

            // 3. Status Filters Bar
            HStack(spacing: 6) {
                ForEach(["All", "Expense", "Income", "Paid"], id: \.self) { type in
                    let isSel = selectedTypeFilter.caseInsensitiveCompare(type) == .orderedSame
                    Button(action: { selectedTypeFilter = type }) {
                        Text(type)
                            .font(.system(size: 11, weight: isSel ? .black : .bold))
                            .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(isSel ? Color(red: 217/255, green: 119/255, blue: 6/255) : Color.white)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(isSel ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                }
                Spacer()
            }

            // 4. Expense List
            if filtered.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "tray")
                        .font(.system(size: 30))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No Expense Vouchers Found")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Tap 'Add Voucher' above to record rent, utilities or petty cash.")
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
                        TransactionItemCard(
                            transaction: tx,
                            onView: { onViewExpense(tx) },
                            onDelete: { onDeleteExpense(tx) }
                        )
                    }
                }
            }
        }
    }
}
