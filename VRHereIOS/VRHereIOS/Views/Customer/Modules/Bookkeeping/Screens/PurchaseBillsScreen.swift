import SwiftUI

public struct PurchaseBillsScreen: View {
    public let purchaseTransactions: [TransactionDto]
    @Binding public var selectedStatusFilter: String
    @Binding public var searchQuery: String
    public let onCreateBill: () -> Void
    public let onViewBill: (TransactionDto) -> Void
    public let onDeleteBill: (TransactionDto) -> Void

    private var totalPurchases: Double { purchaseTransactions.reduce(0) { $0 + $1.summary.totalAmount } }
    private var totalItc: Double {
        purchaseTransactions.reduce(0) { $0 + $1.summary.totalCgst + $1.summary.totalSgst + $1.summary.totalIgst }
    }

    private var filtered: [TransactionDto] {
        purchaseTransactions.filter { tx in
            let statusMatch = selectedStatusFilter.caseInsensitiveCompare("All") == .orderedSame ||
                tx.paymentStatus.caseInsensitiveCompare(selectedStatusFilter) == .orderedSame ||
                (tx.status?.caseInsensitiveCompare(selectedStatusFilter) == .orderedSame)
            let searchMatch = searchQuery.trimmingCharacters(in: .whitespaces).isEmpty ||
                tx.docNumber.localizedCaseInsensitiveContains(searchQuery) ||
                tx.partyName.localizedCaseInsensitiveContains(searchQuery)
            return statusMatch && searchMatch
        }
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. KPI Summaries
            HStack(spacing: 10) {
                BookkeepingKPICard(
                    title: "Total Purchases",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalPurchases),
                    subtitle: "\(purchaseTransactions.count) Inward Bills Logged",
                    icon: "cart.fill",
                    accentColor: Color(red: 5/255, green: 150/255, blue: 105/255)
                )

                BookkeepingKPICard(
                    title: "ITC Claimable",
                    value: IndianCurrencyFormatter.formatNoDecimals(totalItc),
                    subtitle: "GSTR-2B Input Tax Credit",
                    icon: "checkmark.shield.fill",
                    accentColor: Color(red: 79/255, green: 70/255, blue: 229/255)
                )
            }

            // 2. Search & Create Button Bar
            HStack(spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .font(.system(size: 14))
                    TextField("Search bill / vendor...", text: $searchQuery)
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

                Button(action: onCreateBill) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 12, weight: .bold))
                        Text("New Bill")
                            .font(.system(size: 12, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .frame(height: 44)
                    .background(Color(red: 5/255, green: 150/255, blue: 105/255))
                    .cornerRadius(12)
                }
            }

            // 3. Status Filters Bar
            HStack(spacing: 6) {
                ForEach(["All", "Paid", "Pending", "Draft"], id: \.self) { status in
                    let isSel = selectedStatusFilter.caseInsensitiveCompare(status) == .orderedSame
                    Button(action: { selectedStatusFilter = status }) {
                        Text(status)
                            .font(.system(size: 11, weight: isSel ? .black : .bold))
                            .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(isSel ? Color(red: 5/255, green: 150/255, blue: 105/255) : Color.white)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(isSel ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                    }
                }
                Spacer()
            }

            // 4. Bills List
            if filtered.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "cart")
                        .font(.system(size: 30))
                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                    Text("No Purchase Bills Found")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Text("Tap 'New Bill' above to record vendor purchases.")
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
                            onView: { onViewBill(tx) },
                            onDelete: { onDeleteBill(tx) }
                        )
                    }
                }
            }
        }
    }
}
