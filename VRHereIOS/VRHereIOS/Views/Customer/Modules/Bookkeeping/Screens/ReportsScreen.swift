import SwiftUI

public struct ReportsScreen: View {
    public let transactions: [TransactionDto]
    public let selectedMonth: String

    private var salesTx: [TransactionDto] {
        transactions.filter { $0.transactionType.caseInsensitiveCompare("Sales") == .orderedSame }
    }
    private var purchaseTx: [TransactionDto] {
        transactions.filter { $0.transactionType.caseInsensitiveCompare("Purchase") == .orderedSame }
    }
    private var expenseTx: [TransactionDto] {
        transactions.filter { $0.transactionType.caseInsensitiveCompare("Expense") == .orderedSame }
    }
    private var otherIncomeTx: [TransactionDto] {
        transactions.filter { $0.transactionType.caseInsensitiveCompare("Income") == .orderedSame }
    }

    private var totalSalesRevenue: Double { salesTx.reduce(0) { $0 + $1.summary.totalTaxableValue } }
    private var totalOtherIncome: Double { otherIncomeTx.reduce(0) { $0 + $1.summary.totalTaxableValue } }
    private var totalIncome: Double { totalSalesRevenue + totalOtherIncome }

    private var totalPurchasesCost: Double { purchaseTx.reduce(0) { $0 + $1.summary.totalTaxableValue } }
    private var totalOperationalExpenses: Double { expenseTx.reduce(0) { $0 + $1.summary.totalTaxableValue } }
    private var totalExpenses: Double { totalPurchasesCost + totalOperationalExpenses }

    private var netProfit: Double { totalIncome - totalExpenses }
    private var isProfitable: Bool { netProfit >= 0 }

    private var outputGst: Double {
        salesTx.reduce(0) { $0 + $1.summary.totalCgst + $1.summary.totalSgst + $1.summary.totalIgst }
    }
    private var inputItc: Double {
        purchaseTx.reduce(0) { $0 + $1.summary.totalCgst + $1.summary.totalSgst + $1.summary.totalIgst }
    }
    private var netGstPayable: Double { max(0.0, outputGst - inputItc) }

    public init(transactions: [TransactionDto], selectedMonth: String) {
        self.transactions = transactions
        self.selectedMonth = selectedMonth
    }

    public var body: some View {
        VStack(spacing: 14) {
            // 1. Profit & Loss Summary Card
            VStack(spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("PROFIT & LOSS STATEMENT")
                            .font(.system(size: 11, weight: .black))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            .tracking(1)
                        Text(selectedMonth)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                    }
                    Spacer()
                    Text(isProfitable ? "NET PROFIT" : "NET LOSS")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(isProfitable ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 220/255, green: 38/255, blue: 38/255))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(isProfitable ? Color(red: 220/255, green: 252/255, blue: 231/255) : Color(red: 254/255, green: 226/255, blue: 226/255))
                        .cornerRadius(20)
                }

                Divider().background(Color.white.opacity(0.15))

                // Breakdown Rows
                HStack {
                    Text("Total Revenue (Sales + Other Income)")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                    Spacer()
                    Text(IndianCurrencyFormatter.format(totalIncome))
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.white)
                }

                HStack {
                    Text("Total Cost & Expenses (Purchases + OpEx)")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                    Spacer()
                    Text(IndianCurrencyFormatter.format(totalExpenses))
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(.white)
                }

                Divider().background(Color.white.opacity(0.15))

                HStack {
                    Text("Estimated Net Margin")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.white)
                    Spacer()
                    Text(IndianCurrencyFormatter.format(netProfit))
                        .font(.system(size: 17, weight: .black))
                        .foregroundColor(isProfitable ? Color(red: 74/255, green: 222/255, blue: 128/255) : Color(red: 248/255, green: 113/255, blue: 113/255))
                }
            }
            .padding(18)
            .background(Color(red: 15/255, green: 23/255, blue: 42/255))
            .cornerRadius(16)

            // 2. GST Tax Computation Sheet
            VStack(spacing: 10) {
                Text("GST Tax Liability Summary")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .frame(maxWidth: .infinity, alignment: .leading)

                HStack {
                    Text("Output Tax (GSTR-1 Sales)")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    Spacer()
                    Text(IndianCurrencyFormatter.format(outputGst))
                        .font(.system(size: 12.5, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                }

                HStack {
                    Text("Input Tax Credit (GSTR-2B Purchases)")
                        .font(.system(size: 12))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    Spacer()
                    Text("- \(IndianCurrencyFormatter.format(inputItc))")
                        .font(.system(size: 12.5, weight: .bold))
                        .foregroundColor(Color(red: 5/255, green: 150/255, blue: 105/255))
                }

                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))

                HStack {
                    Text("Net Tax Payable in Cash")
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                    Text(IndianCurrencyFormatter.format(netGstPayable))
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 239/255, green: 68/255, blue: 68/255))
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
        }
    }
}
