import SwiftUI

public struct TagPaymentBottomSheet: View {
    public let bankTransaction: BankTransactionDto
    public let openInvoicesOrBills: [TransactionDto]
    public let onDismiss: () -> Void
    public let onTagSubmitted: (_ voucherId: String?, _ category: String?, _ notes: String?) -> Void

    @State private var taggingMode: String = "Voucher" // "Voucher" or "Category"
    @State private var selectedVoucherId: String? = nil
    @State private var selectedCategory: String = ""
    @State private var notes: String = ""

    private var isCredit: Bool {
        bankTransaction.type.caseInsensitiveCompare("CREDIT") == .orderedSame
    }

    private var defaultCategories: [String] {
        if isCredit {
            return ["Direct Business Income", "Client Advance", "Interest Income", "Capital Infusion", "Tax Refund", "Other Receipts"]
        } else {
            return ["Office Space Rent", "Salaries & Wages", "Electricity & Utilities", "Software Subscriptions", "Travel & Conveyance", "Legal & Professional", "Bank Charges", "Petty Cash / Misc"]
        }
    }

    public init(
        bankTransaction: BankTransactionDto,
        openInvoicesOrBills: [TransactionDto],
        onDismiss: @escaping () -> Void,
        onTagSubmitted: @escaping (_ voucherId: String?, _ category: String?, _ notes: String?) -> Void
    ) {
        self.bankTransaction = bankTransaction
        self.openInvoicesOrBills = openInvoicesOrBills
        self.onDismiss = onDismiss
        self.onTagSubmitted = onTagSubmitted
    }

    public var body: some View {
        NavigationView {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 16) {
                    // Transaction Snippet Card
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(isCredit ? "CREDIT (Money In)" : "DEBIT (Money Out)")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(isCredit ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 220/255, green: 38/255, blue: 38/255))
                            Text(String(bankTransaction.date.prefix(10)))
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        Spacer()
                        Text(IndianCurrencyFormatter.format(bankTransaction.amount))
                            .font(.system(size: 17, weight: .black))
                            .foregroundColor(isCredit ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 220/255, green: 38/255, blue: 38/255))
                    }
                    .padding(14)
                    .background(isCredit ? Color(red: 220/255, green: 252/255, blue: 231/255).opacity(0.6) : Color(red: 254/255, green: 226/255, blue: 226/255).opacity(0.6))
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(isCredit ? Color(red: 134/255, green: 239/255, blue: 172/255) : Color(red: 252/255, green: 165/255, blue: 165/255), lineWidth: 1)
                    )

                    // Mode Toggle (Link to Voucher vs Direct Category Head)
                    HStack(spacing: 8) {
                        Button(action: { taggingMode = "Voucher" }) {
                            Text(isCredit ? "Link Sales Invoice" : "Link Purchase Bill")
                                .font(.system(size: 11.5, weight: .bold))
                                .foregroundColor(taggingMode == "Voucher" ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(taggingMode == "Voucher" ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                .cornerRadius(10)
                        }

                        Button(action: { taggingMode = "Category" }) {
                            Text("Direct Category Head")
                                .font(.system(size: 11.5, weight: .bold))
                                .foregroundColor(taggingMode == "Category" ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 10)
                                .background(taggingMode == "Category" ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                .cornerRadius(10)
                        }
                    }

                    // Option 1: Open Vouchers List
                    if taggingMode == "Voucher" {
                        Text(isCredit ? "Select Open Unpaid Invoice:" : "Select Open Unpaid Bill:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                        if openInvoicesOrBills.isEmpty {
                            Text("No open vouchers found. You can tag as a Direct Category Head.")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                .padding(.vertical, 8)
                        } else {
                            VStack(spacing: 8) {
                                ForEach(openInvoicesOrBills.prefix(5)) { v in
                                    let isSelected = selectedVoucherId == v.id
                                    Button(action: { selectedVoucherId = v.id }) {
                                        HStack {
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(v.docNumber)
                                                    .font(.system(size: 12.5, weight: .black))
                                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                Text(v.partyName)
                                                    .font(.system(size: 11))
                                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                            }
                                            Spacer()
                                            Text(IndianCurrencyFormatter.format(v.summary.totalAmount))
                                                .font(.system(size: 13, weight: .bold))
                                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                        }
                                        .padding(12)
                                        .background(isSelected ? Color(red: 238/255, green: 242/255, blue: 255/255) : Color.white)
                                        .cornerRadius(10)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 10)
                                                .stroke(isSelected ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                        )
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                        }
                    } else {
                        // Option 2: Category Selector
                        Text("Select Ledger Head:")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                        VStack(spacing: 6) {
                            ForEach(defaultCategories, id: \.self) { cat in
                                let isSel = selectedCategory == cat
                                Button(action: { selectedCategory = cat }) {
                                    Text(cat)
                                        .font(.system(size: 12, weight: isSel ? .bold : .medium))
                                        .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 10)
                                        .background(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 248/255, green: 250/255, blue: 252/255))
                                        .cornerRadius(8)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 8)
                                                .stroke(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                    }

                    // Notes
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Reconciliation Note (Optional)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        TextField("e.g. Paid via UPI reference", text: $notes)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                    }

                    // Confirm Button
                    Button(action: {
                        if taggingMode == "Voucher" && selectedVoucherId == nil && !openInvoicesOrBills.isEmpty {
                            return
                        }
                        onTagSubmitted(
                            taggingMode == "Voucher" ? selectedVoucherId : nil,
                            taggingMode == "Category" ? selectedCategory : nil,
                            notes.isEmpty ? nil : notes
                        )
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "link")
                                .font(.system(size: 14, weight: .bold))
                            Text("Confirm & Reconcile Payment")
                                .font(.system(size: 13.5, weight: .bold))
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                        .cornerRadius(12)
                    }

                    Spacer().frame(height: 20)
                }
                .padding(20)
            }
            .navigationTitle("Tag Bank Transaction")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel", action: onDismiss)
                }
            }
        }
        .onAppear {
            selectedCategory = isCredit ? "Direct Business Income" : "Office Space Rent"
        }
    }
}
