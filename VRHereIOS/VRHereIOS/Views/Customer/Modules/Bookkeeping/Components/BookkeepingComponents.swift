import SwiftUI

// MARK: - Bookkeeping KPI Card

public struct BookkeepingKPICard: View {
    public let title: String
    public let value: String
    public let subtitle: String
    public let icon: String
    public let accentColor: Color

    public init(
        title: String,
        value: String,
        subtitle: String,
        icon: String,
        accentColor: Color
    ) {
        self.title = title
        self.value = value
        self.subtitle = subtitle
        self.icon = icon
        self.accentColor = accentColor
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(accentColor.opacity(0.12))
                        .frame(width: 30, height: 30)
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(accentColor)
                }

                Text(title)
                    .font(.system(size: 10, weight: .black))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    .lineLimit(1)
            }

            Text(value)
                .font(.system(size: 17, weight: .black))
                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                .lineLimit(1)
                .minimumScaleFactor(0.8)

            Text(subtitle)
                .font(.system(size: 9.5, weight: .medium))
                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
}

// MARK: - Date & Financial Year Filter Bar

public struct BookkeepingDateFilterBar: View {
    public let financialYear: String
    @Binding public var selectedMonth: String
    public let monthsList: [String]

    public var body: some View {
        HStack(spacing: 8) {
            // Financial Year Badge
            HStack(spacing: 4) {
                Image(systemName: "calendar")
                    .font(.system(size: 11, weight: .bold))
                Text(financialYear)
                    .font(.system(size: 11, weight: .black))
            }
            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
            .cornerRadius(10)

            // Horizontal Scrollable Month Filter Chips
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(monthsList, id: \.self) { m in
                        let isSelected = selectedMonth.caseInsensitiveCompare(m) == .orderedSame
                        Button(action: { selectedMonth = m }) {
                            Text(m)
                                .font(.system(size: 11, weight: isSelected ? .black : .bold))
                                .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(isSelected ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color.white)
                                .cornerRadius(8)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(isSelected ? Color.clear : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                                )
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Transaction Item Card

public struct TransactionItemCard: View {
    public let transaction: TransactionDto
    public let onView: () -> Void
    public var onDelete: (() -> Void)? = nil

    private var isPaid: Bool {
        transaction.paymentStatus.caseInsensitiveCompare("Paid") == .orderedSame
    }

    private var statusBg: Color {
        isPaid ? Color(red: 220/255, green: 252/255, blue: 231/255) : Color(red: 254/255, green: 243/255, blue: 199/255)
    }

    private var statusText: Color {
        isPaid ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 217/255, green: 119/255, blue: 6/255)
    }

    private var totalAmount: Double {
        transaction.summary.totalAmount > 0 ? transaction.summary.totalAmount : transaction.items.reduce(0) { $0 + $1.total }
    }

    public var body: some View {
        Button(action: onView) {
            VStack(alignment: .leading, spacing: 10) {
                // Header Row: Doc Number + Status Badge
                HStack {
                    HStack(spacing: 6) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 6)
                                .fill(
                                    transaction.transactionType == "Sales" ? Color(red: 79/255, green: 70/255, blue: 229/255).opacity(0.12) :
                                    (transaction.transactionType == "Purchase" ? Color(red: 5/255, green: 150/255, blue: 105/255).opacity(0.12) : Color(red: 217/255, green: 119/255, blue: 6/255).opacity(0.12))
                                )
                                .frame(width: 24, height: 24)
                            Image(systemName: transaction.transactionType == "Sales" ? "doc.text.fill" : (transaction.transactionType == "Purchase" ? "cart.fill" : "arrow.down.right.circle.fill"))
                                .font(.system(size: 12))
                                .foregroundColor(
                                    transaction.transactionType == "Sales" ? Color(red: 79/255, green: 70/255, blue: 229/255) :
                                    (transaction.transactionType == "Purchase" ? Color(red: 5/255, green: 150/255, blue: 105/255) : Color(red: 217/255, green: 119/255, blue: 6/255))
                                )
                        }

                        Text(transaction.docNumber.isEmpty ? "Voucher" : transaction.docNumber)
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    }

                    Spacer()

                    Text(transaction.paymentStatus.isEmpty ? "Unpaid" : transaction.paymentStatus)
                        .font(.system(size: 9.5, weight: .black))
                        .foregroundColor(statusText)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(statusBg)
                        .cornerRadius(20)
                }

                // Party Name and GSTIN
                VStack(alignment: .leading, spacing: 2) {
                    Text(transaction.partyName.isEmpty ? "Cash / Direct" : transaction.partyName)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(1)

                    if let gstin = transaction.partyGstin, !gstin.isEmpty {
                        Text("GSTIN: \(gstin)")
                            .font(.system(size: 10.5))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                }

                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))

                // Footer Row: Date / Payment Mode & Total Amount + Actions
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(String(transaction.docDate.prefix(10)))
                            .font(.system(size: 10.5, weight: .medium))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        Text(transaction.paymentMode)
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                    }

                    Spacer()

                    HStack(spacing: 8) {
                        Text(IndianCurrencyFormatter.format(totalAmount))
                            .font(.system(size: 14.5, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))

                        // WhatsApp Share Action
                        Button(action: {
                            let msg = "Hello, here are details for \(transaction.docNumber):\nParty: \(transaction.partyName)\nAmount: \(IndianCurrencyFormatter.format(totalAmount))\nStatus: \(transaction.paymentStatus)\nThank you!"
                            if let url = URL(string: "whatsapp://send?text=\(msg.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")"),
                               UIApplication.shared.canOpenURL(url) {
                                UIApplication.shared.open(url)
                            }
                        }) {
                            ZStack {
                                Circle()
                                    .fill(Color(red: 34/255, green: 197/255, blue: 94/255).opacity(0.12))
                                    .frame(width: 28, height: 28)
                                Image(systemName: "square.and.arrow.up")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(Color(red: 22/255, green: 163/255, blue: 74/255))
                            }
                        }
                        .buttonStyle(PlainButtonStyle())

                        if let onDelete = onDelete {
                            Button(action: onDelete) {
                                ZStack {
                                    Circle()
                                        .fill(Color(red: 254/255, green: 226/255, blue: 226/255))
                                        .frame(width: 28, height: 28)
                                    Image(systemName: "trash")
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                }
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                }
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(16)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// MARK: - Party Item Card

public struct PartyItemCard: View {
    public let party: PartyDto
    public let onEdit: () -> Void
    public var onDelete: (() -> Void)? = nil

    private var isCustomer: Bool {
        party.partyType.caseInsensitiveCompare("Customer") == .orderedSame || party.partyType.caseInsensitiveCompare("Both") == .orderedSame
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(isCustomer ? Color(red: 220/255, green: 252/255, blue: 231/255) : Color(red: 219/255, green: 234/255, blue: 254/255))
                        .frame(width: 38, height: 38)
                    Image(systemName: isCustomer ? "person.crop.circle.badge.plus" : "building.2.fill")
                        .foregroundColor(isCustomer ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 37/255, green: 99/255, blue: 235/255))
                        .font(.system(size: 16))
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(party.name)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(1)

                    let trade = party.tradeName ?? ""
                    let gstin = party.gstin ?? ""
                    let subtext = !trade.isEmpty ? trade : (!gstin.isEmpty ? "GSTIN: \(gstin)" : (party.phone ?? ""))
                    Text(subtext)
                        .font(.system(size: 10.5))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        .lineLimit(1)
                }

                Spacer()

                Text(party.partyType.uppercased())
                    .font(.system(size: 8.5, weight: .black))
                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    .cornerRadius(6)
            }

            Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))

            // Quick Contact & Action Buttons
            HStack(spacing: 12) {
                if let phone = party.phone, !phone.isEmpty {
                    Button(action: {
                        let clean = phone.replacingOccurrences(of: " ", with: "")
                        if let url = URL(string: "tel:\(clean)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "phone.fill")
                                .font(.system(size: 10))
                            Text("Call")
                                .font(.system(size: 10.5, weight: .bold))
                        }
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    }
                    .buttonStyle(PlainButtonStyle())

                    Button(action: {
                        let clean = phone.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "+", with: "")
                        if let url = URL(string: "https://wa.me/\(clean)") {
                            UIApplication.shared.open(url)
                        }
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "message.fill")
                                .font(.system(size: 10))
                            Text("WhatsApp")
                                .font(.system(size: 10.5, weight: .bold))
                        }
                        .foregroundColor(Color(red: 22/255, green: 163/255, blue: 74/255))
                    }
                    .buttonStyle(PlainButtonStyle())
                }

                Spacer()

                Button(action: onEdit) {
                    HStack(spacing: 3) {
                        Image(systemName: "pencil")
                            .font(.system(size: 10))
                        Text("Edit")
                            .font(.system(size: 10.5, weight: .bold))
                    }
                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                }
                .buttonStyle(PlainButtonStyle())

                if let onDelete = onDelete {
                    Button(action: onDelete) {
                        Image(systemName: "trash")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
}

// MARK: - Bank Transaction Card

public struct BankTransactionCard: View {
    public let transaction: BankTransactionDto
    public let onTagClick: () -> Void

    private var isCredit: Bool {
        transaction.type.caseInsensitiveCompare("CREDIT") == .orderedSame
    }

    private var isTagged: Bool {
        transaction.reconciliationStatus.caseInsensitiveCompare("TAGGED") == .orderedSame
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(transaction.description)
                        .font(.system(size: 12.5, weight: .bold))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .lineLimit(2)

                    HStack(spacing: 6) {
                        Text(String(transaction.date.prefix(10)))
                            .font(.system(size: 10.5))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))

                        if let ref = transaction.referenceNo, !ref.isEmpty {
                            Text("• Ref: \(ref)")
                                .font(.system(size: 10.5))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                    }
                }

                Spacer()

                VStack(alignment: .trailing, spacing: 2) {
                    Text(isCredit ? "+ \(IndianCurrencyFormatter.format(transaction.amount))" : "- \(IndianCurrencyFormatter.format(transaction.amount))")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(isCredit ? Color(red: 22/255, green: 163/255, blue: 74/255) : Color(red: 220/255, green: 38/255, blue: 38/255))

                    Text("Bal: \(IndianCurrencyFormatter.format(transaction.balance))")
                        .font(.system(size: 9.5))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
            }

            Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))

            HStack {
                if isTagged {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 22/255, green: 163/255, blue: 74/255))
                        Text(transaction.taggedCategory?.isEmpty == false ? "Reconciled: \(transaction.taggedCategory!)" : "Reconciled")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(Color(red: 22/255, green: 163/255, blue: 74/255))
                    }
                } else {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 217/255, green: 119/255, blue: 6/255))
                        Text("Unreconciled")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(Color(red: 217/255, green: 119/255, blue: 6/255))
                    }
                }

                Spacer()

                Button(action: onTagClick) {
                    HStack(spacing: 4) {
                        Image(systemName: "link")
                            .font(.system(size: 10))
                        Text(isTagged ? "Re-tag" : "Tag & Reconcile")
                            .font(.system(size: 11, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(isTagged ? Color(red: 71/255, green: 85/255, blue: 105/255) : Color(red: 79/255, green: 70/255, blue: 229/255))
                    .cornerRadius(8)
                }
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(14)
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
        )
    }
}
