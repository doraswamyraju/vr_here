import SwiftUI

public struct TransactionFormBottomSheet: View {
    public let transactionType: String // "Sales", "Purchase", "Expense", "Income"
    public let existingTransaction: TransactionDto?
    public let parties: [PartyDto]
    public let onDismiss: () -> Void
    public let onSubmit: (TransactionDto) -> Void
    public let onPartyCreated: ((PartyDto) -> Void)?

    @State private var localParties: [PartyDto] = []
    @State private var showPartySuggestions: Bool = false
    @State private var showAddPartySheet: Bool = false
    @State private var isSavingParty: Bool = false

    @State private var docNumber: String = ""
    @State private var docDate: String = ""
    @State private var dueDate: String = ""
    @State private var paymentMode: String = "Bank Transfer"
    @State private var paymentStatus: String = "Unpaid"

    // Party Details
    @State private var partyName: String = ""
    @State private var partyGstin: String = ""
    @State private var partyPan: String = ""
    @State private var partyAddress: String = ""
    @State private var partyPhone: String = ""
    @State private var placeOfSupply: String = "37-Andhra Pradesh"
    @State private var isInterstate: Bool = false
    @State private var itcEligibility: String = "N/A"

    // Line Items State
    @State private var items: [TransactionItemDto] = []

    public init(
        transactionType: String,
        existingTransaction: TransactionDto? = nil,
        parties: [PartyDto] = [],
        onDismiss: @escaping () -> Void,
        onSubmit: @escaping (TransactionDto) -> Void,
        onPartyCreated: ((PartyDto) -> Void)? = nil
    ) {
        self.transactionType = transactionType
        self.existingTransaction = existingTransaction
        self.parties = parties
        self._localParties = State(initialValue: parties)
        self.onDismiss = onDismiss
        self.onSubmit = onSubmit
        self.onPartyCreated = onPartyCreated
    }

    private let paymentModes = ["Bank Transfer", "UPI", "Cash", "Cheque", "Credit"]
    private let itcCategories = ["Inputs", "Input Services", "Capital Goods", "Ineligible"]

    private var calculatedItems: [TransactionItemDto] {
        items.map { item in
            let gross = item.qty * item.rate
            let disc = (gross * (item.discPercent ?? 0.0)) / 100.0
            let taxable = max(0.0, gross - disc)
            let taxRate = item.gstRate

            let cgst = !isInterstate ? (taxable * (taxRate / 2.0)) / 100.0 : 0.0
            let sgst = !isInterstate ? (taxable * (taxRate / 2.0)) / 100.0 : 0.0
            let igst = isInterstate ? (taxable * taxRate) / 100.0 : 0.0
            let total = taxable + cgst + sgst + igst

            var updated = item
            updated.taxableValue = taxable
            updated.cgst = cgst
            updated.sgst = sgst
            updated.igst = igst
            updated.total = total
            return updated
        }
    }

    private var totalTaxable: Double { calculatedItems.reduce(0) { $0 + $1.taxableValue } }
    private var totalCgst: Double { calculatedItems.reduce(0) { $0 + ($1.cgst ?? 0) } }
    private var totalSgst: Double { calculatedItems.reduce(0) { $0 + ($1.sgst ?? 0) } }
    private var totalIgst: Double { calculatedItems.reduce(0) { $0 + ($1.igst ?? 0) } }
    private var rawGrandTotal: Double { totalTaxable + totalCgst + totalSgst + totalIgst }
    private var grandTotalRounded: Double { round(rawGrandTotal) }
    private var roundOff: Double { grandTotalRounded - rawGrandTotal }

    private var matchingParties: [PartyDto] {
        let q = partyName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty {
            return localParties
        }
        return localParties.filter { p in
            p.name.lowercased().contains(q) ||
            (p.tradeName?.lowercased().contains(q) ?? false) ||
            (p.phone?.contains(q) ?? false) ||
            (p.gstin?.lowercased().contains(q) ?? false)
        }
    }

    private func selectParty(_ p: PartyDto) {
        partyName = p.name
        partyGstin = p.gstin ?? ""
        partyPan = p.pan ?? ""
        partyAddress = p.billingAddress ?? ""
        partyPhone = p.phone ?? ""
        if let st = p.state, !st.isEmpty {
            placeOfSupply = st.contains("-") ? st : "37-\(st)"
            if !st.localizedCaseInsensitiveContains("Andhra Pradesh") {
                isInterstate = true
            } else {
                isInterstate = false
            }
        }
        showPartySuggestions = false
    }

    private func saveNewPartyInline(_ party: PartyDto) {
        isSavingParty = true
        Task {
            do {
                let saved = try await NetworkManager.shared.createAccountingParty(party: party)
                await MainActor.run {
                    self.localParties.removeAll { $0._id == saved._id && saved._id != nil }
                    self.localParties.insert(saved, at: 0)
                    self.selectParty(saved)
                    self.isSavingParty = false
                    self.showAddPartySheet = false
                    self.onPartyCreated?(saved)
                }
            } catch {
                await MainActor.run {
                    self.localParties.insert(party, at: 0)
                    self.selectParty(party)
                    self.isSavingParty = false
                    self.showAddPartySheet = false
                    self.onPartyCreated?(party)
                }
            }
        }
    }

    public var body: some View {
        NavigationView {
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 16) {
                    // 1. Doc Number & Date
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Doc / Invoice #")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("INV-001", text: $docNumber)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Date (YYYY-MM-DD)")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("2026-09-30", text: $docDate)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    // 2. Party Name & Search / Suggest
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(transactionType == "Sales" ? "Customer Name *" : "Vendor / Payee Name *")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Spacer()
                            Button(action: {
                                showPartySuggestions = false
                                showAddPartySheet = true
                            }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "plus.circle.fill")
                                        .font(.system(size: 11))
                                    Text("+ Add New")
                                        .font(.system(size: 11, weight: .bold))
                                }
                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                            }
                        }

                        // Search Input Field
                        HStack(spacing: 8) {
                            Image(systemName: "magnifyingglass")
                                .font(.system(size: 13))
                                .foregroundColor(.secondary)

                            TextField(transactionType == "Sales" ? "Search customer or type new..." : "Search vendor or type new...", text: $partyName)
                                .textFieldStyle(PlainTextFieldStyle())
                                .font(.system(size: 13))
                                .onChange(of: partyName) { _ in
                                    showPartySuggestions = true
                                }
                                .onTapGesture {
                                    showPartySuggestions = true
                                }

                            if !partyName.isEmpty {
                                Button(action: {
                                    partyName = ""
                                    partyGstin = ""
                                    partyPan = ""
                                    partyAddress = ""
                                    partyPhone = ""
                                    showPartySuggestions = false
                                }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundColor(.secondary)
                                        .font(.system(size: 13))
                                }
                            }
                        }
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(showPartySuggestions ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                        )

                        // Quick Horizontal Pills (when suggestions closed or empty)
                        if !localParties.isEmpty && !showPartySuggestions {
                            ScrollView(.horizontal, showsIndicators: false) {
                                HStack(spacing: 6) {
                                    ForEach(localParties.prefix(4)) { p in
                                        Button(action: {
                                            selectParty(p)
                                        }) {
                                            HStack(spacing: 4) {
                                                Image(systemName: "building.2")
                                                    .font(.system(size: 9))
                                                Text(p.name)
                                                    .font(.system(size: 10.5, weight: .bold))
                                            }
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                            .cornerRadius(6)
                                        }
                                    }
                                }
                            }
                        }

                        // Suggestions Dropdown Panel
                        if showPartySuggestions {
                            VStack(alignment: .leading, spacing: 0) {
                                HStack {
                                    Text("Suggested Directory Parties (\(matchingParties.count))")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Button("Done") {
                                        showPartySuggestions = false
                                    }
                                    .font(.system(size: 10.5, weight: .bold))
                                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                }
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(Color(red: 241/255, green: 245/255, blue: 249/255))

                                if matchingParties.isEmpty {
                                    VStack(spacing: 6) {
                                        Text("No existing parties found for \"\(partyName)\"")
                                            .font(.system(size: 11.5))
                                            .foregroundColor(.secondary)
                                            .padding(.vertical, 8)
                                    }
                                    .frame(maxWidth: .infinity)
                                } else {
                                    ForEach(matchingParties.prefix(5)) { p in
                                        Button(action: {
                                            selectParty(p)
                                        }) {
                                            HStack(spacing: 10) {
                                                Image(systemName: "person.crop.square.fill")
                                                    .font(.system(size: 16))
                                                    .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))

                                                VStack(alignment: .leading, spacing: 2) {
                                                    HStack {
                                                        Text(p.name)
                                                            .font(.system(size: 12, weight: .bold))
                                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                                        if let tName = p.tradeName, !tName.isEmpty && tName != p.name {
                                                            Text("(\(tName))")
                                                                .font(.system(size: 10.5))
                                                                .foregroundColor(.secondary)
                                                        }
                                                    }
                                                    HStack(spacing: 6) {
                                                        if let g = p.gstin, !g.isEmpty {
                                                            Text("GST: \(g)")
                                                                .font(.system(size: 9.5, weight: .medium))
                                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                                        }
                                                        if let ph = p.phone, !ph.isEmpty {
                                                            Text("• \(ph)")
                                                                .font(.system(size: 9.5))
                                                                .foregroundColor(.secondary)
                                                        }
                                                    }
                                                }
                                                Spacer()
                                                Image(systemName: "arrow.up.left")
                                                    .font(.system(size: 11))
                                                    .foregroundColor(.secondary)
                                            }
                                            .padding(.horizontal, 10)
                                            .padding(.vertical, 8)
                                        }
                                        Divider()
                                    }
                                }

                                // "+ Add New Party" Action inside the suggestions panel
                                Button(action: {
                                    showPartySuggestions = false
                                    showAddPartySheet = true
                                }) {
                                    HStack(spacing: 8) {
                                        Image(systemName: "plus.circle.fill")
                                            .font(.system(size: 14))
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text(!partyName.trimmingCharacters(in: .whitespaces).isEmpty
                                                ? "Add \"\(partyName.trimmingCharacters(in: .whitespaces))\" as New Party"
                                                : "Add New \(transactionType == "Sales" ? "Customer" : "Party")")
                                                .font(.system(size: 11.5, weight: .bold))
                                                .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                            Text("Not in directory? Tap here to create and auto-select")
                                                .font(.system(size: 9.5))
                                                .foregroundColor(.secondary)
                                        }
                                        Spacer()
                                        Image(systemName: "chevron.right")
                                            .font(.system(size: 10, weight: .bold))
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                    }
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 10)
                                    .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                }
                            }
                            .background(Color.white)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.06), radius: 6, x: 0, y: 3)
                        }
                    }

                    // 3. GSTIN & Place of Supply
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("GSTIN (Optional)")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("37AAACS1429B1Z0", text: $partyGstin)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                                .textInputAutocapitalization(.characters)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Place of Supply")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            TextField("37-Andhra Pradesh", text: $placeOfSupply)
                                .textFieldStyle(RoundedBorderTextFieldStyle())
                        }
                    }

                    // 4. Interstate Toggle
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(isInterstate ? "Inter-State Supply (IGST)" : "Intra-State Supply (CGST + SGST)")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text(isInterstate ? "Single integrated tax applies" : "50/50 central & state tax split")
                                .font(.system(size: 10.5))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        Spacer()
                        Toggle("", isOn: $isInterstate)
                            .labelsHidden()
                            .tint(Color(red: 79/255, green: 70/255, blue: 229/255))
                    }
                    .padding(12)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(12)

                    // 5. Payment Mode & Status
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Payment Mode")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Picker("Mode", selection: $paymentMode) {
                                ForEach(paymentModes, id: \.self) { m in
                                    Text(m).tag(m)
                                }
                            }
                            .pickerStyle(MenuPickerStyle())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                        }

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Payment Status")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Picker("Status", selection: $paymentStatus) {
                                Text("Unpaid").tag("Unpaid")
                                Text("Paid").tag("Paid")
                                Text("Partially Paid").tag("Partially Paid")
                            }
                            .pickerStyle(MenuPickerStyle())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                        }
                    }

                    // 6. ITC Tagging (for Purchases)
                    if transactionType == "Purchase" {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("ITC Eligibility Category")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            HStack(spacing: 6) {
                                ForEach(itcCategories, id: \.self) { cat in
                                    let isSel = itcEligibility == cat
                                    Button(action: { itcEligibility = cat }) {
                                        Text(cat)
                                            .font(.system(size: 10.5, weight: .bold))
                                            .foregroundColor(isSel ? .white : Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 6)
                                            .background(isSel ? Color(red: 79/255, green: 70/255, blue: 229/255) : Color(red: 241/255, green: 245/255, blue: 249/255))
                                            .cornerRadius(8)
                                    }
                                }
                            }
                        }
                    }

                    // 7. Line Items Section
                    HStack {
                        Text("Line Items & Services")
                            .font(.system(size: 13, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Spacer()
                        Button(action: {
                            items.append(
                                TransactionItemDto(
                                    description: "Additional Item / Service",
                                    qty: 1.0,
                                    unit: "PCS",
                                    rate: 1000.0,
                                    gstRate: 18.0
                                )
                            )
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "plus")
                                    .font(.system(size: 10, weight: .bold))
                                Text("Add Item")
                                    .font(.system(size: 11, weight: .bold))
                            }
                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Color(red: 79/255, green: 70/255, blue: 229/255).opacity(0.12))
                            .cornerRadius(8)
                        }
                    }

                    ForEach(Array(items.enumerated()), id: \.offset) { index, item in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("Item #\(index + 1)")
                                    .font(.system(size: 11, weight: .black))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                Spacer()
                                if items.count > 1 {
                                    Button(action: { items.remove(at: index) }) {
                                        Image(systemName: "trash")
                                            .font(.system(size: 12))
                                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                    }
                                }
                            }

                            TextField("Item Description", text: Binding(
                                get: { items[index].description },
                                set: { items[index].description = $0 }
                            ))
                            .textFieldStyle(RoundedBorderTextFieldStyle())

                            HStack(spacing: 8) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Qty")
                                        .font(.system(size: 10))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    TextField("Qty", value: Binding(
                                        get: { items[index].qty },
                                        set: { items[index].qty = $0 }
                                    ), formatter: NumberFormatter())
                                    .keyboardType(.decimalPad)
                                    .textFieldStyle(RoundedBorderTextFieldStyle())
                                }

                                VStack(alignment: .leading, spacing: 2) {
                                    Text("Rate (₹)")
                                        .font(.system(size: 10))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    TextField("Rate", value: Binding(
                                        get: { items[index].rate },
                                        set: { items[index].rate = $0 }
                                    ), formatter: NumberFormatter())
                                    .keyboardType(.decimalPad)
                                    .textFieldStyle(RoundedBorderTextFieldStyle())
                                }

                                VStack(alignment: .leading, spacing: 2) {
                                    Text("GST %")
                                        .font(.system(size: 10))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    TextField("GST", value: Binding(
                                        get: { items[index].gstRate },
                                        set: { items[index].gstRate = $0 }
                                    ), formatter: NumberFormatter())
                                    .keyboardType(.decimalPad)
                                    .textFieldStyle(RoundedBorderTextFieldStyle())
                                }
                            }

                            if index < calculatedItems.count {
                                let calc = calculatedItems[index]
                                HStack {
                                    Text("Taxable: \(IndianCurrencyFormatter.format(calc.taxableValue))")
                                        .font(.system(size: 10.5))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("Total: \(IndianCurrencyFormatter.format(calc.total))")
                                        .font(.system(size: 11.5, weight: .bold))
                                        .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                }
                            }
                        }
                        .padding(12)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                        )
                    }

                    // 8. Totals Summary Card
                    VStack(spacing: 6) {
                        HStack {
                            Text("Taxable Subtotal")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Spacer()
                            Text(IndianCurrencyFormatter.format(totalTaxable))
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.white)
                        }

                        if !isInterstate {
                            HStack {
                                Text("CGST Total")
                                    .font(.system(size: 12))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Spacer()
                                Text(IndianCurrencyFormatter.format(totalCgst))
                                    .font(.system(size: 12))
                                    .foregroundColor(.white)
                            }
                            HStack {
                                Text("SGST Total")
                                    .font(.system(size: 12))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Spacer()
                                Text(IndianCurrencyFormatter.format(totalSgst))
                                    .font(.system(size: 12))
                                    .foregroundColor(.white)
                            }
                        } else {
                            HStack {
                                Text("IGST Total")
                                    .font(.system(size: 12))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Spacer()
                                Text(IndianCurrencyFormatter.format(totalIgst))
                                    .font(.system(size: 12))
                                    .foregroundColor(.white)
                            }
                        }

                        Divider().background(Color.white.opacity(0.2))

                        HStack {
                            Text("GRAND TOTAL")
                                .font(.system(size: 13, weight: .black))
                                .foregroundColor(.white)
                            Spacer()
                            Text(IndianCurrencyFormatter.format(grandTotalRounded))
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(Color(red: 129/255, green: 140/255, blue: 248/255))
                        }
                    }
                    .padding(14)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(14)

                    // Submit Button
                    Button(action: {
                        guard !partyName.trimmingCharacters(in: .whitespaces).isEmpty else { return }

                        let payload = TransactionDto(
                            _id: existingTransaction?._id,
                            transactionType: transactionType,
                            docNumber: docNumber,
                            docDate: docDate,
                            dueDate: dueDate.isEmpty ? nil : dueDate,
                            paymentMode: paymentMode,
                            partyName: partyName,
                            partyGstin: partyGstin,
                            partyPan: partyPan,
                            partyAddress: partyAddress,
                            partyPhone: partyPhone,
                            placeOfSupply: placeOfSupply,
                            isInterstate: isInterstate,
                            items: calculatedItems,
                            summary: TransactionSummaryDto(
                                totalTaxableValue: totalTaxable,
                                totalCgst: totalCgst,
                                totalSgst: totalSgst,
                                totalIgst: totalIgst,
                                roundOff: roundOff,
                                totalAmount: grandTotalRounded,
                                amountInWords: IndianCurrencyFormatter.numberToWords(grandTotalRounded)
                            ),
                            itcEligibility: itcEligibility,
                            paymentStatus: paymentStatus
                        )
                        onSubmit(payload)
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark")
                                .font(.system(size: 14, weight: .bold))
                            Text(existingTransaction != nil ? "Update \(transactionType) Voucher" : "Save & Record \(transactionType)")
                                .font(.system(size: 14, weight: .black))
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
            .navigationTitle("\(existingTransaction != nil ? "Edit" : "Create") \(transactionType)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cancel", action: onDismiss)
                }
            }
        }
        .sheet(isPresented: $showAddPartySheet) {
            PartyFormBottomSheet(
                initialName: partyName,
                initialPartyType: transactionType == "Sales" ? "Customer" : (transactionType == "Purchase" ? "Vendor" : "Both"),
                onDismiss: { showAddPartySheet = false },
                onSubmit: { newParty in
                    saveNewPartyInline(newParty)
                }
            )
        }
        .onAppear {
            if localParties.isEmpty {
                localParties = parties
            }
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd"
            let today = formatter.string(from: Date())

            if let existing = existingTransaction {
                docNumber = existing.docNumber
                docDate = String(existing.docDate.prefix(10))
                dueDate = existing.dueDate != nil ? String(existing.dueDate!.prefix(10)) : today
                paymentMode = existing.paymentMode
                paymentStatus = existing.paymentStatus
                partyName = existing.partyName
                partyGstin = existing.partyGstin ?? ""
                partyPan = existing.partyPan ?? ""
                partyAddress = existing.partyAddress ?? ""
                partyPhone = existing.partyPhone ?? ""
                placeOfSupply = existing.placeOfSupply ?? "37-Andhra Pradesh"
                isInterstate = existing.isInterstate ?? false
                itcEligibility = existing.itcEligibility ?? "N/A"
                items = existing.items.isEmpty ? [
                    TransactionItemDto(
                        description: transactionType == "Expense" ? "Office Operational Expense" : "Professional Business Services",
                        qty: 1.0,
                        unit: "PCS",
                        rate: 10000.0,
                        gstRate: 18.0
                    )
                ] : existing.items
            } else {
                let suffix = String(Int.random(in: 100000...999999))
                docNumber = whenPrefix() + suffix
                docDate = today
                dueDate = today
                itcEligibility = transactionType == "Purchase" ? "Inputs" : "N/A"
                items = [
                    TransactionItemDto(
                        description: transactionType == "Expense" ? "Office Operational Expense" : "Professional Business Services",
                        qty: 1.0,
                        unit: "PCS",
                        rate: 10000.0,
                        gstRate: 18.0
                    )
                ]
            }
        }
    }

    private func whenPrefix() -> String {
        switch transactionType {
        case "Sales": return "INV-"
        case "Purchase": return "PUR-"
        case "Expense": return "EXP-"
        default: return "INC-"
        }
    }
}
