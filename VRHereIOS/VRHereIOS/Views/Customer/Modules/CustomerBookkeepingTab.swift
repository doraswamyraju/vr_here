import SwiftUI
import PhotosUI
import Contacts
import ContactsUI

// MARK: - Bookkeeping Models for Mobile

struct BookkeepingTransactionItem: Identifiable {
    let id: String
    let type: String // "Sales", "Purchase", "Expense", "Income"
    let docNumber: String
    let date: String
    let partyName: String
    let partyGstin: String
    let amount: Double
    let taxAmount: Double
    let status: String // "Paid", "Pending", "Overdue"
}

struct BookkeepingPartyItem: Identifiable {
    let id: String
    let name: String
    let type: String // "Customer" or "Vendor"
    let gstin: String
    let phone: String
    let balance: Double
}

struct BookkeepingPayrollItem: Identifiable {
    let id: String
    let employeeName: String
    let designation: String
    let baseSalary: Double
    let netSalary: Double
    let status: String
}

// MARK: - Main Bookkeeping Hub (iOS)

struct CustomerBookkeepingTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    
    @State private var selectedSubModule = "Dashboard"
    
    private let subModules = [
        ("Dashboard", "chart.bar.xaxis", "Overview"),
        ("Sales", "doc.plaintext.fill", "Sales Invoices"),
        ("Purchases", "cart.fill", "Purchase Bills"),
        ("Expenses", "arrow.down.right.circle.fill", "Income & Expense"),
        ("Bank", "building.columns.fill", "Bank Sync"),
        ("Parties", "person.2.fill", "Customers & Vendors"),
        ("Payroll", "person.3.fill", "Payroll & Staff"),
        ("Reports", "chart.pie.fill", "Reports & P&L")
    ]
    
    // Sample state data for offline/online synchronization
    @State private var sampleTransactions: [BookkeepingTransactionItem] = [
        BookkeepingTransactionItem(id: "1", type: "Sales", docNumber: "INV-2026-089", date: "15 Sep 2026", partyName: "Sri Krishna Enterprises", partyGstin: "37AAACS1429B1Z0", amount: 48500, taxAmount: 8730, status: "Paid"),
        BookkeepingTransactionItem(id: "2", type: "Sales", docNumber: "INV-2026-090", date: "12 Sep 2026", partyName: "Apex Digital Solutions", partyGstin: "37AABCA4589D1Z3", amount: 24000, taxAmount: 4320, status: "Pending"),
        BookkeepingTransactionItem(id: "3", type: "Purchase", docNumber: "PUR-2026-044", date: "10 Sep 2026", partyName: "Tirupati Hardware & Tech", partyGstin: "37ABCDF6789G1Z8", amount: 15600, taxAmount: 2808, status: "Paid"),
        BookkeepingTransactionItem(id: "4", type: "Expense", docNumber: "EXP-2026-012", date: "08 Sep 2026", partyName: "Office Cloud Servers AWS", partyGstin: "", amount: 6500, taxAmount: 0, status: "Paid"),
        BookkeepingTransactionItem(id: "5", type: "Purchase", docNumber: "PUR-2026-045", date: "05 Sep 2026", partyName: "Venkata Logistics Co", partyGstin: "37BCDEF1234H1Z2", amount: 8900, taxAmount: 1602, status: "Pending")
    ]
    
    @State private var sampleParties: [BookkeepingPartyItem] = [
        BookkeepingPartyItem(id: "1", name: "Sri Krishna Enterprises", type: "Customer", gstin: "37AAACS1429B1Z0", phone: "+91 9848022338", balance: 0),
        BookkeepingPartyItem(id: "2", name: "Apex Digital Solutions", type: "Customer", gstin: "37AABCA4589D1Z3", phone: "+91 9885011223", balance: 24000),
        BookkeepingPartyItem(id: "3", name: "Tirupati Hardware & Tech", type: "Vendor", gstin: "37ABCDF6789G1Z8", phone: "+91 9949033445", balance: 0),
        BookkeepingPartyItem(id: "4", name: "Venkata Logistics Co", type: "Vendor", gstin: "37BCDEF1234H1Z2", phone: "+91 9440055667", balance: 8900)
    ]
    
    @State private var samplePayroll: [BookkeepingPayrollItem] = [
        BookkeepingPayrollItem(id: "1", employeeName: "Vamsi Krishna", designation: "Accounts Executive", baseSalary: 35000, netSalary: 33200, status: "Processed"),
        BookkeepingPayrollItem(id: "2", employeeName: "Anusha Reddy", designation: "GST Compliance Associate", baseSalary: 28000, netSalary: 26600, status: "Processed"),
        BookkeepingPayrollItem(id: "3", employeeName: "Karthik Naidu", designation: "Field Executive", baseSalary: 20000, netSalary: 19000, status: "Processed")
    ]
    
    // Create Invoice Modal State
    @State private var showCreateInvoiceSheet = false
    @State private var newInvParty = ""
    @State private var newInvAmount = ""
    @State private var newInvGstRate = 18.0
    @State private var newInvType = "Sales"
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 18) {
                // Header
                VStack(alignment: .leading, spacing: 4) {
                    Text("Bookkeeping & AaaS")
                        .font(.system(size: 20, weight: .black))
                        .foregroundColor(.textDark)
                    Text("Accounting-as-a-Service portal: Invoices, GST, Bank Recon & Payroll.")
                        .font(.system(size: 12))
                        .foregroundColor(.textMuted)
                }
                .padding(.horizontal, 20)
                .padding(.top, 16)
                
                // Horizontal Sub-Module Tabs
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(subModules, id: \.0) { mod in
                            let isSelected = selectedSubModule == mod.0
                            Button(action: { selectedSubModule = mod.0 }) {
                                HStack(spacing: 6) {
                                    Image(systemName: mod.1)
                                        .font(.system(size: 12))
                                    Text(mod.2)
                                        .font(.system(size: 12, weight: isSelected ? .black : .bold))
                                }
                                .foregroundColor(isSelected ? .white : Color(red: 71/255, green: 85/255, blue: 105/255))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .background(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255) : Color.white)
                                .cornerRadius(12)
                                .shadow(color: Color.black.opacity(isSelected ? 0.15 : 0.03), radius: 4, y: 1)
                            }
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                // Content Switcher based on Sub-Module
                Group {
                    switch selectedSubModule {
                    case "Dashboard":
                        BookkeepingDashboardView(transactions: sampleTransactions)
                    case "Sales":
                        BookkeepingSalesView(
                            transactions: sampleTransactions.filter { $0.type == "Sales" },
                            onCreateNew: {
                                newInvType = "Sales"
                                showCreateInvoiceSheet = true
                            }
                        )
                    case "Purchases":
                        BookkeepingPurchasesView(
                            transactions: sampleTransactions.filter { $0.type == "Purchase" },
                            onCreateNew: {
                                newInvType = "Purchase"
                                showCreateInvoiceSheet = true
                            }
                        )
                    case "Expenses":
                        BookkeepingExpensesView(
                            transactions: sampleTransactions.filter { $0.type == "Expense" || $0.type == "Income" },
                            onCreateNew: {
                                newInvType = "Expense"
                                showCreateInvoiceSheet = true
                            }
                        )
                    case "Bank":
                        BookkeepingBankView()
                    case "Parties":
                        BookkeepingPartiesView(parties: sampleParties)
                    case "Payroll":
                        BookkeepingPayrollView(payroll: samplePayroll)
                    case "Reports":
                        BookkeepingReportsView(transactions: sampleTransactions)
                    default:
                        Text("Unknown module")
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
        .sheet(isPresented: $showCreateInvoiceSheet) {
            CreateInvoiceSheetView(
                invType: newInvType,
                partyName: $newInvParty,
                amount: $newInvAmount,
                gstRate: $newInvGstRate,
                onSave: {
                    let baseAmt = Double(newInvAmount) ?? 0
                    let taxAmt = baseAmt * (newInvGstRate / 100.0)
                    let newTx = BookkeepingTransactionItem(
                        id: UUID().uuidString,
                        type: newInvType,
                        docNumber: "\(newInvType.prefix(3).uppercased())-\(Int.random(in: 100...999))",
                        date: "Today",
                        partyName: newInvParty.isEmpty ? "Client" : newInvParty,
                        partyGstin: "37AAACS1429B1Z0",
                        amount: baseAmt,
                        taxAmount: taxAmt,
                        status: "Paid"
                    )
                    sampleTransactions.insert(newTx, at: 0)
                    showCreateInvoiceSheet = false
                    newInvParty = ""
                    newInvAmount = ""
                },
                onDismiss: { showCreateInvoiceSheet = false }
            )
        }
    }
}

// MARK: - Submodule Views

private struct BookkeepingDashboardView: View {
    let transactions: [BookkeepingTransactionItem]
    
    var totalSales: Double { transactions.filter { $0.type == "Sales" }.reduce(0) { $0 + $1.amount } }
    var totalPurchases: Double { transactions.filter { $0.type == "Purchase" }.reduce(0) { $0 + $1.amount } }
    var totalExpenses: Double { transactions.filter { $0.type == "Expense" }.reduce(0) { $0 + $1.amount } }
    var netProfit: Double { totalSales - totalPurchases - totalExpenses }
    
    var body: some View {
        VStack(spacing: 16) {
            // Financial KPI Cards
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                FinanceStatCard(title: "TOTAL REVENUE", value: "₹\(Int(totalSales))", icon: "arrow.up.circle.fill", color: .green)
                FinanceStatCard(title: "PURCHASES", value: "₹\(Int(totalPurchases))", icon: "cart.fill", color: .blue)
                FinanceStatCard(title: "EXPENSES", value: "₹\(Int(totalExpenses))", icon: "arrow.down.right.circle.fill", color: .orange)
                FinanceStatCard(title: "NET PROFIT", value: "₹\(Int(netProfit))", icon: "chart.line.uptrend.xyaxis", color: .purple)
            }
            .padding(.horizontal, 20)
            
            // Monthly Compliance Calendar Card
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "calendar.badge.clock")
                        .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    Text("Monthly Filing Compliance Matrix")
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.textDark)
                }
                
                VStack(spacing: 8) {
                    ComplianceDueRow(title: "GSTR-1 (Outward Supplies)", dueDate: "11th Every Month", status: "FILED")
                    ComplianceDueRow(title: "GSTR-3B (Summary Return)", dueDate: "20th Every Month", status: "UPCOMING")
                    ComplianceDueRow(title: "TDS Payment / Challan 281", dueDate: "7th Every Month", status: "FILED")
                    ComplianceDueRow(title: "Advance Tax Q2 Installment", dueDate: "15th September", status: "ACTIVE")
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .shadow(color: Color.black.opacity(0.03), radius: 6, y: 2)
            .padding(.horizontal, 20)
        }
    }
}

private struct BookkeepingSalesView: View {
    let transactions: [BookkeepingTransactionItem]
    let onCreateNew: () -> Void
    
    var body: some View {
        VStack(spacing: 14) {
            HStack {
                Text("Sales Invoices (\(transactions.count))")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: onCreateNew) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Create GST Invoice")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                    .cornerRadius(8)
                }
            }
            .padding(.horizontal, 20)
            
            VStack(spacing: 10) {
                ForEach(transactions) { tx in
                    TransactionCardRow(tx: tx)
                }
            }
            .padding(.horizontal, 20)
        }
    }
}

private struct BookkeepingPurchasesView: View {
    let transactions: [BookkeepingTransactionItem]
    let onCreateNew: () -> Void
    
    var body: some View {
        VStack(spacing: 14) {
            HStack {
                Text("Purchase Bills (\(transactions.count))")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: onCreateNew) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Record Purchase")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(8)
                }
            }
            .padding(.horizontal, 20)
            
            VStack(spacing: 10) {
                ForEach(transactions) { tx in
                    TransactionCardRow(tx: tx)
                }
            }
            .padding(.horizontal, 20)
        }
    }
}

private struct BookkeepingExpensesView: View {
    let transactions: [BookkeepingTransactionItem]
    let onCreateNew: () -> Void
    
    var body: some View {
        VStack(spacing: 14) {
            HStack {
                Text("Income & Expenses")
                    .font(.system(size: 14, weight: .black))
                    .foregroundColor(.textDark)
                Spacer()
                Button(action: onCreateNew) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Add Voucher")
                    }
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(Color.orange)
                    .cornerRadius(8)
                }
            }
            .padding(.horizontal, 20)
            
            VStack(spacing: 10) {
                ForEach(transactions) { tx in
                    TransactionCardRow(tx: tx)
                }
            }
            .padding(.horizontal, 20)
        }
    }
}

private struct BookkeepingBankView: View {
    var body: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Bank Statements & Auto-Reconciliation")
                    .font(.system(size: 15, weight: .black))
                    .foregroundColor(.textDark)
                Text("Upload Bank PDF/Excel statements to auto-match inward and outward entries.")
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
                
                Button(action: {}) {
                    HStack {
                        Image(systemName: "doc.badge.plus")
                        Text("Upload Bank Statement (PDF/CSV)")
                    }
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color(red: 99/255, green: 102/255, blue: 241/255))
                    .cornerRadius(12)
                }
            }
            .padding(16)
            .background(Color.white)
            .cornerRadius(18)
            .padding(.horizontal, 20)
        }
    }
}

private struct BookkeepingPartiesView: View {
    let parties: [BookkeepingPartyItem]
    @State private var partyList: [BookkeepingPartyItem] = []
    @State private var showContactPicker = false
    @State private var showNewPartyModal = false
    @State private var importedName = ""
    @State private var importedPhone = ""
    @State private var importedEmail = ""
    @State private var newPartyGstin = ""
    @State private var newPartyType = "Customer"
    @State private var toastMessage: String? = nil
    
    var body: some View {
        VStack(spacing: 12) {
            // Action Bar for Parties
            HStack(spacing: 10) {
                Button(action: {
                    showContactPicker = true
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "person.crop.circle.badge.plus")
                            .font(.system(size: 12))
                        Text("Import from Contacts")
                            .font(.system(size: 11.5, weight: .bold))
                    }
                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                    .cornerRadius(10)
                }
                .buttonStyle(PlainButtonStyle())
                
                Spacer()
                
                Button(action: {
                    importedName = ""
                    importedPhone = ""
                    importedEmail = ""
                    newPartyGstin = ""
                    showNewPartyModal = true
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                        Text("Add Party")
                    }
                    .font(.system(size: 11.5, weight: .black))
                    .foregroundColor(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(10)
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            }
            .padding(.horizontal, 20)
            
            let allParties = partyList.isEmpty ? parties : partyList
            
            ForEach(allParties) { p in
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 12) {
                        ZStack {
                            Circle()
                                .fill(p.type == "Customer" ? Color.green.opacity(0.12) : Color.blue.opacity(0.12))
                                .frame(width: 38, height: 38)
                            Image(systemName: p.type == "Customer" ? "person.crop.circle.badge.plus" : "building.2.fill")
                                .foregroundColor(p.type == "Customer" ? .green : .blue)
                        }
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.name)
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.textDark)
                            Text(p.gstin.isEmpty ? p.phone : "GSTIN: \(p.gstin)")
                                .font(.system(size: 10))
                                .foregroundColor(.textMuted)
                        }
                        Spacer()
                        
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(p.type.uppercased())
                                .font(.system(size: 8, weight: .black))
                                .foregroundColor(.gray)
                            Text(p.balance > 0 ? "₹\(Int(p.balance)) Due" : "Settled")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(p.balance > 0 ? .red : .green)
                        }
                    }
                    
                    Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                    
                    // Quick Action Micro Row
                    HStack(spacing: 12) {
                        if !p.phone.isEmpty {
                            Button(action: {
                                let clean = p.phone.replacingOccurrences(of: " ", with: "")
                                if let url = URL(string: "tel:\(clean)") {
                                    UIApplication.shared.open(url)
                                }
                            }) {
                                HStack(spacing: 4) {
                                    Image(systemName: "phone.fill")
                                        .font(.system(size: 10))
                                    Text("Call")
                                        .font(.system(size: 10, weight: .bold))
                                }
                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                        
                        Spacer()
                        
                        Button(action: {
                            exportPartyToContacts(party: p)
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "square.and.arrow.down.fill")
                                    .font(.system(size: 10))
                                Text("Save to Contacts")
                                    .font(.system(size: 10, weight: .bold))
                            }
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                        }
                        .buttonStyle(PlainButtonStyle())
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
        .padding(.horizontal, 20)
        .sheet(isPresented: $showContactPicker) {
            ContactPickerView(
                selectedName: $importedName,
                selectedPhone: $importedPhone,
                selectedEmail: $importedEmail,
                onSelected: {
                    showContactPicker = false
                    showNewPartyModal = true
                }
            )
        }
        .sheet(isPresented: $showNewPartyModal) {
            NavigationView {
                Form {
                    Section(header: Text("Party Details")) {
                        TextField("Full Name / Business Name", text: $importedName)
                        TextField("Phone Number", text: $importedPhone)
                        TextField("Email Address", text: $importedEmail)
                        TextField("GSTIN (Optional)", text: $newPartyGstin)
                        Picker("Party Role", selection: $newPartyType) {
                            Text("Customer").tag("Customer")
                            Text("Vendor").tag("Vendor")
                        }
                    }
                    
                    Section {
                        Button(action: {
                            guard !importedName.isEmpty else { return }
                            let newParty = BookkeepingPartyItem(
                                id: UUID().uuidString,
                                name: importedName,
                                type: newPartyType,
                                gstin: newPartyGstin,
                                phone: importedPhone,
                                balance: 0.0
                            )
                            if partyList.isEmpty {
                                partyList = parties
                            }
                            partyList.append(newParty)
                            showNewPartyModal = false
                        }) {
                            Text("Save Party")
                                .font(.system(size: 14, weight: .black))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity, alignment: .center)
                        }
                        .listRowBackground(Color(red: 15/255, green: 23/255, blue: 42/255))
                    }
                }
                .navigationTitle("Add Party")
                .navigationBarItems(trailing: Button("Cancel") { showNewPartyModal = false })
            }
        }
    }
    
    private func exportPartyToContacts(party: BookkeepingPartyItem) {
        let store = CNContactStore()
        store.requestAccess(for: .contacts) { granted, _ in
            guard granted else { return }
            let contact = CNMutableContact()
            contact.givenName = party.name
            contact.organizationName = party.name
            if !party.phone.isEmpty {
                contact.phoneNumbers = [CNLabeledValue(label: CNLabelWork, value: CNPhoneNumber(stringValue: party.phone))]
            }
            let req = CNSaveRequest()
            req.add(contact, toContainerWithIdentifier: nil)
            _ = try? store.execute(req)
        }
    }
}

// MARK: - Native Contact Picker Representable
struct ContactPickerView: UIViewControllerRepresentable {
    @Binding var selectedName: String
    @Binding var selectedPhone: String
    @Binding var selectedEmail: String
    var onSelected: () -> Void
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    func makeUIViewController(context: Context) -> CNContactPickerViewController {
        let picker = CNContactPickerViewController()
        picker.delegate = context.coordinator
        return picker
    }
    
    func updateUIViewController(_ uiViewController: CNContactPickerViewController, context: Context) {}
    
    class Coordinator: NSObject, CNContactPickerDelegate {
        var parent: ContactPickerView
        init(_ parent: ContactPickerView) { self.parent = parent }
        
        func contactPicker(_ picker: CNContactPickerViewController, didSelect contact: CNContact) {
            let fullName = "\(contact.givenName) \(contact.familyName)".trimmingCharacters(in: .whitespaces)
            let phone = contact.phoneNumbers.first?.value.stringValue ?? ""
            let email = (contact.emailAddresses.first?.value as String?) ?? ""
            
            DispatchQueue.main.async {
                self.parent.selectedName = fullName.isEmpty ? "Contact" : fullName
                self.parent.selectedPhone = phone
                self.parent.selectedEmail = email
                self.parent.onSelected()
            }
        }
    }
}

private struct BookkeepingPayrollView: View {
    let payroll: [BookkeepingPayrollItem]
    
    var body: some View {
        VStack(spacing: 10) {
            ForEach(payroll) { emp in
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill(Color(red: 238/255, green: 242/255, blue: 255/255))
                            .frame(width: 38, height: 38)
                        Image(systemName: "person.fill")
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                    
                    VStack(alignment: .leading, spacing: 2) {
                        Text(emp.employeeName)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.textDark)
                        Text(emp.designation)
                            .font(.system(size: 10))
                            .foregroundColor(.textMuted)
                    }
                    Spacer()
                    
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Net ₹\(Int(emp.netSalary))")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(.textDark)
                        Text(emp.status)
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(.green)
                    }
                }
                .padding(12)
                .background(Color.white)
                .cornerRadius(14)
            }
        }
        .padding(.horizontal, 20)
    }
}

private struct BookkeepingReportsView: View {
    let transactions: [BookkeepingTransactionItem]
    
    var body: some View {
        VStack(spacing: 12) {
            ReportActionCard(title: "Profit & Loss Statement (P&L)", desc: "Comprehensive FY 2025-26 revenue and expense breakdown", icon: "doc.text.fill")
            ReportActionCard(title: "GST Liability & Input Tax Credit (ITC)", desc: "CGST, SGST, and IGST computation sheet", icon: "percent")
            ReportActionCard(title: "Tally Prime & Zoho XML Export", desc: "1-Click journal & ledger export for chartered accountants", icon: "square.and.arrow.up.fill")
        }
        .padding(.horizontal, 20)
    }
}

// MARK: - Reusable Row Components

private struct FinanceStatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Image(systemName: icon)
                .foregroundColor(color)
            Text(title)
                .font(.system(size: 9, weight: .black))
                .foregroundColor(.secondary)
            Text(value)
                .font(.system(size: 18, weight: .black))
                .foregroundColor(.primary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.03), radius: 6, y: 2)
    }
}

private struct ComplianceDueRow: View {
    let title: String
    let dueDate: String
    let status: String
    
    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.textDark)
                Text("Due: \(dueDate)")
                    .font(.system(size: 10))
                    .foregroundColor(.textMuted)
            }
            Spacer()
            Text(status)
                .font(.system(size: 9, weight: .black))
                .foregroundColor(status == "FILED" ? .green : .orange)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(status == "FILED" ? Color.green.opacity(0.1) : Color.orange.opacity(0.1))
                .cornerRadius(6)
        }
        .padding(.vertical, 4)
    }
}

private struct TransactionCardRow: View {
    let tx: BookkeepingTransactionItem
    
    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(tx.docNumber)
                        .font(.system(size: 12, weight: .black))
                        .foregroundColor(.textDark)
                    Text("• \(tx.date)")
                        .font(.system(size: 10))
                        .foregroundColor(.textMuted)
                }
                Text(tx.partyName)
                    .font(.system(size: 11))
                    .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                    .lineLimit(1)
            }
            Spacer()
            
            VStack(alignment: .trailing, spacing: 2) {
                Text("₹\(Int(tx.amount + tx.taxAmount))")
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(tx.type == "Sales" ? .green : .textDark)
                Text(tx.status.uppercased())
                    .font(.system(size: 8, weight: .black))
                    .foregroundColor(tx.status == "Paid" ? .green : .orange)
            }
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(14)
        .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
    }
}

private struct ReportActionCard: View {
    let title: String
    let desc: String
    let icon: String
    
    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color(red: 238/255, green: 242/255, blue: 255/255))
                    .frame(width: 44, height: 44)
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
            }
            
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .black))
                    .foregroundColor(.textDark)
                Text(desc)
                    .font(.system(size: 11))
                    .foregroundColor(.textMuted)
            }
            Spacer()
            Image(systemName: "arrow.down.doc.fill")
                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.03), radius: 6, y: 2)
    }
}

private struct CreateInvoiceSheetView: View {
    let invType: String
    @Binding var partyName: String
    @Binding var amount: String
    @Binding var gstRate: Double
    let onSave: () -> Void
    let onDismiss: () -> Void
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Voucher Details")) {
                    TextField("Party / Customer Name", text: $partyName)
                    TextField("Base Amount (₹)", text: $amount)
                        .keyboardType(.numberPad)
                }
                
                Section(header: Text("GST Tax Rate")) {
                    Picker("GST Rate", selection: $gstRate) {
                        Text("0% (Exempt)").tag(0.0)
                        Text("5% GST").tag(5.0)
                        Text("12% GST").tag(12.0)
                        Text("18% GST (Standard)").tag(18.0)
                        Text("28% GST").tag(28.0)
                    }
                }
                
                Section {
                    Button(action: onSave) {
                        Text("Generate \(invType) Voucher")
                            .font(.system(size: 15, weight: .bold))
                            .frame(maxWidth: .infinity, alignment: .center)
                            .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                    }
                }
            }
            .navigationTitle("New \(invType)")
            .navigationBarItems(leading: Button("Cancel", action: onDismiss))
        }
    }
}
