import SwiftUI

struct UnifiedInvoiceItem: Identifiable {
    let id: String
    let orderId: String
    let invoiceNumber: String
    let serviceName: String
    let packageName: String
    let date: String
    let dueDate: String?
    let amount: Double
    let status: String
    let isPaid: Bool
    let canPayNow: Bool
    let directUrl: String
    let paymentId: String
}

struct CustomerInvoicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    var isEmbedded: Bool = false
    
    @Environment(\.openURL) private var openURL
    @State private var selectedInvoiceItem: UnifiedInvoiceItem? = nil
    @State private var showInvoiceModal = false
    
    private var unifiedInvoices: [UnifiedInvoiceItem] {
        var list: [UnifiedInvoiceItem] = []
        var processedKeys = Set<String>()
        
        // 1. Explicit milestone invoices from orders (e.g. INV-0310260001)
        for order in viewModel.orders {
            for inv in order.invoices {
                let invNum = !inv.invoiceNumber.isEmpty ? inv.invoiceNumber : "INV-\(String(inv.id.suffix(6)).uppercased())"
                let key = invNum.uppercased()
                if !processedKeys.contains(key) {
                    processedKeys.insert(key)
                    let isPaid = inv.status.lowercased() == "paid" || inv.status.lowercased() == "completed"
                    let canPay = !isPaid && inv.status.lowercased() != "cancelled" && inv.status.lowercased() != "draft"
                    
                    list.append(
                        UnifiedInvoiceItem(
                            id: !inv.id.isEmpty ? inv.id : "inv_\(order.id)_\(invNum)",
                            orderId: order.id,
                            invoiceNumber: invNum,
                            serviceName: order.serviceName,
                            packageName: order.packageName,
                            date: inv.createdAt.count >= 10 ? String(inv.createdAt.prefix(10)) : (order.createdAt.count >= 10 ? String(order.createdAt.prefix(10)) : "Recent"),
                            dueDate: inv.dueDate,
                            amount: inv.amount,
                            status: inv.status,
                            isPaid: isPaid,
                            canPayNow: canPay,
                            directUrl: inv.url ?? "",
                            paymentId: ""
                        )
                    )
                }
            }
        }
        
        // 2. Orders with unpaid balance and no separate milestone invoices
        for order in viewModel.orders {
            let hasMilestones = !order.invoices.isEmpty
            if !hasMilestones {
                let orderPayments = viewModel.payments.filter {
                    $0.orderId == order.id || $0.order?.id == order.id || ($0.paymentId == order.paymentId && !order.paymentId.isEmpty)
                }
                let paidForOrder = orderPayments.filter { $0.status == "Completed" || $0.status == "Paid" }.reduce(0.0) { $0 + $1.amount }
                let isOrderPaid = order.paymentStatus.lowercased() == "paid" || (!order.paymentId.isEmpty && paidForOrder >= order.price)
                let balance = isOrderPaid ? 0.0 : max(0.0, order.price - paidForOrder)
                let invNum = "INV-\(String(order.id.suffix(8)).uppercased())"
                
                if !isOrderPaid && balance > 0.0 && !processedKeys.contains(invNum.uppercased()) {
                    processedKeys.insert(invNum.uppercased())
                    list.append(
                        UnifiedInvoiceItem(
                            id: order.id,
                            orderId: order.id,
                            invoiceNumber: invNum,
                            serviceName: order.serviceName,
                            packageName: order.packageName,
                            date: order.createdAt.count >= 10 ? String(order.createdAt.prefix(10)) : "Recent",
                            dueDate: nil,
                            amount: balance,
                            status: paidForOrder > 0.0 ? "Partially Paid" : "Pending",
                            isPaid: false,
                            canPayNow: true,
                            directUrl: "",
                            paymentId: ""
                        )
                    )
                }
            }
        }
        
        // 3. All recorded payments (Paid / Completed receipts)
        for p in viewModel.payments {
            let invNum = "INV-\(String((p.paymentId.isEmpty ? p.id : p.paymentId).suffix(8)).uppercased())"
            let key = invNum.uppercased()
            if !processedKeys.contains(key) {
                processedKeys.insert(key)
                let isPaid = p.status == "Completed" || p.status == "Paid"
                list.append(
                    UnifiedInvoiceItem(
                        id: p.id,
                        orderId: p.orderId ?? p.order?.id ?? "",
                        invoiceNumber: invNum,
                        serviceName: !p.serviceName.isEmpty ? p.serviceName : (p.order?.serviceName ?? "Professional Compliance & Legal Services"),
                        packageName: !p.packageName.isEmpty ? p.packageName : "Standard Package",
                        date: p.createdAt.count >= 10 ? String(p.createdAt.prefix(10)) : "Recent",
                        dueDate: nil,
                        amount: p.amount,
                        status: isPaid ? "Paid" : p.status,
                        isPaid: isPaid,
                        canPayNow: !isPaid && p.status.lowercased() != "cancelled",
                        directUrl: p.invoiceUrl ?? "",
                        paymentId: p.paymentId
                    )
                )
            }
        }
        
        return list
    }
    
    private var totalSpent: Double {
        unifiedInvoices.filter { $0.isPaid }.reduce(0.0) { $0 + $1.amount }
    }
    
    var body: some View {
        ScrollView(showsIndicators: false) {
            VStack(alignment: .leading, spacing: 16) {
                if !isEmbedded {
                    // 1. HERO HEADER & GST BADGE
                    HStack(alignment: .center) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Billing & Invoices")
                                .font(.system(size: 22, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("View & download service estimates, proforma & GST tax invoices.")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        
                        Spacer()
                        
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.seal.fill")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                            Text("GST COMPLIANT")
                                .font(.system(size: 9.5, weight: .black))
                                .foregroundColor(Color(red: 4/255, green: 120/255, blue: 87/255))
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(Color(red: 236/255, green: 253/255, blue: 245/255))
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color(red: 167/255, green: 243/255, blue: 208/255), lineWidth: 1)
                        )
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 16)
                }
                
                // 2. FINANCIAL SUMMARY DARK CARD
                VStack(spacing: 16) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("TOTAL VERIFIED INVESTMENT")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                .tracking(0.5)
                            Text("₹\(Int(totalSpent))")
                                .font(.system(size: 28, weight: .black))
                                .foregroundColor(.white)
                        }
                        Spacer()
                        ZStack {
                            Circle()
                                .fill(Color.white.opacity(0.1))
                                .frame(width: 44, height: 44)
                            Image(systemName: "creditcard.fill")
                                .font(.system(size: 18))
                                .foregroundColor(Color(red: 52/255, green: 211/255, blue: 153/255))
                        }
                    }
                    
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("INVOICES & RECEIPTS")
                                .font(.system(size: 8.5, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Text("\(unifiedInvoices.count)")
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.white.opacity(0.05))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.white.opacity(0.1), lineWidth: 1)
                        )
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text("ACTIVE ORDERS")
                                .font(.system(size: 8.5, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Text("\(viewModel.orders.count)")
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(.white)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.white.opacity(0.05))
                        .cornerRadius(12)
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .stroke(Color.white.opacity(0.1), lineWidth: 1)
                        )
                    }
                }
                .padding(20)
                .background(
                    LinearGradient(
                        colors: [Color(red: 15/255, green: 23/255, blue: 42/255), Color(red: 30/255, green: 41/255, blue: 59/255)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .cornerRadius(24)
                .padding(.horizontal, 20)
                
                // 3. INVOICES LIST
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Invoices & Payment Records")
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Spacer()
                        Text("\(unifiedInvoices.count) Total")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    .padding(.horizontal, 20)
                    
                    if unifiedInvoices.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "doc.plaintext")
                                .font(.system(size: 40))
                                .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                            Text("No billing history yet")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Text("Your tax invoices will appear here once orders are initiated.")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(32)
                        .background(Color.white)
                        .cornerRadius(20)
                        .padding(.horizontal, 20)
                    } else {
                        LazyVStack(spacing: 12) {
                            ForEach(unifiedInvoices) { inv in
                                invoiceCard(invoice: inv)
                            }
                        }
                        .padding(.horizontal, 20)
                    }
                }
                
                Spacer().frame(height: 100)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255).ignoresSafeArea())
        .sheet(item: $selectedInvoiceItem) { item in
            GSTInvoicePreviewSheet(invoice: item)
        }
    }
    
    // MARK: - Invoice Card
    private func invoiceCard(invoice: UnifiedInvoiceItem) -> some View {
        let isPaid = invoice.isPaid
        let isCancelled = invoice.status.lowercased() == "cancelled"
        
        return VStack(alignment: .leading, spacing: 10) {
            // Header Tags
            HStack {
                HStack(spacing: 6) {
                    Text("TAX INVOICE")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(Color(red: 67/255, green: 56/255, blue: 202/255))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                        .cornerRadius(5)
                    
                    Text("#\(invoice.invoiceNumber)")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                
                Spacer()
                
                Text(invoice.status.uppercased())
                    .font(.system(size: 9, weight: .black))
                    .foregroundColor(isPaid ? Color(red: 4/255, green: 120/255, blue: 87/255) : (isCancelled ? Color(red: 190/255, green: 18/255, blue: 60/255) : Color(red: 180/255, green: 83/255, blue: 9/255)))
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2.5)
                    .background(isPaid ? Color(red: 209/255, green: 250/255, blue: 229/255) : (isCancelled ? Color(red: 254/255, green: 242/255, blue: 242/255) : Color(red: 254/255, green: 243/255, blue: 199/255)))
                    .cornerRadius(5)
            }
            
            // Service Name & Amount
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(invoice.serviceName)
                        .font(.system(size: 13, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    
                    Text("Date: \(invoice.date)\(invoice.dueDate != nil ? " • Due: \(invoice.dueDate!)" : "")")
                        .font(.system(size: 10.5))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                
                Spacer()
                
                Text("₹\(Int(invoice.amount))")
                    .font(.system(size: 16, weight: .black))
                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
            }
            
            Divider()
                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
            
            // Action Buttons
            HStack(spacing: 8) {
                Button(action: {
                    selectedInvoiceItem = invoice
                }) {
                    HStack(spacing: 4) {
                        Image(systemName: "doc.text.fill")
                            .font(.system(size: 10))
                        Text("GST Tax Invoice")
                            .font(.system(size: 10.5, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .frame(height: 34)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(10)
                }
                
                if !invoice.directUrl.isEmpty, let url = URL(string: invoice.directUrl) {
                    Button(action: { openURL(url) }) {
                        HStack(spacing: 4) {
                            Image(systemName: "arrow.down.circle")
                                .font(.system(size: 11))
                            Text("PDF")
                                .font(.system(size: 10.5, weight: .bold))
                        }
                        .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                        .padding(.horizontal, 10)
                        .frame(height: 34)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .cornerRadius(10)
                    }
                }
                
                if invoice.canPayNow {
                    Button(action: {
                        viewModel.initiateCheckout(
                            serviceName: invoice.serviceName.isEmpty ? "Statutory Compliance Service" : invoice.serviceName,
                            packageName: "Invoice #\(invoice.invoiceNumber)",
                            amount: invoice.amount
                        )
                    }) {
                        Text("Pay Now")
                            .font(.system(size: 10.5, weight: .black))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .frame(height: 34)
                            .background(Color.primaryRed)
                            .cornerRadius(10)
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
        .shadow(color: Color.black.opacity(0.02), radius: 4, x: 0, y: 2)
    }
}

// MARK: - A4 GST INVOICE PREVIEW SHEET
struct GSTInvoicePreviewSheet: View {
    let invoice: UnifiedInvoiceItem
    @Environment(\.presentationMode) private var presentationMode
    
    private var subtotal: Double {
        round(invoice.amount / 1.18)
    }
    
    private var totalTax: Double {
        invoice.amount - subtotal
    }
    
    private var cgst: Double {
        round(totalTax / 2.0)
    }
    
    private var sgst: Double {
        totalTax - cgst
    }
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // Document Content (A4 Printable Area)
                    VStack(alignment: .leading, spacing: 16) {
                        // 1. Header (VR HERE Brand & Invoice Type)
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 8) {
                                    Text("VR")
                                        .font(.system(size: 18, weight: .black))
                                        .foregroundColor(.white)
                                        .frame(width: 36, height: 36)
                                        .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .cornerRadius(8)
                                    
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text("VR HERE BUSINESS MANAGEMENT SOLUTIONS PRIVATE LIMITED")
                                            .font(.system(size: 11, weight: .black))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .fixedSize(horizontal: false, vertical: true)
                                        
                                        Text("TRADE NAME: VR HERE")
                                            .font(.system(size: 8.5, weight: .bold))
                                            .foregroundColor(Color(red: 79/255, green: 70/255, blue: 229/255))
                                    }
                                }
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati, Andhra Pradesh - 517501")
                                    Text("Helpline: +91 80085 30606 • Email: support@vrhere.in • Web: www.vrhere.in")
                                    Text("GSTIN: 37AAHCR7654E1Z8")
                                        .font(.system(size: 9.5, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .padding(.top, 2)
                                }
                                .font(.system(size: 8.5))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                .padding(.top, 4)
                            }
                            
                            Spacer()
                            
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("TAX INVOICE")
                                    .font(.system(size: 16, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text("#\(invoice.invoiceNumber)")
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                Text("Date: \(invoice.date)")
                                    .font(.system(size: 9.5, weight: .bold))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            }
                        }
                        .padding(.bottom, 12)
                        .overlay(
                            Rectangle()
                                .frame(height: 2)
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255)),
                            alignment: .bottom
                        )
                        
                        // 2. Bill To & Jurisdiction Box
                        HStack(alignment: .top, spacing: 16) {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("BILL TO:")
                                    .font(.system(size: 8.5, weight: .black))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                Text("Valued Business Client")
                                    .font(.system(size: 12, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text("Registered Customer Office")
                                    .font(.system(size: 9.5))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                Text("GSTIN: URP / N/A")
                                    .font(.system(size: 9.5, weight: .bold))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            }
                            
                            Spacer()
                            
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text("Place of Supply:")
                                        .font(.system(size: 8.5, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("Andhra Pradesh (37)")
                                        .font(.system(size: 9.5, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                                HStack {
                                    Text("Reverse Charge:")
                                        .font(.system(size: 8.5, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("No")
                                        .font(.system(size: 9.5, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                            }
                            .padding(10)
                            .frame(width: 180)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(8)
                        }
                        
                        // 3. Line Items Table
                        VStack(spacing: 0) {
                            HStack {
                                Text("Description")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text("SAC")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(width: 50, alignment: .center)
                                Text("Qty")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(width: 30, alignment: .center)
                                Text("Rate")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(width: 60, alignment: .trailing)
                                Text("GST")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(width: 40, alignment: .trailing)
                                Text("Amount")
                                    .font(.system(size: 9, weight: .black))
                                    .frame(width: 60, alignment: .trailing)
                            }
                            .padding(8)
                            .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                            .foregroundColor(.white)
                            .cornerRadius(6)
                            
                            HStack {
                                Text(invoice.serviceName)
                                    .font(.system(size: 10, weight: .bold))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text("998311")
                                    .font(.system(size: 9.5))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    .frame(width: 50, alignment: .center)
                                Text("1")
                                    .font(.system(size: 9.5, weight: .bold))
                                    .frame(width: 30, alignment: .center)
                                Text("₹\(Int(subtotal))")
                                    .font(.system(size: 9.5, weight: .bold))
                                    .frame(width: 60, alignment: .trailing)
                                Text("18%")
                                    .font(.system(size: 9.5))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    .frame(width: 40, alignment: .trailing)
                                Text("₹\(Int(subtotal))")
                                    .font(.system(size: 10, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    .frame(width: 60, alignment: .trailing)
                            }
                            .padding(.vertical, 10)
                            .padding(.horizontal, 8)
                        }
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                        )
                        
                        // 4. Financial Totals Breakdown
                        HStack {
                            Spacer()
                            VStack(spacing: 5) {
                                HStack {
                                    Text("Taxable Subtotal:")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("₹\(Int(subtotal))")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                                HStack {
                                    Text("CGST (9%):")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("₹\(Int(cgst))")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                                HStack {
                                    Text("SGST (9%):")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    Spacer()
                                    Text("₹\(Int(sgst))")
                                        .font(.system(size: 9.5, weight: .bold))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                                Divider()
                                HStack {
                                    Text("Total Amount (INR):")
                                        .font(.system(size: 11, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                    Spacer()
                                    Text("₹\(Int(invoice.amount))")
                                        .font(.system(size: 13, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                            }
                            .frame(width: 200)
                        }
                        .padding(.top, 8)
                        
                        // 5. Statutory Bank Details & Terms
                        VStack(alignment: .leading, spacing: 6) {
                            Text("BANK & SETTLEMENT DETAILS")
                                .font(.system(size: 8.5, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Text("Bank: HDFC Bank, Tirupati • A/C: 50200085306061 • IFSC: HDFC0001234 • UPI: vrhere@hdfcbank")
                                .font(.system(size: 8.5))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Text("Declaration: We declare that this invoice shows the actual price of the services described and that all particulars are true and correct.")
                                .font(.system(size: 7.5))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        .padding(10)
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .cornerRadius(8)
                        .padding(.top, 12)
                    }
                    .padding(20)
                    .background(Color.white)
                    .cornerRadius(16)
                    .shadow(color: Color.black.opacity(0.04), radius: 6, x: 0, y: 3)
                    .padding(16)
                }
            }
            .background(Color(red: 241/255, green: 245/255, blue: 249/255).ignoresSafeArea())
            .navigationTitle("GST Tax Invoice")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Close") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        printInvoice()
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "printer.fill")
                            Text("Print / PDF")
                        }
                        .font(.system(size: 12, weight: .bold))
                    }
                }
            }
        }
    }
    
    private func printInvoice() {
        #if os(iOS)
        let printController = UIPrintInteractionController.shared
        let printInfo = UIPrintInfo(dictionary: nil)
        printInfo.outputType = .general
        printInfo.jobName = "Invoice_\(invoice.invoiceNumber)"
        printController.printInfo = printInfo
        printController.present(animated: true, completionHandler: nil)
        #endif
    }
}
