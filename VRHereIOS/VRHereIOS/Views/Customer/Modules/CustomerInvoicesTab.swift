import SwiftUI

struct CustomerInvoicesTab: View {
    @ObservedObject var viewModel: CustomerDashboardViewModel
    var isEmbedded: Bool = false
    
    @Environment(\.openURL) private var openURL
    @State private var selectedPaymentForInvoice: PaymentResponse? = nil
    @State private var showInvoiceModal = false
    
    private var totalSpent: Double {
        viewModel.payments.filter { $0.status == "Completed" || $0.status == "Paid" }.reduce(0.0) { $0 + $1.amount }
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
                            Text("TRANSACTIONS")
                                .font(.system(size: 8.5, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Text("\(viewModel.payments.count)")
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
                .shadow(color: Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.15), radius: 10, y: 4)
                
                // 3. INVOICES & PAYMENT RECORDS SECTION
                HStack {
                    Text("Invoices & Payment Records")
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                    Spacer()
                    Text("\(viewModel.payments.count) Total")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                }
                .padding(.horizontal, 20)
                .padding(.top, 4)
                
                if viewModel.payments.isEmpty {
                    VStack(spacing: 12) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.system(size: 36))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        Text("No Billing Records Yet")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        Text("Invoices will appear here once your projects are initiated.")
                            .font(.system(size: 11))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 36)
                    .background(Color.white)
                    .cornerRadius(20)
                    .padding(.horizontal, 20)
                } else {
                    VStack(spacing: 12) {
                        ForEach(viewModel.payments) { pay in
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    HStack(spacing: 6) {
                                        Text("TAX INVOICE")
                                            .font(.system(size: 8.5, weight: .black))
                                            .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                            .padding(.horizontal, 6)
                                            .padding(.vertical, 2)
                                            .background(Color(red: 254/255, green: 242/255, blue: 242/255))
                                            .cornerRadius(4)
                                        
                                        Text("#\(pay.id.suffix(8).uppercased())")
                                            .font(.system(size: 11, weight: .bold))
                                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    }
                                    
                                    Spacer()
                                    
                                    let isCompleted = pay.status.lowercased() == "completed" || pay.status.lowercased() == "paid"
                                    Text(isCompleted ? "COMPLETED" : pay.status.uppercased())
                                        .font(.system(size: 9, weight: .black))
                                        .foregroundColor(isCompleted ? Color(red: 5/255, green: 150/255, blue: 105/255) : Color(red: 217/255, green: 119/255, blue: 6/255))
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 3)
                                        .background(isCompleted ? Color(red: 236/255, green: 253/255, blue: 245/255) : Color(red: 254/255, green: 243/255, blue: 199/255))
                                        .cornerRadius(6)
                                }
                                
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(pay.serviceName)
                                            .font(.system(size: 13.5, weight: .bold))
                                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                            .lineLimit(2)
                                        
                                        let dateDisplay = pay.createdAt.count >= 10 ? String(pay.createdAt.prefix(10)) : "2026-09-30"
                                        Text("Date: \(dateDisplay) • \(pay.method.isEmpty ? "Razorpay" : pay.method)")
                                            .font(.system(size: 10.5))
                                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                    }
                                    Spacer()
                                    Text("₹\(Int(pay.amount))")
                                        .font(.system(size: 16, weight: .black))
                                        .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                }
                                
                                Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                
                                HStack(spacing: 8) {
                                    Button(action: {
                                        selectedPaymentForInvoice = pay
                                        showInvoiceModal = true
                                    }) {
                                        HStack(spacing: 6) {
                                            Image(systemName: "doc.text.fill")
                                                .font(.system(size: 11))
                                            Text("GST Tax Invoice")
                                                .font(.system(size: 11.5, weight: .black))
                                        }
                                        .foregroundColor(.white)
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 9)
                                        .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                                        .cornerRadius(10)
                                    }
                                    .buttonStyle(ScaleOnPressButtonStyle())
                                    
                                    if let invUrl = pay.invoiceUrl, !invUrl.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                        Button(action: {
                                            if let url = getAbsoluteURL(path: invUrl) {
                                                openURL(url)
                                            }
                                        }) {
                                            Image(systemName: "arrow.down.doc.fill")
                                                .font(.system(size: 12))
                                                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
                                                .frame(width: 36, height: 36)
                                                .background(Color(red: 238/255, green: 242/255, blue: 255/255))
                                                .cornerRadius(10)
                                        }
                                        .buttonStyle(PlainButtonStyle())
                                    }
                                }
                            }
                            .padding(16)
                            .background(Color.white)
                            .cornerRadius(18)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18)
                                    .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                            )
                            .shadow(color: Color.black.opacity(0.02), radius: 4, y: 1)
                        }
                    }
                    .padding(.horizontal, 20)
                }
                
                Spacer().frame(height: 120)
            }
        }
        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
        .sheet(item: $selectedPaymentForInvoice) { pay in
            GSTInvoicePreviewSheet(payment: pay, onDismiss: { selectedPaymentForInvoice = nil })
        }
    }
}

// MARK: - GST TAX INVOICE PREVIEW SHEET (Standard Bookkeeping A4 Layout)

struct GSTInvoicePreviewSheet: View {
    let payment: PaymentResponse
    let onDismiss: () -> Void
    
    private var subtotal: Double {
        payment.amount / 1.18
    }
    private var taxAmount: Double {
        payment.amount - subtotal
    }
    private var cgst: Double {
        taxAmount / 2.0
    }
    private var sgst: Double {
        taxAmount / 2.0
    }
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    // 1. Tax Invoice Header Box
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("TAX INVOICE")
                                    .font(.system(size: 16, weight: .black))
                                    .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                                Text("Original for Recipient (Sec 31 CGST Act)")
                                    .font(.system(size: 9.5, weight: .bold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 2) {
                                Text("INV-#\(payment.id.suffix(6).uppercased())")
                                    .font(.system(size: 13, weight: .black))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text(payment.createdAt.count >= 10 ? String(payment.createdAt.prefix(10)) : "2026-09-30")
                                    .font(.system(size: 10, weight: .semibold))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                        }
                    }
                    .padding(14)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(12)
                    
                    // 2. Seller Details Box (VR HERE)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("SELLER / SERVICE PROVIDER")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        
                        Text("VR HERE BUSINESS MANAGEMENT SOLUTIONS PVT LTD")
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        Text("GSTIN: 37AAHCR7654E1Z8 | State: 37-Andhra Pradesh")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                        
                        Text("#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati - 517501")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        
                        Text("Helpline: +91 80085 30606 | Email: support@vrhere.in")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                    
                    // 3. Buyer / Customer Details Box
                    VStack(alignment: .leading, spacing: 6) {
                        Text("BILL TO / RECIPIENT")
                            .font(.system(size: 9, weight: .black))
                            .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        
                        Text(payment.customerName.isEmpty ? "Valued Client" : payment.customerName)
                            .font(.system(size: 12, weight: .black))
                            .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        if !payment.email.isEmpty {
                            Text("Email: \(payment.email)")
                                .font(.system(size: 10))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        }
                        
                        Text("Place of Supply: 37-Andhra Pradesh | Payment Mode: \(payment.method.isEmpty ? "Razorpay Online" : payment.method)")
                            .font(.system(size: 10))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                    
                    // 4. Line Items Table Box
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("ITEM DESCRIPTION")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Spacer()
                            Text("SAC")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            Spacer().frame(width: 40)
                            Text("AMOUNT")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        
                        Divider().background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(payment.serviceName)
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                                Text(payment.packageName.isEmpty ? "Standard Package" : payment.packageName)
                                    .font(.system(size: 10))
                                    .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            }
                            Spacer()
                            Text("998311")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                            Spacer().frame(width: 40)
                            Text("₹\(String(format: "%.2f", subtotal))")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        }
                    }
                    .padding(14)
                    .background(Color.white)
                    .cornerRadius(12)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(Color(red: 226/255, green: 232/255, blue: 240/255), lineWidth: 1)
                    )
                    
                    // 5. Tax Summary & Totals Breakdown Box
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Taxable Subtotal")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Spacer()
                            Text("₹\(String(format: "%.2f", subtotal))")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        }
                        
                        HStack {
                            Text("CGST (9.0%)")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Spacer()
                            Text("₹\(String(format: "%.2f", cgst))")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        }
                        
                        HStack {
                            Text("SGST (9.0%)")
                                .font(.system(size: 11))
                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                            Spacer()
                            Text("₹\(String(format: "%.2f", sgst))")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                        }
                        
                        Divider().background(Color(red: 226/255, green: 232/255, blue: 240/255))
                        
                        HStack {
                            Text("TOTAL AMOUNT PAID")
                                .font(.system(size: 12, weight: .black))
                                .foregroundColor(Color(red: 15/255, green: 23/255, blue: 42/255))
                            Spacer()
                            Text("₹\(String(format: "%.2f", payment.amount))")
                                .font(.system(size: 16, weight: .black))
                                .foregroundColor(Color(red: 220/255, green: 38/255, blue: 38/255))
                        }
                    }
                    .padding(14)
                    .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                    .cornerRadius(12)
                    
                    // 6. Action Button (Share / Print)
                    Button(action: {
                        let printInfo = UIPrintInfo(dictionary: nil)
                        printInfo.outputType = .general
                        printInfo.jobName = "Invoice_#\(payment.id.suffix(6))"
                        
                        let printController = UIPrintInteractionController.shared
                        printController.printInfo = printInfo
                        printController.printingItem = URL(string: "https://vrhere.in") // Native print trigger
                        printController.present(animated: true, completionHandler: nil)
                    }) {
                        HStack(spacing: 8) {
                            Image(systemName: "printer.fill")
                                .font(.system(size: 13))
                            Text("Print / Save GST Invoice PDF")
                                .font(.system(size: 12, weight: .black))
                        }
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                        .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                        .cornerRadius(12)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                    .padding(.top, 6)
                }
                .padding(20)
            }
            .navigationBarTitle("Tax Invoice", displayMode: .inline)
            .navigationBarItems(
                trailing: Button("Done") {
                    onDismiss()
                }
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(Color(red: 99/255, green: 102/255, blue: 241/255))
            )
        }
    }
}
