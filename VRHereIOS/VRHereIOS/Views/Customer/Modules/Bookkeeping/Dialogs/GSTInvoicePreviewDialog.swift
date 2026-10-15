import SwiftUI
import WebKit

public struct GSTInvoicePreviewDialog: View {
    public let transaction: TransactionDto
    public let companyDetails: CompanyDetailsDto?
    public let onDismiss: () -> Void

    @State private var localCompanyDetails: CompanyDetailsDto? = nil
    @State private var toastMessage: String? = nil
    @State private var webView: WKWebView? = nil

    public init(
        transaction: TransactionDto,
        companyDetails: CompanyDetailsDto?,
        onDismiss: @escaping () -> Void
    ) {
        self.transaction = transaction
        self.companyDetails = companyDetails
        self.onDismiss = onDismiss
        self._localCompanyDetails = State(initialValue: companyDetails)
    }

    private var effectiveCompany: CompanyDetailsDto? {
        localCompanyDetails ?? companyDetails ?? CompanyDetailsManager.cachedCompanyDetails
    }

    private var htmlContent: String {
        InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: effectiveCompany)
    }

    public var body: some View {
        NavigationView {
            ZStack {
                VStack(spacing: 0) {
                    // Top Action Bar
                    HStack(spacing: 8) {
                        // WhatsApp Button
                        Button(action: {
                            showToast("PDF Invoice ready. Select WhatsApp to send.")
                            InvoicePdfGenerator.sharePdf(transaction: transaction, company: effectiveCompany, webView: webView, targetWhatsApp: true)
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "message.fill")
                                    .font(.system(size: 11))
                                Text("WhatsApp")
                                    .font(.system(size: 11.5, weight: .bold))
                            }
                            .foregroundColor(.white)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(Color(red: 5/255, green: 150/255, blue: 105/255))
                            .cornerRadius(8)
                        }

                        // Download PDF Button
                        Button(action: {
                            showToast("Preparing PDF download...")
                            InvoicePdfGenerator.downloadPdf(transaction: transaction, company: effectiveCompany, webView: webView)
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.down.circle.fill")
                                    .font(.system(size: 11))
                                Text("Download PDF")
                                    .font(.system(size: 11.5, weight: .bold))
                            }
                            .foregroundColor(.white)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(Color(red: 79/255, green: 70/255, blue: 229/255))
                            .cornerRadius(8)
                        }

                        // Share PDF Button
                        Button(action: {
                            showToast("Preparing PDF share...")
                            InvoicePdfGenerator.sharePdf(transaction: transaction, company: effectiveCompany, webView: webView, targetWhatsApp: false)
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "square.and.arrow.up")
                                    .font(.system(size: 11))
                                Text("Share")
                                    .font(.system(size: 11.5, weight: .bold))
                            }
                            .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 7)
                            .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                            .cornerRadius(8)
                        }

                        Spacer()

                        // Print Button
                        Button(action: {
                            InvoicePdfGenerator.printPdf(transaction: transaction, company: effectiveCompany, webView: webView)
                        }) {
                            Image(systemName: "printer.fill")
                                .font(.system(size: 13))
                                .foregroundColor(Color(red: 71/255, green: 85/255, blue: 105/255))
                                .padding(8)
                                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                .cornerRadius(8)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 10)
                    .background(Color.white)
                    .overlay(
                        Rectangle()
                            .frame(height: 1)
                            .foregroundColor(Color(red: 226/255, green: 232/255, blue: 240/255)),
                        alignment: .bottom
                    )

                    // Web View rendering the GST Invoice
                    InvoiceWebView(html: htmlContent, webView: $webView)
                        .edgesIgnoringSafeArea(.bottom)
                }

                // Toast Notice Overlay
                if let toast = toastMessage {
                    VStack {
                        Spacer()
                        Text(toast)
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)
                            .background(Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.92))
                            .cornerRadius(20)
                            .shadow(radius: 6)
                            .padding(.bottom, 24)
                    }
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .animation(.spring(), value: toastMessage)
                }
            }
            .navigationTitle(transaction.docNumber.isEmpty ? "GST Invoice Preview" : transaction.docNumber)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(action: onDismiss) {
                        HStack(spacing: 4) {
                            Image(systemName: "chevron.left")
                            Text("Back")
                        }
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                    }
                }
            }
            .onAppear {
                if localCompanyDetails == nil {
                    self.localCompanyDetails = companyDetails ?? CompanyDetailsManager.cachedCompanyDetails
                }
                Task {
                    if let comp = try? await NetworkManager.shared.getCompanyDetails() {
                        await MainActor.run {
                            self.localCompanyDetails = comp
                            CompanyDetailsManager.cachedCompanyDetails = comp
                        }
                    }
                }
            }
        }
    }

    private func showToast(_ msg: String) {
        toastMessage = msg
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            if toastMessage == msg {
                toastMessage = nil
            }
        }
    }
}

// MARK: - WKWebView Representable for GST Invoice

struct InvoiceWebView: UIViewRepresentable {
    let html: String
    @Binding var webView: WKWebView?

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let wv = WKWebView(frame: .zero, configuration: config)
        wv.isOpaque = false
        wv.backgroundColor = UIColor(red: 241/255, green: 245/255, blue: 249/255, alpha: 1.0)
        wv.scrollView.isScrollEnabled = true
        wv.scrollView.bounces = true
        DispatchQueue.main.async {
            self.webView = wv
        }
        return wv
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        DispatchQueue.main.async {
            if self.webView !== uiView {
                self.webView = uiView
            }
        }
        uiView.loadHTMLString(html, baseURL: URL(string: "https://vrhere.in/"))
    }
}
