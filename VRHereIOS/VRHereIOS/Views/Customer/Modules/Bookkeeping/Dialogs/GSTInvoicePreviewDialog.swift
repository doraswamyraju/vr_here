import SwiftUI
import WebKit

public struct GSTInvoicePreviewDialog: View {
    public let transaction: TransactionDto
    public let companyDetails: CompanyDetailsDto?
    public let onDismiss: () -> Void

    public init(
        transaction: TransactionDto,
        companyDetails: CompanyDetailsDto?,
        onDismiss: @escaping () -> Void
    ) {
        self.transaction = transaction
        self.companyDetails = companyDetails
        self.onDismiss = onDismiss
    }

    private var htmlContent: String {
        InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: companyDetails)
    }

    public var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Top Action Bar
                HStack(spacing: 8) {
                    // WhatsApp Button
                    Button(action: {
                        InvoicePdfGenerator.sharePdf(transaction: transaction, company: companyDetails, targetWhatsApp: true)
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

                    // Share PDF Button
                    Button(action: {
                        InvoicePdfGenerator.sharePdf(transaction: transaction, company: companyDetails, targetWhatsApp: false)
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "square.and.arrow.up")
                                .font(.system(size: 11))
                            Text("Share PDF")
                                .font(.system(size: 11.5, weight: .bold))
                        }
                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                        .cornerRadius(8)
                    }

                    Spacer()

                    // Print / Save PDF Button
                    Button(action: {
                        InvoicePdfGenerator.printPdf(transaction: transaction, company: companyDetails)
                    }) {
                        HStack(spacing: 4) {
                            Image(systemName: "printer.fill")
                                .font(.system(size: 11))
                            Text("Print / Save")
                                .font(.system(size: 11.5, weight: .bold))
                        }
                        .foregroundColor(.white)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                        .background(Color(red: 79/255, green: 70/255, blue: 229/255))
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
                InvoiceWebView(html: htmlContent)
                    .edgesIgnoringSafeArea(.bottom)
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
        }
    }
}

// MARK: - WKWebView Representable for GST Invoice

struct InvoiceWebView: UIViewRepresentable {
    let html: String

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.isOpaque = false
        webView.backgroundColor = UIColor(red: 241/255, green: 245/255, blue: 249/255, alpha: 1.0)
        webView.scrollView.isScrollEnabled = true
        webView.scrollView.bounces = true
        return webView
    }

    func updateUIView(_ uiView: WKWebView, context: Context) {
        uiView.loadHTMLString(html, baseURL: URL(string: "https://vrhere.in/"))
    }
}
