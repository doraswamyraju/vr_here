import UIKit
import WebKit

public struct InvoicePdfGenerator {

    // MARK: - Core Web View PDF Generation

    @MainActor
    public static func generatePdfFromWebView(_ webView: WKWebView, completion: @escaping (Data?) -> Void) {
        webView.evaluateJavaScript("""
            ({
                width: Math.max(document.body.scrollWidth, document.documentElement.scrollWidth, 780),
                height: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight, 1050)
            })
        """) { result, _ in
            var w: CGFloat = 780
            var h: CGFloat = 1100
            if let dict = result as? [String: Any] {
                if let nw = dict["width"] as? NSNumber { w = max(CGFloat(nw.doubleValue), 780) }
                if let nh = dict["height"] as? NSNumber { h = max(CGFloat(nh.doubleValue), 1050) }
            } else {
                let size = webView.scrollView.contentSize
                w = max(size.width, 780)
                h = max(size.height, 1100)
            }

            let config = WKPDFConfiguration()
            config.rect = CGRect(x: 0, y: 0, width: w, height: h)

            webView.createPDF(configuration: config) { pdfResult in
                switch pdfResult {
                case .success(let data):
                    completion(data)
                case .failure(let err):
                    print("WKWebView createPDF failed: \(err), falling back to print formatter")
                    let fallback = generatePdfDataFromFormatter(webView.viewPrintFormatter())
                    completion(fallback)
                }
            }
        }
    }

    public static func generatePdfDataFromFormatter(_ formatter: UIPrintFormatter) -> Data? {
        let renderer = UIPrintPageRenderer()
        renderer.addPrintFormatter(formatter, startingAtPageAt: 0)

        // A4 Paper Dimensions at 72 dpi (595.2 x 841.8 points)
        let paperRect = CGRect(x: 0, y: 0, width: 595.2, height: 841.8)
        let printableRect = paperRect.insetBy(dx: 15, dy: 15)

        renderer.setValue(NSValue(cgRect: paperRect), forKey: "paperRect")
        renderer.setValue(NSValue(cgRect: printableRect), forKey: "printableRect")
        renderer.prepare(forDrawingPages: NSRange(location: 0, length: renderer.numberOfPages))

        let pdfData = NSMutableData()
        UIGraphicsBeginPDFContextToData(pdfData, paperRect, nil)

        for i in 0..<renderer.numberOfPages {
            UIGraphicsBeginPDFPage()
            renderer.drawPage(at: i, in: UIGraphicsGetPDFContextBounds())
        }

        UIGraphicsEndPDFContext()
        return pdfData as Data
    }

    // Image URI cache to avoid re-downloading across calls
    private static var imageCache: [String: String] = [:]

    public static func convertUrlToBase64DataUri(_ urlString: String?, timeout: TimeInterval = 4.0) -> String? {
        guard let str = urlString?.trimmingCharacters(in: .whitespacesAndNewlines), !str.isEmpty else {
            return nil
        }
        if str.hasPrefix("data:image/") {
            return str
        }
        if let cached = imageCache[str] {
            return cached
        }
        guard let url = URL(string: str), let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            return nil
        }

        var resultDataUri: String? = nil
        let semaphore = DispatchSemaphore(value: 0)
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout

        URLSession.shared.dataTask(with: request) { data, response, error in
            defer { semaphore.signal() }
            guard let data = data, error == nil, !data.isEmpty else { return }
            let mimeType: String
            if let httpResponse = response as? HTTPURLResponse, let mime = httpResponse.mimeType, !mime.isEmpty {
                mimeType = mime
            } else if str.lowercased().hasSuffix(".png") {
                mimeType = "image/png"
            } else if str.lowercased().hasSuffix(".svg") {
                mimeType = "image/svg+xml"
            } else {
                mimeType = "image/jpeg"
            }
            let uri = "data:\(mimeType);base64,\(data.base64EncodedString())"
            resultDataUri = uri
            DispatchQueue.global(qos: .utility).async {
                imageCache[str] = uri
            }
        }.resume()

        _ = semaphore.wait(timeout: .now() + timeout)
        return resultDataUri
    }

    public static func prepareResolvedCompany(company: CompanyDetailsDto?) -> CompanyDetailsDto? {
        let effective = company ?? CompanyDetailsManager.cachedCompanyDetails
        guard var comp = effective else { return nil }

        if let logo = comp.logo, !logo.isEmpty, !logo.hasPrefix("data:") {
            if let base64Logo = convertUrlToBase64DataUri(logo) {
                comp.logo = base64Logo
            }
        }
        if let sig = comp.signature, !sig.isEmpty, !sig.hasPrefix("data:") {
            if let base64Sig = convertUrlToBase64DataUri(sig) {
                comp.signature = base64Sig
            }
        }
        if let qr = comp.qrCode, !qr.isEmpty, !qr.hasPrefix("data:") {
            if let base64Qr = convertUrlToBase64DataUri(qr) {
                comp.qrCode = base64Qr
            }
        }
        return comp
    }

    public static func generatePdf(
        from webView: WKWebView?,
        html: String,
        completion: @escaping (Data?) -> Void
    ) {
        DispatchQueue.main.async {
            if let wv = webView {
                generatePdfFromWebView(wv, completion: completion)
            } else {
                OffscreenInvoicePdfRenderer.shared.renderToPdf(html: html, completion: completion)
            }
        }
    }

    public static func downloadPdf(
        transaction: TransactionDto,
        company: CompanyDetailsDto?,
        webView: WKWebView? = nil
    ) {
        let resolvedCompany = prepareResolvedCompany(company: company)
        var resolvedTx = transaction
        if let att = transaction.attachmentUrl, !att.isEmpty, !att.hasPrefix("data:") {
            if let base64Att = convertUrlToBase64DataUri(att) {
                resolvedTx.attachmentUrl = base64Att
            }
        }

        let html = InvoiceHtmlBuilder.buildHtml(transaction: resolvedTx, company: resolvedCompany)

        generatePdf(from: webView, html: html) { data in
            guard let data = data else {
                print("Failed to generate PDF for download")
                return
            }

            let fileName = "\(transaction.docNumber.isEmpty ? "Invoice" : transaction.docNumber).pdf"
                .replacingOccurrences(of: "/", with: "-")
                .replacingOccurrences(of: " ", with: "_")
            let tempUrl = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)

            do {
                try data.write(to: tempUrl)
            } catch {
                print("Error writing PDF file: \(error)")
                return
            }

            DispatchQueue.main.async {
                guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                      let rootVC = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController else {
                    return
                }

                var topVC = rootVC
                while let presented = topVC.presentedViewController {
                    topVC = presented
                }

                let activityVC = UIActivityViewController(activityItems: [tempUrl], applicationActivities: nil)
                if let popover = activityVC.popoverPresentationController {
                    popover.sourceView = topVC.view
                    popover.sourceRect = CGRect(x: topVC.view.bounds.midX, y: topVC.view.bounds.midY, width: 0, height: 0)
                    popover.permittedArrowDirections = []
                }
                topVC.present(activityVC, animated: true)
            }
        }
    }

    public static func sharePdf(
        transaction: TransactionDto,
        company: CompanyDetailsDto?,
        webView: WKWebView? = nil,
        targetWhatsApp: Bool = false
    ) {
        let total = transaction.summary.totalAmount > 0 ? transaction.summary.totalAmount : transaction.items.reduce(0) { $0 + $1.total }
        let msg = "Hello, here is the Tax Invoice \(transaction.docNumber) for \(transaction.partyName) amounting to \(IndianCurrencyFormatter.format(total))."

        // Copy invoice summary text to clipboard for convenient pasting in chat
        UIPasteboard.general.string = msg

        let resolvedCompany = prepareResolvedCompany(company: company)
        var resolvedTx = transaction
        if let att = transaction.attachmentUrl, !att.isEmpty, !att.hasPrefix("data:") {
            if let base64Att = convertUrlToBase64DataUri(att) {
                resolvedTx.attachmentUrl = base64Att
            }
        }

        let html = InvoiceHtmlBuilder.buildHtml(transaction: resolvedTx, company: resolvedCompany)

        generatePdf(from: webView, html: html) { data in
            guard let data = data else {
                print("Failed to generate PDF for sharing")
                return
            }

            let fileName = "\(transaction.docNumber.isEmpty ? "Invoice" : transaction.docNumber).pdf"
                .replacingOccurrences(of: "/", with: "-")
                .replacingOccurrences(of: " ", with: "_")
            let tempUrl = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)

            do {
                try data.write(to: tempUrl)
            } catch {
                print("Error writing PDF file: \(error)")
                return
            }

            DispatchQueue.main.async {
                guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                      let rootVC = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController else {
                    return
                }

                var topVC = rootVC
                while let presented = topVC.presentedViewController {
                    topVC = presented
                }

                // Passing ONLY [tempUrl] ensures messaging apps treat this as a document
                let activityVC = UIActivityViewController(activityItems: [tempUrl], applicationActivities: nil)
                activityVC.setValue("Tax Invoice - \(transaction.docNumber)", forKey: "subject")

                if let popover = activityVC.popoverPresentationController {
                    popover.sourceView = topVC.view
                    popover.sourceRect = CGRect(x: topVC.view.bounds.midX, y: topVC.view.bounds.midY, width: 0, height: 0)
                    popover.permittedArrowDirections = []
                }
                topVC.present(activityVC, animated: true)
            }
        }
    }

    public static func printPdf(
        transaction: TransactionDto,
        company: CompanyDetailsDto?,
        webView: WKWebView? = nil
    ) {
        DispatchQueue.main.async {
            let printController = UIPrintInteractionController.shared
            let printInfo = UIPrintInfo(dictionary: nil)
            printInfo.outputType = .general
            printInfo.jobName = transaction.docNumber.isEmpty ? "Tax Invoice" : transaction.docNumber
            printController.printInfo = printInfo

            if let wv = webView {
                printController.printFormatter = wv.viewPrintFormatter()
            } else {
                let resolvedCompany = prepareResolvedCompany(company: company)
                let html = InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: resolvedCompany)
                let formatter = UIMarkupTextPrintFormatter(markupText: html)
                formatter.perPageContentInsets = UIEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
                printController.printFormatter = formatter
            }

            printController.present(animated: true, completionHandler: nil)
        }
    }
}

// MARK: - Offscreen WKWebView PDF Renderer (Fallback when no on-screen preview exists)

@MainActor
final class OffscreenInvoicePdfRenderer: NSObject, WKNavigationDelegate {
    static let shared = OffscreenInvoicePdfRenderer()

    private var activeWebView: WKWebView?
    private var completionHandler: ((Data?) -> Void)?

    func renderToPdf(html: String, completion: @escaping (Data?) -> Void) {
        self.completionHandler = completion

        let config = WKWebViewConfiguration()
        let wv = WKWebView(frame: CGRect(x: 0, y: 0, width: 780, height: 1100), configuration: config)
        self.activeWebView = wv
        wv.navigationDelegate = self
        wv.loadHTMLString(html, baseURL: URL(string: "https://vrhere.in/"))
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Wait 0.35s for base64 images and WebKit paint cycle
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
            InvoicePdfGenerator.generatePdfFromWebView(webView) { [weak self] data in
                self?.finish(with: data)
            }
        }
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(with: nil)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(with: nil)
    }

    private func finish(with data: Data?) {
        let handler = self.completionHandler
        self.completionHandler = nil
        self.activeWebView?.navigationDelegate = nil
        self.activeWebView = nil
        handler?(data)
    }
}
