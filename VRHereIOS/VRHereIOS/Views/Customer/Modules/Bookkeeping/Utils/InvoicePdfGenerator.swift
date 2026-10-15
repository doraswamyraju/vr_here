import UIKit
import WebKit

public struct InvoicePdfGenerator {

    public static func generatePdfData(html: String) -> Data? {
        let printFormatter = UIMarkupTextPrintFormatter(markupText: html)
        let renderer = UIPrintPageRenderer()
        renderer.addPrintFormatter(printFormatter, startingAtPageAt: 0)

        // A4 Paper Dimensions at 72 dpi (595.2 x 841.8 points)
        let paperRect = CGRect(x: 0, y: 0, width: 595.2, height: 841.8)
        let printableRect = paperRect.insetBy(dx: 20, dy: 20)

        renderer.setValue(NSValue(cgRect: paperRect), forKey: "paperRect")
        renderer.setValue(NSValue(cgRect: printableRect), forKey: "printableRect")

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

    public static func savePdfToTempFile(transaction: TransactionDto, company: CompanyDetailsDto?) -> URL? {
        let resolvedCompany = prepareResolvedCompany(company: company)
        var resolvedTx = transaction
        if let att = transaction.attachmentUrl, !att.isEmpty, !att.hasPrefix("data:") {
            if let base64Att = convertUrlToBase64DataUri(att) {
                resolvedTx.attachmentUrl = base64Att
            }
        }

        let html = InvoiceHtmlBuilder.buildHtml(transaction: resolvedTx, company: resolvedCompany)
        guard let data = generatePdfData(html: html) else { return nil }

        let fileName = "\(transaction.docNumber.isEmpty ? "Invoice" : transaction.docNumber).pdf"
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: " ", with: "_")
        let tempUrl = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)

        do {
            try data.write(to: tempUrl)
            return tempUrl
        } catch {
            print("Error writing PDF file: \(error)")
            return nil
        }
    }

    public static func downloadPdf(transaction: TransactionDto, company: CompanyDetailsDto?) {
        guard let fileUrl = savePdfToTempFile(transaction: transaction, company: company) else { return }

        DispatchQueue.main.async {
            guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let rootVC = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController else {
                return
            }

            var topVC = rootVC
            while let presented = topVC.presentedViewController {
                topVC = presented
            }

            let activityVC = UIActivityViewController(activityItems: [fileUrl], applicationActivities: nil)
            if let popover = activityVC.popoverPresentationController {
                popover.sourceView = topVC.view
                popover.sourceRect = CGRect(x: topVC.view.bounds.midX, y: topVC.view.bounds.midY, width: 0, height: 0)
                popover.permittedArrowDirections = []
            }
            topVC.present(activityVC, animated: true)
        }
    }

    public static func sharePdf(transaction: TransactionDto, company: CompanyDetailsDto?, targetWhatsApp: Bool = false) {
        guard let fileUrl = savePdfToTempFile(transaction: transaction, company: company) else { return }

        let total = transaction.summary.totalAmount > 0 ? transaction.summary.totalAmount : transaction.items.reduce(0) { $0 + $1.total }
        let msg = "Hello, here is the Tax Invoice \(transaction.docNumber) for \(transaction.partyName) amounting to \(IndianCurrencyFormatter.format(total))."

        // Copy invoice summary text to clipboard for convenient pasting in chat
        UIPasteboard.general.string = msg

        DispatchQueue.main.async {
            guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let rootVC = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController else {
                return
            }

            var topVC = rootVC
            while let presented = topVC.presentedViewController {
                topVC = presented
            }

            // CRITICAL: Passing ONLY [fileUrl] ensures WhatsApp and other messaging apps treat this as a document
            // and attach the actual .pdf file instead of discarding it for plain text.
            let activityVC = UIActivityViewController(activityItems: [fileUrl], applicationActivities: nil)
            activityVC.setValue("Tax Invoice - \(transaction.docNumber)", forKey: "subject")

            if let popover = activityVC.popoverPresentationController {
                popover.sourceView = topVC.view
                popover.sourceRect = CGRect(x: topVC.view.bounds.midX, y: topVC.view.bounds.midY, width: 0, height: 0)
                popover.permittedArrowDirections = []
            }
            topVC.present(activityVC, animated: true)
        }
    }

    public static func printPdf(transaction: TransactionDto, company: CompanyDetailsDto?) {
        let resolvedCompany = prepareResolvedCompany(company: company)
        let html = InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: resolvedCompany)

        DispatchQueue.main.async {
            let printController = UIPrintInteractionController.shared
            let printInfo = UIPrintInfo(dictionary: nil)
            printInfo.outputType = .general
            printInfo.jobName = transaction.docNumber.isEmpty ? "Tax Invoice" : transaction.docNumber
            printController.printInfo = printInfo

            let formatter = UIMarkupTextPrintFormatter(markupText: html)
            formatter.perPageContentInsets = UIEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
            printController.printFormatter = formatter

            printController.present(animated: true, completionHandler: nil)
        }
    }
}
