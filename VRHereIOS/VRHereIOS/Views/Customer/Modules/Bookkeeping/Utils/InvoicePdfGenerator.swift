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

    public static func savePdfToTempFile(transaction: TransactionDto, company: CompanyDetailsDto?) -> URL? {
        let html = InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: company)
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

    public static func sharePdf(transaction: TransactionDto, company: CompanyDetailsDto?, targetWhatsApp: Bool = false) {
        guard let fileUrl = savePdfToTempFile(transaction: transaction, company: company) else { return }

        let total = transaction.summary.totalAmount > 0 ? transaction.summary.totalAmount : transaction.items.reduce(0) { $0 + $1.total }
        let msg = "Hello, here is the Tax Invoice \(transaction.docNumber) for \(transaction.partyName) amounting to \(IndianCurrencyFormatter.format(total))."

        DispatchQueue.main.async {
            guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let rootVC = windowScene.windows.first(where: { $0.isKeyWindow })?.rootViewController else {
                return
            }

            var topVC = rootVC
            while let presented = topVC.presentedViewController {
                topVC = presented
            }

            if targetWhatsApp {
                // If WhatsApp is installed, launch with text and prompt user
                let whatsappUrlString = "whatsapp://send?text=\(msg.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")"
                if let whatsappUrl = URL(string: whatsappUrlString), UIApplication.shared.canOpenURL(whatsappUrl) {
                    UIApplication.shared.open(whatsappUrl)
                    return
                }
            }

            let activityVC = UIActivityViewController(activityItems: [fileUrl, msg], applicationActivities: nil)
            if let popover = activityVC.popoverPresentationController {
                popover.sourceView = topVC.view
                popover.sourceRect = CGRect(x: topVC.view.bounds.midX, y: topVC.view.bounds.midY, width: 0, height: 0)
                popover.permittedArrowDirections = []
            }
            topVC.present(activityVC, animated: true)
        }
    }

    public static func printPdf(transaction: TransactionDto, company: CompanyDetailsDto?) {
        let html = InvoiceHtmlBuilder.buildHtml(transaction: transaction, company: company)

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
