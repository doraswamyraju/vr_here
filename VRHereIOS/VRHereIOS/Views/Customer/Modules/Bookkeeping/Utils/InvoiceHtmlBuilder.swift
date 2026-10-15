import Foundation
import UIKit
import CoreImage

public struct InvoiceHtmlBuilder {

    public static func generateQrCodeBase64(from string: String) -> String? {
        guard let data = string.data(using: .utf8),
              let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let outputImage = filter.outputImage else { return nil }

        let transform = CGAffineTransform(scaleX: 5.0, y: 5.0)
        let scaledImage = outputImage.transformed(by: transform)

        let context = CIContext()
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else { return nil }
        let uiImage = UIImage(cgImage: cgImage)
        guard let pngData = uiImage.pngData() else { return nil }
        return "data:image/png;base64," + pngData.base64EncodedString()
    }

    public static func buildHtml(transaction: TransactionDto, company: CompanyDetailsDto?) -> String {
        let effectiveCompany = company ?? CompanyDetailsManager.cachedCompanyDetails

        let isSales = transaction.transactionType.caseInsensitiveCompare("Sales") == .orderedSame
        let isPurchase = transaction.transactionType.caseInsensitiveCompare("Purchase") == .orderedSame
        let isIncome = transaction.transactionType.caseInsensitiveCompare("Income") == .orderedSame
        let isExpense = transaction.transactionType.caseInsensitiveCompare("Expense") == .orderedSame
        let isVoucher = isIncome || isExpense

        let copyType = (transaction.copyType?.isEmpty ?? true) ? "Original for Recipient" : transaction.copyType!
        let docNumber: String
        if !transaction.docNumber.isEmpty {
            docNumber = transaction.docNumber
        } else {
            if isIncome { docNumber = "RV-0001" }
            else if isExpense { docNumber = "PV-0001" }
            else if isPurchase { docNumber = "PUR-0001" }
            else { docNumber = "INV-0001" }
        }

        let rawDate = transaction.docDate
        let docDate = rawDate.count >= 10 ? String(rawDate.prefix(10)) : (rawDate.isEmpty ? "30/09/2026" : rawDate)
        let dueDate = (transaction.dueDate != nil && !transaction.dueDate!.isEmpty) ? String(transaction.dueDate!.prefix(10)) : docDate
        let paymentMode = transaction.paymentMode.isEmpty ? "Bank Transfer" : transaction.paymentMode
        let placeOfSupply = (transaction.placeOfSupply?.isEmpty ?? true) ? (effectiveCompany?.state ?? "37-Andhra Pradesh") : transaction.placeOfSupply!

        let docTitle: String
        if isIncome { docTitle = "RECEIPT VOUCHER" }
        else if isExpense { docTitle = "PAYMENT VOUCHER" }
        else if isPurchase { docTitle = "PURCHASE INVOICE" }
        else { docTitle = "TAX INVOICE" }

        // Supplier info
        let userCompany = SessionManager.shared.getCompanyName().trimmingCharacters(in: .whitespacesAndNewlines)
        let userName = SessionManager.shared.getUserName().trimmingCharacters(in: .whitespacesAndNewlines)
        let supplierName: String
        if isSales || isVoucher {
            if let cName = effectiveCompany?.companyName?.trimmingCharacters(in: .whitespacesAndNewlines), !cName.isEmpty {
                supplierName = cName
            } else if !userCompany.isEmpty {
                supplierName = userCompany
            } else if !userName.isEmpty {
                supplierName = userName
            } else {
                supplierName = "Rajugari Ventures"
            }
        } else {
            supplierName = transaction.partyName.isEmpty ? "Vendor Name" : transaction.partyName
        }

        let supplierTrade = (isSales || isVoucher) ? (effectiveCompany?.tradeName ?? "") : ""
        let userAddress = SessionManager.shared.getAddress().trimmingCharacters(in: .whitespacesAndNewlines)
        let supplierAddress: String
        if isSales || isVoucher {
            var parts: [String] = []
            let street = (effectiveCompany?.address?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false ? effectiveCompany?.address : userAddress)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !street.isEmpty {
                parts.append(street)
            }
            if let st = effectiveCompany?.state?.trimmingCharacters(in: .whitespacesAndNewlines), !st.isEmpty {
                if !parts.joined(separator: " ").localizedCaseInsensitiveContains(st) {
                    parts.append(st)
                }
            }
            if let pin = effectiveCompany?.pincode?.trimmingCharacters(in: .whitespacesAndNewlines), !pin.isEmpty {
                if !parts.joined(separator: " ").contains(pin) {
                    parts.append(pin)
                }
            }
            if parts.isEmpty {
                supplierAddress = "#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati, Andhra Pradesh - 517501"
            } else {
                supplierAddress = parts.joined(separator: ", ")
            }
        } else {
            supplierAddress = transaction.partyAddress ?? ""
        }

        let userGstin = SessionManager.shared.getGstin().trimmingCharacters(in: .whitespacesAndNewlines)
        let supplierGstin: String
        if isSales || isVoucher {
            if let g = effectiveCompany?.gstin?.trimmingCharacters(in: .whitespacesAndNewlines), !g.isEmpty {
                supplierGstin = g
            } else if !userGstin.isEmpty {
                supplierGstin = userGstin
            } else {
                supplierGstin = "37ABCDE1234F1Z5"
            }
        } else {
            supplierGstin = transaction.partyGstin ?? ""
        }

        let supplierState = (isSales || isVoucher) ? (effectiveCompany?.state ?? "Andhra Pradesh") : placeOfSupply
        let userPhone = SessionManager.shared.getPhone().trimmingCharacters(in: .whitespacesAndNewlines)
        let userEmail = SessionManager.shared.getUserEmail().trimmingCharacters(in: .whitespacesAndNewlines)
        let supplierPhone = (isSales || isVoucher) ? ((effectiveCompany?.phone?.isEmpty == false ? effectiveCompany?.phone : userPhone) ?? "") : (transaction.partyPhone ?? "")
        let supplierEmail = (isSales || isVoucher) ? ((effectiveCompany?.email?.isEmpty == false ? effectiveCompany?.email : userEmail) ?? "") : (transaction.partyEmail ?? "")

        let userLogo = SessionManager.shared.getCompanyLogo().trimmingCharacters(in: .whitespacesAndNewlines)
        let rawLogo = (effectiveCompany?.logo?.isEmpty == false ? effectiveCompany?.logo : (userLogo.isEmpty ? nil : userLogo))
        let supplierLogo: String?
        if let l = rawLogo, !l.isEmpty {
            if l.hasPrefix("data:") {
                supplierLogo = l
            } else if let base64 = InvoicePdfGenerator.convertUrlToBase64DataUri(l, timeout: 2.0) {
                supplierLogo = base64
            } else {
                supplierLogo = l
            }
        } else {
            supplierLogo = nil
        }

        // Bill To
        let billToName: String
        if isSales {
            billToName = transaction.partyName.isEmpty ? "Customer Name" : transaction.partyName
        } else if isVoucher {
            billToName = transaction.partyName.isEmpty ? "General" : transaction.partyName
        } else {
            billToName = supplierName
        }

        let billToAddress: String
        if isSales {
            billToAddress = (transaction.partyAddress?.isEmpty ?? true) ? "N/A" : transaction.partyAddress!
        } else {
            billToAddress = supplierAddress
        }

        let billToGstin = isSales ? ((transaction.partyGstin?.isEmpty ?? true) ? "URP / N/A" : transaction.partyGstin!) : (effectiveCompany?.gstin ?? "N/A")
        let billToPan = isSales ? ((transaction.partyPan?.isEmpty ?? true) ? "N/A" : transaction.partyPan!) : "N/A"
        let billToState = isSales ? ((transaction.partyState?.isEmpty ?? true) ? placeOfSupply : transaction.partyState!) : (effectiveCompany?.state ?? "Andhra Pradesh")
        let billToPhone = isSales ? ((transaction.partyPhone?.isEmpty ?? true) ? "N/A" : transaction.partyPhone!) : (effectiveCompany?.phone ?? "N/A")
        let billToEmail = isSales ? ((transaction.partyEmail?.isEmpty ?? true) ? "N/A" : transaction.partyEmail!) : (effectiveCompany?.email ?? "N/A")

        // Ship To
        let shipToSame = transaction.shipToSameAsBilling ?? true
        let shipToName = shipToSame ? billToName : ((transaction.shipToName?.isEmpty ?? true) ? billToName : transaction.shipToName!)
        let shipToAddress = shipToSame ? billToAddress : ((transaction.shipToAddress?.isEmpty ?? true) ? billToAddress : transaction.shipToAddress!)
        let shipToGstin = shipToSame ? billToGstin : ((transaction.shipToGstin?.isEmpty ?? true) ? billToGstin : transaction.shipToGstin!)
        let shipToPan = shipToSame ? billToPan : ((transaction.shipToPan?.isEmpty ?? true) ? billToPan : transaction.shipToPan!)
        let shipToState = shipToSame ? billToState : ((transaction.shipToState?.isEmpty ?? true) ? billToState : transaction.shipToState!)
        let shipToPhone = shipToSame ? billToPhone : ((transaction.shipToMobile?.isEmpty ?? true) ? billToPhone : transaction.shipToMobile!)
        let shipToEmail = shipToSame ? billToEmail : ((transaction.shipToEmail?.isEmpty ?? true) ? billToEmail : transaction.shipToEmail!)

        // Bank Details
        let bankInfo = effectiveCompany?.bankDetails
        let bankName = (bankInfo?.bankName?.isEmpty ?? true) ? "HDFC Bank" : bankInfo!.bankName!
        let bankAccount = (bankInfo?.accountNumber?.isEmpty ?? true) ? "50200012345678" : bankInfo!.accountNumber!
        let bankIfsc = (bankInfo?.ifscCode?.isEmpty ?? true) ? "HDFC0001234" : bankInfo!.ifscCode!
        let bankBranch = (bankInfo?.accountName?.isEmpty ?? true) ? "Main Branch" : bankInfo!.accountName!
        let upiId = effectiveCompany?.upiId ?? ""

        let itemsList: [TransactionItemDto]
        if !transaction.items.isEmpty {
            itemsList = transaction.items
        } else {
            itemsList = [
                TransactionItemDto(
                    description: "Professional Business Services",
                    hsnSac: "998311",
                    qty: 1.0,
                    unit: "PCS",
                    rate: 10000.0,
                    taxableValue: 10000.0,
                    gstRate: 18.0,
                    total: 11800.0
                )
            ]
        }

        let summary = transaction.summary
        let totalAmount = summary.totalAmount > 0 ? summary.totalAmount : itemsList.reduce(0) { $0 + $1.total }
        let amountInWords = (summary.amountInWords?.isEmpty ?? true) ? IndianCurrencyFormatter.numberToWords(totalAmount) : summary.amountInWords!

        // QR Code & Signature computation
        let rawQr = (effectiveCompany?.qrCode?.isEmpty == false) ? effectiveCompany!.qrCode! : ""
        let qrCode: String
        if !rawQr.isEmpty {
            if rawQr.hasPrefix("data:") {
                qrCode = rawQr
            } else if let base64 = InvoicePdfGenerator.convertUrlToBase64DataUri(rawQr, timeout: 2.0) {
                qrCode = base64
            } else {
                qrCode = rawQr
            }
        } else {
            let effectiveUpi: String
            if let upi = effectiveCompany?.upiId?.trimmingCharacters(in: .whitespacesAndNewlines), !upi.isEmpty {
                effectiveUpi = upi
            } else if !supplierPhone.isEmpty && supplierPhone.count >= 10 {
                let digits = supplierPhone.replacingOccurrences(of: "[^0-9]", with: "", options: .regularExpression)
                effectiveUpi = digits.count == 10 ? "\(digits)@upi" : "business@upi"
            } else {
                effectiveUpi = "business@upi"
            }
            let upiString = "upi://pay?pa=\(effectiveUpi)&pn=\(supplierName)&am=\(String(format: "%.2f", totalAmount))&cu=INR"
            qrCode = generateQrCodeBase64(from: upiString) ?? ""
        }

        let rawSig = (effectiveCompany?.signature?.isEmpty == false ? effectiveCompany?.signature : transaction.attachmentUrl) ?? ""
        let signature: String
        if !rawSig.isEmpty {
            if rawSig.hasPrefix("data:") {
                signature = rawSig
            } else if let base64 = InvoicePdfGenerator.convertUrlToBase64DataUri(rawSig, timeout: 2.0) {
                signature = base64
            } else {
                signature = rawSig
            }
        } else {
            signature = ""
        }

        let qrCodeHtml: String
        if !qrCode.isEmpty {
            qrCodeHtml = """
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 6px; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; flex-shrink: 0; align-self: center;">
                <img src="\(qrCode)" width="64" height="64" alt="Payment QR" style="width: 64px; height: 64px; max-width: 64px; max-height: 64px; object-fit: contain; border-radius: 4px; display: block;" />
                <span style="font-size: 7.5px; font-weight: 900; color: #334155; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.5px;">SCAN TO PAY</span>
            </div>
            """
        } else {
            qrCodeHtml = ""
        }

        let signatureHtml: String
        if !signature.isEmpty {
            signatureHtml = """
            <div style="height: 42px; display: flex; align-items: flex-end; justify-content: center; margin-bottom: 4px;">
                <img src="\(signature)" height="40" alt="Signature" style="max-height: 40px; max-width: 140px; object-fit: contain; display: block;" />
            </div>
            """
        } else {
            signatureHtml = "<div style=\"height: 42px;\"></div>"
        }

        let defaultTerms = [
            "1. Payment: Payment must be made as per the terms and due date mentioned in the invoice.",
            "2. Taxes: GST and other applicable taxes will be charged as per prevailing laws.",
            "3. Disputes: Any discrepancy in the invoice must be reported within 7 days of receipt.",
            "4. Jurisdiction: Any disputes shall be subject to the jurisdiction of the seller's place of business."
        ]

        let itemsRowsHtml = itemsList.enumerated().map { idx, item -> String in
            let bg = idx % 2 == 0 ? "#ffffff" : "#f8fafc"
            let discText = (item.discPercent ?? 0) > 0 ? "\(Int(item.discPercent!))%" : "-"
            let gstText = "\(Int(item.gstRate))%"
            let hsn = (item.hsnSac?.isEmpty ?? true) ? "-" : item.hsnSac!
            let unit = (item.unit?.isEmpty ?? true) ? "PCS" : item.unit!

            return """
            <tr style="background-color: \(bg);">
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #64748b;">\(idx + 1)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; font-weight: 700; color: #0f172a;">\(item.description)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; font-family: monospace; color: #475569;">\(hsn)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #0f172a;">\(item.qty)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #64748b;">\(unit)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; font-family: monospace; color: #0f172a;">\(String(format: "%.2f", item.rate))</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; color: #64748b;">\(discText)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; color: #64748b;">\(gstText)</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; font-family: monospace; font-weight: 700; color: #0f172a;">\(String(format: "%.2f", item.taxableValue))</td>
                <td style="padding: 8px; text-align: right; font-family: monospace; font-weight: 900; color: #0f172a;">\(String(format: "%.2f", item.total))</td>
            </tr>
            """
        }.joined(separator: "\n")

        let logoHtml: String
        if let logo = supplierLogo, !logo.isEmpty {
            logoHtml = "<img src=\"\(logo)\" width=\"56\" height=\"56\" alt=\"Logo\" style=\"width: 56px; height: 56px; max-width: 56px; max-height: 56px; object-fit: contain; border-radius: 6px; border: 1px solid #e2e8f0; background: #fff; padding: 4px; flex-shrink: 0; display: block;\" />"
        } else {
            let initials = String(supplierName.prefix(2)).uppercased()
            logoHtml = "<div style=\"width: 56px; height: 56px; border-radius: 8px; background: #EEF2FF; border: 1px solid #C7D2FE; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 20px; color: #4F46E5; flex-shrink: 0;\">\(initials)</div>"
        }

        var taxesBreakdownHtml = ""
        if summary.totalCgst > 0 {
            taxesBreakdownHtml += "<div style=\"display: flex; justify-content: space-between; margin-bottom: 4px;\"><span>Total CGST:</span><span style=\"font-family: monospace; font-weight: 700; color: #0f172a;\">₹\(String(format: "%.2f", summary.totalCgst))</span></div>"
            taxesBreakdownHtml += "<div style=\"display: flex; justify-content: space-between; margin-bottom: 4px;\"><span>Total SGST:</span><span style=\"font-family: monospace; font-weight: 700; color: #0f172a;\">₹\(String(format: "%.2f", summary.totalSgst))</span></div>"
        } else if summary.totalIgst > 0 {
            taxesBreakdownHtml += "<div style=\"display: flex; justify-content: space-between; margin-bottom: 4px;\"><span>Total IGST:</span><span style=\"font-family: monospace; font-weight: 700; color: #0f172a;\">₹\(String(format: "%.2f", summary.totalIgst))</span></div>"
        }

        let roundOffHtml: String
        if summary.roundOff != 0.0 {
            let sign = summary.roundOff > 0 ? "+" : ""
            roundOffHtml = "<div style=\"display: flex; justify-content: space-between; font-size: 10px; color: #64748b; margin-bottom: 4px;\"><span>Round Off:</span><span style=\"font-family: monospace;\">\(sign)\(String(format: "%.2f", summary.roundOff))</span></div>"
        } else {
            roundOffHtml = ""
        }

        let notesHtml: String
        if let notes = transaction.notes, !notes.isEmpty {
            notesHtml = "<div style=\"border-top: 1px solid #e2e8f0; padding-top: 8px; margin-top: 8px; font-size: 10px; color: #475569;\"><strong>Special Notes: </strong>\(notes)</div>"
        } else {
            notesHtml = ""
        }

        let upiHtml: String
        if !upiId.isEmpty {
            upiHtml = "<p style=\"margin: 3px 0 0 0;\"><strong style=\"color: #334155;\">UPI ID:</strong> <span style=\"font-family: monospace; font-weight: 700; color: #4f46e5;\">\(upiId)</span></p>"
        } else {
            upiHtml = ""
        }

        let supplierTradeHtml = !supplierTrade.isEmpty ? "<p style=\"font-size: 10px; font-weight: 800; color: #4f46e5; text-transform: uppercase; margin-top: 2px;\">\(supplierTrade)</p>" : ""
        let supplierPhoneEmailHtml = (!supplierPhone.isEmpty || !supplierEmail.isEmpty) ? "<p style=\"font-size: 10.5px; color: #64748b; margin-top: 2px;\">Phone: \(supplierPhone.isEmpty ? "07997991101" : supplierPhone) | Email: \(supplierEmail.isEmpty ? "N/A" : supplierEmail)</p>" : ""
        let shipToSameBadge = shipToSame ? "<span style=\"font-size: 9px; font-weight: normal; color: #64748b; text-transform: lowercase;\">(same as billing)</span>" : ""
        let termsListHtml = defaultTerms.map { "<p style='margin-bottom: 2px;'>\($0)</p>" }.joined(separator: "\n")
        let totalTaxableVal = summary.totalTaxableValue > 0 ? summary.totalTaxableValue : itemsList.reduce(0) { $0 + $1.taxableValue }

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=780, user-scalable=yes">
            <title>\(docTitle) - \(docNumber)</title>
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body {
                    background-color: #f1f5f9;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    color: #0f172a;
                    padding: 16px;
                    display: flex;
                    justify-content: center;
                    -webkit-print-color-adjust: exact;
                    print-color-adjust: exact;
                }
                .invoice-card {
                    width: 760px;
                    background: #ffffff;
                    border-radius: 16px;
                    padding: 24px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.06);
                }
                @media print {
                    @page { size: A4; margin: 6mm; }
                    body { background: #fff !important; padding: 0 !important; }
                    .invoice-card { width: 100% !important; border-radius: 0 !important; box-shadow: none !important; padding: 0 !important; }
                }
                .copy-badge {
                    text-align: right;
                    margin-bottom: 6px;
                }
                .copy-pill {
                    display: inline-block;
                    font-size: 9px;
                    font-weight: 800;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    color: #64748b;
                    background: #f1f5f9;
                    border: 1px solid #e2e8f0;
                    border-radius: 4px;
                    padding: 3px 8px;
                }
                .main-box {
                    border: 2px solid #0f172a;
                    border-radius: 12px;
                    overflow: hidden;
                }
                .header-section {
                    background-color: #f8fafc;
                    display: flex;
                    justify-content: space-between;
                    padding: 16px;
                    border-bottom: 2px solid #0f172a;
                }
                .header-left {
                    display: flex;
                    gap: 12px;
                    align-items: flex-start;
                    flex: 1.3;
                }
                .header-right {
                    flex: 0.9;
                    border-left: 1px solid #cbd5e1;
                    padding-left: 16px;
                }
                .doc-badge {
                    background: #0f172a;
                    color: #ffffff;
                    text-align: center;
                    font-weight: 900;
                    font-size: 13px;
                    letter-spacing: 1px;
                    text-transform: uppercase;
                    padding: 5px 0;
                    border-radius: 4px;
                    margin-bottom: 8px;
                }
                .meta-table {
                    width: 100%;
                    font-size: 11px;
                }
                .meta-table td {
                    padding: 2px 0;
                }
                .meta-table td.label {
                    color: #475569;
                    font-weight: 700;
                }
                .meta-table td.val {
                    text-align: right;
                    color: #0f172a;
                }
                .parties-section {
                    display: flex;
                    border-bottom: 2px solid #0f172a;
                    background: #ffffff;
                }
                .party-box {
                    flex: 1;
                    padding: 14px;
                    font-size: 11px;
                }
                .party-box.bill {
                    border-right: 1px solid #cbd5e1;
                }
                .party-title {
                    font-size: 11px;
                    font-weight: 900;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    border-bottom: 1px solid #e2e8f0;
                    padding-bottom: 4px;
                    margin-bottom: 6px;
                }
                .items-table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 11px;
                    border-bottom: 2px solid #0f172a;
                }
                .items-table th {
                    background: #0f172a;
                    color: #ffffff;
                    font-weight: 800;
                    padding: 8px 6px;
                    border-right: 1px solid #334155;
                }
                .items-table th:last-child {
                    border-right: none;
                }
                .totals-section {
                    display: flex;
                    border-bottom: 2px solid #0f172a;
                    background: #f8fafc;
                }
                .totals-left {
                    flex: 1.3;
                    padding: 14px;
                    border-right: 1px solid #cbd5e1;
                    display: flex;
                    flex-direction: column;
                    justify-content: space-between;
                }
                .totals-right {
                    flex: 1;
                    padding: 14px;
                    font-size: 11px;
                }
                .grand-total-row {
                    border-top: 2px solid #0f172a;
                    margin-top: 8px;
                    padding-top: 8px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    font-size: 13px;
                    font-weight: 900;
                    color: #0f172a;
                }
                .grand-total-val {
                    font-size: 16px;
                    font-family: monospace;
                    font-weight: 900;
                    color: #1e1b4b;
                }
                .footer-section {
                    display: flex;
                    border-bottom: 1px solid #cbd5e1;
                    background: #ffffff;
                }
                .footer-box {
                    padding: 14px;
                    font-size: 10.5px;
                }
                .footer-box.bank {
                    flex: 1;
                    border-right: 1px solid #cbd5e1;
                }
                .footer-box.terms {
                    flex: 1.3;
                }
                .declaration-section {
                    background: #f8fafc;
                    padding: 14px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    font-size: 10.5px;
                }
            </style>
        </head>
        <body>
            <div class="invoice-card">
                <!-- Copy Indicator -->
                <div class="copy-badge">
                    <span class="copy-pill">copy : \(copyType.lowercased())</span>
                </div>

                <div class="main-box">
                    <!-- 1. Header Section -->
                    <div class="header-section">
                        <div class="header-left">
                            \(logoHtml)
                            <div>
                                <h1 style="font-size: 20px; font-weight: 900; color: #0f172a; line-height: 1.1;">\(supplierName)</h1>
                                \(supplierTradeHtml)
                                <p style="font-size: 11px; color: #475569; margin-top: 3px;">\(supplierAddress)</p>
                                <p style="font-size: 11px; font-weight: 700; color: #0f172a; margin-top: 3px;">
                                    GSTIN: <span style="font-family: monospace;">\(supplierGstin.isEmpty ? "37ABCDE1234F1Z5" : supplierGstin)</span> &nbsp;|&nbsp; State: \(supplierState)
                                </p>
                                \(supplierPhoneEmailHtml)
                            </div>
                        </div>

                        <div class="header-right">
                            <div class="doc-badge">\(docTitle)</div>
                            <table class="meta-table">
                                <tr><td class="label">Invoice No.:</td><td class="val" style="font-family: monospace; font-weight: 800;">\(docNumber)</td></tr>
                                <tr><td class="label">Invoice Date:</td><td class="val">\(docDate)</td></tr>
                                <tr><td class="label">Due Date:</td><td class="val">\(dueDate)</td></tr>
                                <tr><td class="label">Place of Supply:</td><td class="val">\(placeOfSupply)</td></tr>
                                <tr><td class="label">Payment Mode:</td><td class="val">\(paymentMode)</td></tr>
                            </table>
                        </div>
                    </div>

                    <!-- 2. Parties Section: BILL TO & SHIP TO -->
                    <div class="parties-section">
                        <div class="party-box bill">
                            <div class="party-title" style="color: #312e81;">BILL TO</div>
                            <p style="font-weight: 800; color: #0f172a; font-size: 12px; margin-bottom: 2px;">\(billToName)</p>
                            <p style="color: #475569; margin-bottom: 4px;">\(billToAddress)</p>
                            <div style="display: flex; gap: 16px; font-family: monospace; color: #0f172a; font-size: 10.5px;">
                                <span><strong style="font-family: sans-serif; color: #334155;">GSTIN:</strong> \(billToGstin)</span>
                                <span><strong style="font-family: sans-serif; color: #334155;">PAN:</strong> \(billToPan)</span>
                            </div>
                            <div style="display: flex; gap: 16px; color: #475569; font-size: 10.5px; margin-top: 2px;">
                                <span><strong style="color: #334155;">State:</strong> \(billToState)</span>
                                <span><strong style="color: #334155;">Mobile:</strong> \(billToPhone)</span>
                            </div>
                            <p style="color: #475569; font-size: 10.5px; margin-top: 2px;"><strong style="color: #334155;">Email:</strong> \(billToEmail)</p>
                        </div>

                        <div class="party-box">
                            <div class="party-title" style="color: #0f172a; display: flex; justify-content: space-between;">
                                <span>SHIP TO (CONSIGNEE)</span>
                                \(shipToSameBadge)
                            </div>
                            <p style="font-weight: 800; color: #0f172a; font-size: 12px; margin-bottom: 2px;">\(shipToName)</p>
                            <p style="color: #475569; margin-bottom: 4px;">\(shipToAddress)</p>
                            <div style="display: flex; gap: 16px; font-family: monospace; color: #0f172a; font-size: 10.5px;">
                                <span><strong style="font-family: sans-serif; color: #334155;">GSTIN:</strong> \(shipToGstin)</span>
                                <span><strong style="font-family: sans-serif; color: #334155;">PAN:</strong> \(shipToPan)</span>
                            </div>
                            <div style="display: flex; gap: 16px; color: #475569; font-size: 10.5px; margin-top: 2px;">
                                <span><strong style="color: #334155;">State:</strong> \(shipToState)</span>
                                <span><strong style="color: #334155;">Mobile:</strong> \(shipToPhone)</span>
                            </div>
                            <p style="color: #475569; font-size: 10.5px; margin-top: 2px;"><strong style="color: #334155;">Email:</strong> \(shipToEmail)</p>
                        </div>
                    </div>

                    <!-- 3. Items Table (10 Columns) -->
                    <table class="items-table">
                        <thead>
                            <tr>
                                <th style="width: 32px; text-align: center;">#</th>
                                <th style="text-align: left;">Item / Service Description</th>
                                <th style="width: 70px; text-align: center;">HSN/SAC</th>
                                <th style="width: 38px; text-align: center;">Qty</th>
                                <th style="width: 44px; text-align: center;">Unit</th>
                                <th style="width: 70px; text-align: right;">Rate (₹)</th>
                                <th style="width: 48px; text-align: right;">Disc %</th>
                                <th style="width: 48px; text-align: right;">GST %</th>
                                <th style="width: 80px; text-align: right;">Taxable (₹)</th>
                                <th style="width: 90px; text-align: right;">Total (₹)</th>
                            </tr>
                        </thead>
                        <tbody>
                            \(itemsRowsHtml)
                        </tbody>
                    </table>

                    <!-- 4. Totals and Calculations Section -->
                    <div class="totals-section">
                        <div class="totals-left">
                            <div>
                                <span style="font-size: 10px; font-weight: 800; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px;">AMOUNT IN WORDS:</span>
                                <p style="font-size: 12px; font-weight: 800; font-style: italic; color: #0f172a; margin-top: 3px; text-transform: capitalize;">\(amountInWords)</p>
                            </div>
                            \(notesHtml)
                        </div>

                        <div class="totals-right">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 4px; color: #475569;">
                                <span>Subtotal (Taxable Value):</span>
                                <span style="font-family: monospace; font-weight: 700; color: #0f172a;">₹\(String(format: "%.2f", totalTaxableVal))</span>
                            </div>
                            \(taxesBreakdownHtml)
                            \(roundOffHtml)
                            <div class="grand-total-row">
                                <span>GRAND TOTAL:</span>
                                <span class="grand-total-val">\(IndianCurrencyFormatter.format(totalAmount))</span>
                            </div>
                        </div>
                    </div>

                    <!-- 5. Footer: Bank Details & Terms -->
                    <div class="footer-section">
                        <div class="footer-box bank" style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
                            <div style="flex: 1;">
                                <div class="party-title" style="color: #0f172a;">BANK DETAILS</div>
                                <p style="margin: 3px 0;"><strong style="color: #334155;">Bank Name:</strong> \(bankName)</p>
                                <p style="margin: 3px 0;"><strong style="color: #334155;">Account No.:</strong> <span style="font-family: monospace; font-weight: 700; color: #0f172a;">\(bankAccount)</span></p>
                                <p style="margin: 3px 0;"><strong style="color: #334155;">IFSC Code:</strong> <span style="font-family: monospace; font-weight: 700; color: #0f172a;">\(bankIfsc)</span></p>
                                <p style="margin: 3px 0;"><strong style="color: #334155;">Branch:</strong> \(bankBranch)</p>
                                \(upiHtml)
                            </div>
                            \(qrCodeHtml)
                        </div>

                        <div class="footer-box terms">
                            <div class="party-title" style="color: #0f172a;">TERMS & CONDITIONS</div>
                            <div style="color: #475569; font-size: 10px; line-height: 1.4;">
                                \(termsListHtml)
                            </div>
                        </div>
                    </div>

                    <!-- 6. Declaration & Signatory -->
                    <div class="declaration-section">
                        <div style="flex: 1.3; color: #64748b; font-style: italic; font-size: 10px; padding-right: 16px;">
                            <strong style="font-style: normal; color: #334155;">Declaration:</strong> We declare that this invoice shows the actual price of the goods/services described and that all particulars are true and correct.
                        </div>
                        <div style="flex: 0.9; text-align: center; display: flex; flex-direction: column; align-items: center; justify-content: flex-end;">
                            \(signatureHtml)
                            <div style="border-top: 1px solid #94a3b8; width: 150px; margin: 0 auto; padding-top: 4px;">
                                <p style="font-weight: 900; font-size: 10.5px; color: #0f172a;">Authorized Signatory</p>
                                <p style="font-size: 9px; font-weight: 700; color: #64748b; text-transform: uppercase;">\(supplierName.uppercased())</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    }
}
