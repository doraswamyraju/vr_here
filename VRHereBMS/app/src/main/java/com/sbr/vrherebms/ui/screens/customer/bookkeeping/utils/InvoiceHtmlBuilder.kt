package com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils

import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto

object InvoiceHtmlBuilder {

    fun buildHtml(transaction: TransactionDto, company: CompanyDetailsDto?): String {
        val isSales = transaction.transactionType.equals("Sales", ignoreCase = true)
        val isPurchase = transaction.transactionType.equals("Purchase", ignoreCase = true)
        val isIncome = transaction.transactionType.equals("Income", ignoreCase = true)
        val isExpense = transaction.transactionType.equals("Expense", ignoreCase = true)
        val isVoucher = isIncome || isExpense

        val copyType = transaction.copyType.ifBlank { "Original for Recipient" }
        val docNumber = transaction.docNumber.ifBlank {
            when {
                isIncome -> "RV-0001"
                isExpense -> "PV-0001"
                isPurchase -> "PUR-0001"
                else -> "INV-0001"
            }
        }
        val docDate = transaction.docDate.take(10).ifBlank { "30/09/2026" }
        val dueDate = transaction.dueDate?.take(10)?.ifBlank { null } ?: docDate
        val paymentMode = transaction.paymentMode.ifBlank { "Bank Transfer" }
        val placeOfSupply = transaction.placeOfSupply.ifBlank { company?.state ?: "37-Andhra Pradesh" }

        val docTitle = when {
            isIncome -> "RECEIPT VOUCHER"
            isExpense -> "PAYMENT VOUCHER"
            isPurchase -> "PURCHASE INVOICE"
            else -> "TAX INVOICE"
        }

        val supplierName = if (isSales || isVoucher) {
            company?.companyName?.ifBlank { null } ?: "Rajugari Ventures"
        } else {
            transaction.partyName.ifBlank { "Vendor Name" }
        }
        val supplierTrade = if (isSales || isVoucher) company?.tradeName ?: "" else ""
        val supplierAddress = if (isSales || isVoucher) {
            company?.address?.ifBlank { null } ?: "#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati"
        } else {
            transaction.partyAddress
        }
        val supplierGstin = if (isSales || isVoucher) company?.gstin ?: "" else transaction.partyGstin
        val supplierState = if (isSales || isVoucher) company?.state ?: "Andhra Pradesh" else placeOfSupply
        val supplierPhone = if (isSales || isVoucher) company?.phone ?: "" else transaction.partyPhone
        val supplierEmail = if (isSales || isVoucher) company?.email ?: "" else transaction.partyEmail
        val supplierLogo = company?.logo?.ifBlank { null }

        // Bill To
        val billToName = if (isSales) {
            transaction.partyName.ifBlank { "Rajugari Ventures" }
        } else if (isVoucher) {
            transaction.partyName.ifBlank { "General" }
        } else {
            company?.companyName ?: "Rajugari Ventures"
        }
        val billToAddress = if (isSales) {
            transaction.partyAddress.ifBlank { "#38, 1st Floor, TUDA Complex, Bairagipatteda" }
        } else {
            company?.address ?: "#38, 1st Floor, TUDA Complex"
        }
        val billToGstin = if (isSales) transaction.partyGstin.ifBlank { "URP / N/A" } else company?.gstin ?: "N/A"
        val billToPan = if (isSales) transaction.partyPan.ifBlank { "N/A" } else "N/A"
        val billToState = if (isSales) transaction.partyState.ifBlank { placeOfSupply } else company?.state ?: "Andhra Pradesh"
        val billToPhone = if (isSales) transaction.partyPhone.ifBlank { "N/A" } else company?.phone ?: "N/A"
        val billToEmail = if (isSales) transaction.partyEmail.ifBlank { "N/A" } else company?.email ?: "N/A"

        // Ship To
        val shipToSame = transaction.shipToSameAsBilling
        val shipToName = if (shipToSame) billToName else transaction.shipToName.ifBlank { billToName }
        val shipToAddress = if (shipToSame) billToAddress else transaction.shipToAddress.ifBlank { billToAddress }
        val shipToGstin = if (shipToSame) billToGstin else transaction.shipToGstin.ifBlank { billToGstin }
        val shipToPan = if (shipToSame) billToPan else transaction.shipToPan.ifBlank { billToPan }
        val shipToState = if (shipToSame) billToState else transaction.shipToState.ifBlank { billToState }
        val shipToPhone = if (shipToSame) billToPhone else transaction.shipToMobile.ifBlank { billToPhone }
        val shipToEmail = if (shipToSame) billToEmail else transaction.shipToEmail.ifBlank { billToEmail }

        // Bank Details
        val bankInfo = company?.bankDetails
        val bankName = bankInfo?.bankName?.ifBlank { null } ?: "HDFC Bank"
        val bankAccount = bankInfo?.accountNumber?.ifBlank { null } ?: "50200012345678"
        val bankIfsc = bankInfo?.ifscCode?.ifBlank { null } ?: "HDFC0001234"
        val bankBranch = bankInfo?.accountName?.ifBlank { null } ?: "Main Branch"
        val upiId = company?.upiId ?: ""

        val itemsList = if (transaction.items.isNotEmpty()) transaction.items else listOf(
            com.sbr.vrherebms.data.model.TransactionItemDto(
                description = "Professional Business Services",
                hsnSac = "998311",
                qty = 1.0,
                unit = "PCS",
                rate = 10000.0,
                taxableValue = 10000.0,
                gstRate = 18.0,
                total = 11800.0
            )
        )

        val summary = transaction.summary
        val totalAmount = if (summary.totalAmount > 0) summary.totalAmount else itemsList.sumOf { it.total }
        val amountInWords = summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(totalAmount) }

        val defaultTerms = listOf(
            "1. Payment: Payment must be made as per the terms and due date mentioned in the invoice.",
            "2. Taxes: GST and other applicable taxes will be charged as per prevailing laws.",
            "3. Disputes: Any discrepancy in the invoice must be reported within 7 days of receipt.",
            "4. Jurisdiction: Any disputes shall be subject to the jurisdiction of the seller's place of business."
        )

        val itemsRowsHtml = itemsList.mapIndexed { idx, item ->
            val bg = if (idx % 2 == 0) "#ffffff" else "#f8fafc"
            val discText = if (item.discPercent > 0) "${item.discPercent}%" else "-"
            val gstText = "${item.gstRate.toInt()}%"
            """
            <tr style="background-color: $bg;">
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #64748b;">${idx + 1}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; font-weight: 700; color: #0f172a;">${item.description}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; font-family: monospace; color: #475569;">${item.hsnSac.ifBlank { "-" }}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #0f172a;">${item.qty}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: center; color: #64748b;">${item.unit.ifBlank { "PCS" }}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; font-family: monospace; color: #0f172a;">${"%.2f".format(item.rate)}</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; color: #64748b;">$discText</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; color: #64748b;">$gstText</td>
                <td style="padding: 8px; border-right: 1px solid #e2e8f0; text-align: right; font-family: monospace; font-weight: 700; color: #0f172a;">${"%.2f".format(item.taxableValue)}</td>
                <td style="padding: 8px; text-align: right; font-family: monospace; font-weight: 900; color: #0f172a;">${"%.2f".format(item.total)}</td>
            </tr>
            """.trimIndent()
        }.joinToString("\n")

        val logoHtml = if (!supplierLogo.isNullOrBlank()) {
            """<img src="$supplierLogo" alt="Logo" style="width: 56px; height: 56px; object-fit: contain; border-radius: 6px; border: 1px solid #e2e8f0; background: #fff; padding: 4px; flex-shrink: 0;" />"""
        } else {
            """<div style="width: 56px; height: 56px; border-radius: 8px; background: #EEF2FF; border: 1px solid #C7D2FE; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 20px; color: #4F46E5; flex-shrink: 0;">${supplierName.take(2).uppercase()}</div>"""
        }

        val taxesBreakdownHtml = buildString {
            if (summary.totalCgst > 0) {
                append("""<div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>Total CGST:</span><span style="font-family: monospace; font-weight: 700; color: #0f172a;">₹${"%.2f".format(summary.totalCgst)}</span></div>""")
                append("""<div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>Total SGST:</span><span style="font-family: monospace; font-weight: 700; color: #0f172a;">₹${"%.2f".format(summary.totalSgst)}</span></div>""")
            } else if (summary.totalIgst > 0) {
                append("""<div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span>Total IGST:</span><span style="font-family: monospace; font-weight: 700; color: #0f172a;">₹${"%.2f".format(summary.totalIgst)}</span></div>""")
            }
        }

        val roundOffHtml = if (summary.roundOff != 0.0) {
            val sign = if (summary.roundOff > 0) "+" else ""
            """<div style="display: flex; justify-content: space-between; font-size: 10px; color: #64748b; margin-bottom: 4px;"><span>Round Off:</span><span style="font-family: monospace;">$sign${"%.2f".format(summary.roundOff)}</span></div>"""
        } else ""

        val notesHtml = if (transaction.notes.isNotBlank()) {
            """<div style="border-top: 1px solid #e2e8f0; padding-top: 8px; margin-top: 8px; font-size: 10px; color: #475569;"><strong>Special Notes: </strong>${transaction.notes}</div>"""
        } else ""

        val upiHtml = if (upiId.isNotBlank()) {
            """<p style="margin: 3px 0 0 0;"><strong style="color: #334155;">UPI ID:</strong> <span style="font-family: monospace; font-weight: 700; color: #4f46e5;">$upiId</span></p>"""
        } else ""

        return """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=780, user-scalable=yes">
            <title>${docTitle} - ${docNumber}</title>
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
                    <span class="copy-pill">copy : ${copyType.lowercase()}</span>
                </div>

                <div class="main-box">
                    <!-- 1. Header Section -->
                    <div class="header-section">
                        <div class="header-left">
                            $logoHtml
                            <div>
                                <h1 style="font-size: 20px; font-weight: 900; color: #0f172a; line-height: 1.1;">$supplierName</h1>
                                ${if (supplierTrade.isNotBlank()) """<p style="font-size: 10px; font-weight: 800; color: #4f46e5; text-transform: uppercase; margin-top: 2px;">$supplierTrade</p>""" else ""}
                                <p style="font-size: 11px; color: #475569; margin-top: 3px;">$supplierAddress</p>
                                <p style="font-size: 11px; font-weight: 700; color: #0f172a; margin-top: 3px;">
                                    GSTIN: <span style="font-family: monospace;">${supplierGstin.ifBlank { "37ABCDE1234F1Z5" }}</span> &nbsp;|&nbsp; State: $supplierState
                                </p>
                                ${if (supplierPhone.isNotBlank() || supplierEmail.isNotBlank()) """<p style="font-size: 10.5px; color: #64748b; margin-top: 2px;">Phone: ${supplierPhone.ifBlank { "07997991101" }} | Email: ${supplierEmail.ifBlank { "N/A" }}</p>""" else ""}
                            </div>
                        </div>

                        <div class="header-right">
                            <div class="doc-badge">$docTitle</div>
                            <table class="meta-table">
                                <tr><td class="label">Invoice No.:</td><td class="val" style="font-family: monospace; font-weight: 800;">$docNumber</td></tr>
                                <tr><td class="label">Invoice Date:</td><td class="val">$docDate</td></tr>
                                <tr><td class="label">Due Date:</td><td class="val">$dueDate</td></tr>
                                <tr><td class="label">Place of Supply:</td><td class="val">$placeOfSupply</td></tr>
                                <tr><td class="label">Payment Mode:</td><td class="val">$paymentMode</td></tr>
                            </table>
                        </div>
                    </div>

                    <!-- 2. Parties Section: BILL TO & SHIP TO -->
                    <div class="parties-section">
                        <div class="party-box bill">
                            <div class="party-title" style="color: #312e81;">BILL TO</div>
                            <p style="font-weight: 800; color: #0f172a; font-size: 12px; margin-bottom: 2px;">$billToName</p>
                            <p style="color: #475569; margin-bottom: 4px;">$billToAddress</p>
                            <div style="display: flex; gap: 16px; font-family: monospace; color: #0f172a; font-size: 10.5px;">
                                <span><strong style="font-family: sans-serif; color: #334155;">GSTIN:</strong> $billToGstin</span>
                                <span><strong style="font-family: sans-serif; color: #334155;">PAN:</strong> $billToPan</span>
                            </div>
                            <div style="display: flex; gap: 16px; color: #475569; font-size: 10.5px; margin-top: 2px;">
                                <span><strong style="color: #334155;">State:</strong> $billToState</span>
                                <span><strong style="color: #334155;">Mobile:</strong> $billToPhone</span>
                            </div>
                            <p style="color: #475569; font-size: 10.5px; margin-top: 2px;"><strong style="color: #334155;">Email:</strong> $billToEmail</p>
                        </div>

                        <div class="party-box">
                            <div class="party-title" style="color: #0f172a; display: flex; justify-content: space-between;">
                                <span>SHIP TO (CONSIGNEE)</span>
                                ${if (shipToSame) """<span style="font-size: 9px; font-weight: normal; color: #64748b; text-transform: lowercase;">(same as billing)</span>""" else ""}
                            </div>
                            <p style="font-weight: 800; color: #0f172a; font-size: 12px; margin-bottom: 2px;">$shipToName</p>
                            <p style="color: #475569; margin-bottom: 4px;">$shipToAddress</p>
                            <div style="display: flex; gap: 16px; font-family: monospace; color: #0f172a; font-size: 10.5px;">
                                <span><strong style="font-family: sans-serif; color: #334155;">GSTIN:</strong> $shipToGstin</span>
                                <span><strong style="font-family: sans-serif; color: #334155;">PAN:</strong> $shipToPan</span>
                            </div>
                            <div style="display: flex; gap: 16px; color: #475569; font-size: 10.5px; margin-top: 2px;">
                                <span><strong style="color: #334155;">State:</strong> $shipToState</span>
                                <span><strong style="color: #334155;">Mobile:</strong> $shipToPhone</span>
                            </div>
                            <p style="color: #475569; font-size: 10.5px; margin-top: 2px;"><strong style="color: #334155;">Email:</strong> $shipToEmail</p>
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
                            $itemsRowsHtml
                        </tbody>
                    </table>

                    <!-- 4. Totals and Calculations Section -->
                    <div class="totals-section">
                        <div class="totals-left">
                            <div>
                                <span style="font-size: 10px; font-weight: 800; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px;">AMOUNT IN WORDS:</span>
                                <p style="font-size: 12px; font-weight: 800; font-style: italic; color: #0f172a; margin-top: 3px; text-transform: capitalize;">$amountInWords</p>
                            </div>
                            $notesHtml
                        </div>

                        <div class="totals-right">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 4px; color: #475569;">
                                <span>Subtotal (Taxable Value):</span>
                                <span style="font-family: monospace; font-weight: 700; color: #0f172a;">₹${"%.2f".format(if (summary.totalTaxableValue > 0) summary.totalTaxableValue else itemsList.sumOf { it.taxableValue })}</span>
                            </div>
                            $taxesBreakdownHtml
                            $roundOffHtml
                            <div class="grand-total-row">
                                <span>GRAND TOTAL:</span>
                                <span class="grand-total-val">${IndianCurrencyFormatter.format(totalAmount)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- 5. Footer: Bank Details & Terms -->
                    <div class="footer-section">
                        <div class="footer-box bank">
                            <div class="party-title" style="color: #0f172a;">BANK DETAILS</div>
                            <p style="margin: 3px 0;"><strong style="color: #334155;">Bank Name:</strong> $bankName</p>
                            <p style="margin: 3px 0;"><strong style="color: #334155;">Account No.:</strong> <span style="font-family: monospace; font-weight: 700; color: #0f172a;">$bankAccount</span></p>
                            <p style="margin: 3px 0;"><strong style="color: #334155;">IFSC Code:</strong> <span style="font-family: monospace; font-weight: 700; color: #0f172a;">$bankIfsc</span></p>
                            <p style="margin: 3px 0;"><strong style="color: #334155;">Branch:</strong> $bankBranch</p>
                            $upiHtml
                        </div>

                        <div class="footer-box terms">
                            <div class="party-title" style="color: #0f172a;">TERMS & CONDITIONS</div>
                            <div style="color: #475569; font-size: 10px; line-height: 1.4;">
                                ${defaultTerms.map { "<p style='margin-bottom: 2px;'>$it</p>" }.joinToString("\n")}
                            </div>
                        </div>
                    </div>

                    <!-- 6. Declaration & Signatory -->
                    <div class="declaration-section">
                        <div style="flex: 1.3; color: #64748b; font-style: italic; font-size: 10px; padding-right: 16px;">
                            <strong style="font-style: normal; color: #334155;">Declaration:</strong> We declare that this invoice shows the actual price of the goods/services described and that all particulars are true and correct.
                        </div>
                        <div style="flex: 0.9; text-align: center;">
                            <div style="height: 28px;"></div>
                            <div style="border-top: 1px solid #94a3b8; width: 150px; margin: 0 auto; padding-top: 4px;">
                                <p style="font-weight: 900; font-size: 10.5px; color: #0f172a;">Authorized Signatory</p>
                                <p style="font-size: 9px; font-weight: 700; color: #64748b; text-transform: uppercase;">${supplierName.uppercase()}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """.trimIndent()
    }
}
