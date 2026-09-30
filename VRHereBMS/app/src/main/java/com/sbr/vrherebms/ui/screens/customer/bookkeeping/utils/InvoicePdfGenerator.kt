package com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.*
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.print.PrintAttributes
import android.print.PrintManager
import android.provider.MediaStore
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.core.content.FileProvider
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto
import java.io.File
import java.io.FileOutputStream

object InvoicePdfGenerator {

    /**
     * Generates a pristine, vector A4 PDF Document (595 x 842 pt) matching the exact web layout
     */
    fun generateInvoicePdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?): File {
        val pdfDocument = PdfDocument()
        val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()
        val page = pdfDocument.startPage(pageInfo)
        val canvas = page.canvas

        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        val boldPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }

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

        // Supplier Info
        val supplierName = if (isSales || isVoucher) {
            company?.companyName?.ifBlank { null } ?: "Rajugari Ventures"
        } else {
            transaction.partyName.ifBlank { "Vendor Name" }
        }
        val supplierAddress = if (isSales || isVoucher) {
            company?.address?.ifBlank { null } ?: "#38, 1st Floor, TUDA Complex, Bairagipatteda, Tirupati"
        } else {
            transaction.partyAddress
        }
        val supplierGstin = if (isSales || isVoucher) company?.gstin ?: "" else transaction.partyGstin
        val supplierState = if (isSales || isVoucher) company?.state ?: "Andhra Pradesh" else placeOfSupply
        val supplierPhone = if (isSales || isVoucher) company?.phone ?: "" else transaction.partyPhone
        val supplierEmail = if (isSales || isVoucher) company?.email ?: "" else transaction.partyEmail

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

        val leftMargin = 24f
        val rightMargin = 571f
        val contentWidth = rightMargin - leftMargin
        var y = 24f

        // --- 1. Top Copy Indicator ---
        paint.color = Color.rgb(100, 116, 139)
        paint.textSize = 7.5f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        paint.textAlign = Paint.Align.RIGHT
        canvas.drawText("COPY : ${copyType.uppercase()}", rightMargin - 4f, y + 8f, paint)
        paint.textAlign = Paint.Align.LEFT
        paint.typeface = Typeface.DEFAULT
        y += 14f

        // --- 2. Main Outer Header Box ---
        val headerH = 88f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.2f
        canvas.drawRect(leftMargin, y, rightMargin, y + headerH, paint)

        // Split Header (Left 310f, Right 237f)
        val headerSplitX = leftMargin + 310f
        canvas.drawLine(headerSplitX, y, headerSplitX, y + headerH, paint)

        // Left: Logo & Company Name
        boldPaint.color = Color.rgb(15, 23, 42)
        boldPaint.textSize = 13.5f
        canvas.drawText(supplierName, leftMargin + 10f, y + 18f, boldPaint)

        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 8f
        canvas.drawText(supplierAddress.take(50), leftMargin + 10f, y + 32f, paint)

        boldPaint.textSize = 8f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("GSTIN: ${supplierGstin.ifBlank { "37ABCDE1234F1Z5" }}  |  State: $supplierState", leftMargin + 10f, y + 46f, boldPaint)

        paint.color = Color.rgb(71, 85, 105)
        if (supplierPhone.isNotBlank() || supplierEmail.isNotBlank()) {
            canvas.drawText("Phone: ${supplierPhone.ifBlank { "07997991101" }}  |  Email: ${supplierEmail.ifBlank { "N/A" }}", leftMargin + 10f, y + 60f, paint)
        }

        // Right: Doc Badge & Key-Value Metadata
        val rightBoxW = rightMargin - headerSplitX
        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawRect(headerSplitX + 8f, y + 8f, rightMargin - 8f, y + 26f, paint)

        paint.color = Color.WHITE
        paint.textSize = 9.5f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        paint.textAlign = Paint.Align.CENTER
        canvas.drawText(docTitle, headerSplitX + (rightBoxW / 2f), y + 20f, paint)
        paint.textAlign = Paint.Align.LEFT
        paint.typeface = Typeface.DEFAULT

        val metaKeys = arrayOf("Invoice No.:", "Invoice Date:", "Due Date:", "Place of Supply:", "Payment Mode:")
        val metaVals = arrayOf(docNumber, docDate, dueDate, placeOfSupply, paymentMode)
        var metaY = y + 37f

        for (i in metaKeys.indices) {
            paint.color = Color.rgb(71, 85, 105)
            paint.textSize = 7.5f
            paint.typeface = Typeface.DEFAULT
            canvas.drawText(metaKeys[i], headerSplitX + 10f, metaY, paint)

            paint.color = Color.rgb(15, 23, 42)
            paint.typeface = Typeface.create(Typeface.DEFAULT, if (i == 0) Typeface.BOLD else Typeface.NORMAL)
            paint.textAlign = Paint.Align.RIGHT
            canvas.drawText(metaVals[i], rightMargin - 10f, metaY, paint)
            paint.textAlign = Paint.Align.LEFT
            metaY += 10.5f
        }

        y += headerH

        // --- 3. BILL TO & SHIP TO Boxes ---
        val partyBoxH = 76f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.2f
        canvas.drawRect(leftMargin, y, rightMargin, y + partyBoxH, paint)

        val partySplitX = leftMargin + (contentWidth / 2f)
        canvas.drawLine(partySplitX, y, partySplitX, y + partyBoxH, paint)

        // BILL TO
        boldPaint.textSize = 8.5f
        boldPaint.color = Color.rgb(49, 46, 129)
        canvas.drawText("BILL TO", leftMargin + 8f, y + 13f, boldPaint)

        boldPaint.textSize = 8.5f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText(billToName.take(30), leftMargin + 8f, y + 25f, boldPaint)

        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 7.5f
        paint.typeface = Typeface.DEFAULT
        canvas.drawText(billToAddress.take(38), leftMargin + 8f, y + 36f, paint)
        canvas.drawText("GSTIN: $billToGstin    PAN: $billToPan", leftMargin + 8f, y + 48f, paint)
        canvas.drawText("State: $billToState    Mobile: $billToPhone", leftMargin + 8f, y + 59f, paint)
        canvas.drawText("Email: $billToEmail", leftMargin + 8f, y + 70f, paint)

        // SHIP TO
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("SHIP TO (CONSIGNEE)", partySplitX + 8f, y + 13f, boldPaint)
        if (shipToSame) {
            paint.color = Color.rgb(100, 116, 139)
            paint.textSize = 6.5f
            canvas.drawText("(same as billing)", partySplitX + 110f, y + 13f, paint)
            paint.textSize = 7.5f
        }

        canvas.drawText(shipToName.take(30), partySplitX + 8f, y + 25f, boldPaint)
        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText(shipToAddress.take(38), partySplitX + 8f, y + 36f, paint)
        canvas.drawText("GSTIN: $shipToGstin    PAN: $shipToPan", partySplitX + 8f, y + 48f, paint)
        canvas.drawText("State: $shipToState    Mobile: $shipToPhone", partySplitX + 8f, y + 59f, paint)
        canvas.drawText("Email: $shipToEmail", partySplitX + 8f, y + 70f, paint)

        y += partyBoxH

        // --- 4. 10-Column Items Table ---
        val colWidths = floatArrayOf(20f, 150f, 48f, 26f, 26f, 48f, 38f, 38f, 55f, 98f)
        val colHeaders = arrayOf("#", "Item / Service Description", "HSN/SAC", "Qty", "Unit", "Rate (₹)", "Disc %", "GST %", "Taxable (₹)", "Total (₹)")

        val tableHeaderH = 18f
        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawRect(leftMargin, y, rightMargin, y + tableHeaderH, paint)

        paint.color = Color.WHITE
        paint.textSize = 7f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)

        var curColX = leftMargin
        for (i in colHeaders.indices) {
            val alignCenter = i == 0 || i == 2 || i == 3 || i == 4
            val alignRight = i >= 5
            val textX = if (alignRight) curColX + colWidths[i] - 4f
            else if (alignCenter) curColX + (colWidths[i] / 2f)
            else curColX + 4f

            if (alignRight) paint.textAlign = Paint.Align.RIGHT
            else if (alignCenter) paint.textAlign = Paint.Align.CENTER
            else paint.textAlign = Paint.Align.LEFT

            canvas.drawText(colHeaders[i], textX, y + 12f, paint)
            curColX += colWidths[i]
        }
        y += tableHeaderH

        // Items Rows
        val rowHeight = 17f
        val itemsToDraw = if (transaction.items.isNotEmpty()) transaction.items else listOf(
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

        itemsToDraw.forEachIndexed { idx, item ->
            paint.style = Paint.Style.FILL
            paint.color = if (idx % 2 == 0) Color.WHITE else Color.rgb(248, 250, 252)
            canvas.drawRect(leftMargin, y, rightMargin, y + rowHeight, paint)

            paint.style = Paint.Style.STROKE
            paint.color = Color.rgb(226, 232, 240)
            paint.strokeWidth = 0.5f
            canvas.drawRect(leftMargin, y, rightMargin, y + rowHeight, paint)

            paint.style = Paint.Style.FILL
            paint.color = Color.rgb(15, 23, 42)
            paint.textSize = 7.5f

            var colX = leftMargin
            val vals = arrayOf(
                "${idx + 1}",
                item.description.take(28),
                item.hsnSac.ifBlank { "-" },
                "${item.qty}",
                item.unit.ifBlank { "PCS" },
                "%.2f".format(item.rate),
                if (item.discPercent > 0) "${item.discPercent}%" else "-",
                "${item.gstRate.toInt()}%",
                "%.2f".format(item.taxableValue),
                "%.2f".format(item.total)
            )

            for (i in vals.indices) {
                val alignCenter = i == 0 || i == 2 || i == 3 || i == 4
                val alignRight = i >= 5
                val textX = if (alignRight) colX + colWidths[i] - 4f
                else if (alignCenter) colX + (colWidths[i] / 2f)
                else colX + 4f

                if (alignRight) paint.textAlign = Paint.Align.RIGHT
                else if (alignCenter) paint.textAlign = Paint.Align.CENTER
                else paint.textAlign = Paint.Align.LEFT

                paint.typeface = if (i == 1 || i == 9) Typeface.create(Typeface.DEFAULT, Typeface.BOLD) else Typeface.DEFAULT
                canvas.drawText(vals[i], textX, y + 11.5f, paint)
                colX += colWidths[i]
            }

            y += rowHeight
        }

        // --- 5. Totals and Calculations Block ---
        val summaryBoxH = 82f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.2f
        canvas.drawRect(leftMargin, y, rightMargin, y + summaryBoxH, paint)

        val summarySplitX = leftMargin + 320f
        canvas.drawLine(summarySplitX, y, summarySplitX, y + summaryBoxH, paint)

        // Left: Amount in Words
        paint.style = Paint.Style.FILL
        boldPaint.textSize = 7.5f
        boldPaint.color = Color.rgb(100, 116, 139)
        canvas.drawText("AMOUNT IN WORDS:", leftMargin + 8f, y + 14f, boldPaint)

        val totalAmt = if (transaction.summary.totalAmount > 0) transaction.summary.totalAmount else itemsToDraw.sumOf { it.total }
        val words = transaction.summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(totalAmt) }
        boldPaint.textSize = 8.5f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText(words.take(55), leftMargin + 8f, y + 27f, boldPaint)

        if (transaction.notes.isNotBlank()) {
            paint.color = Color.rgb(100, 116, 139)
            paint.textSize = 7.5f
            canvas.drawText("Special Notes: ${transaction.notes.take(45)}", leftMargin + 8f, y + 42f, paint)
        }

        // Right: Subtotal, Taxes, Grand Total
        var sumY = y + 13f
        val summary = transaction.summary

        paint.textSize = 7.5f
        paint.textAlign = Paint.Align.LEFT
        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("Subtotal (Taxable Value):", summarySplitX + 8f, sumY, paint)
        paint.textAlign = Paint.Align.RIGHT
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawText("₹%.2f".format(if (summary.totalTaxableValue > 0) summary.totalTaxableValue else itemsToDraw.sumOf { it.taxableValue }), rightMargin - 8f, sumY, paint)

        val totalCgst = if (summary.totalCgst > 0) summary.totalCgst else itemsToDraw.sumOf { it.cgst }
        val totalSgst = if (summary.totalSgst > 0) summary.totalSgst else itemsToDraw.sumOf { it.sgst }
        val totalIgst = if (summary.totalIgst > 0) summary.totalIgst else itemsToDraw.sumOf { it.igst }

        if (totalCgst > 0) {
            sumY += 11f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("Total CGST:", summarySplitX + 8f, sumY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(totalCgst), rightMargin - 8f, sumY, paint)

            sumY += 11f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("Total SGST:", summarySplitX + 8f, sumY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(totalSgst), rightMargin - 8f, sumY, paint)
        } else if (totalIgst > 0) {
            sumY += 11f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("Total IGST:", summarySplitX + 8f, sumY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(totalIgst), rightMargin - 8f, sumY, paint)
        }

        // Grand Total Divider & Line
        val grandTotalLineY = y + summaryBoxH - 18f
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1f
        canvas.drawLine(summarySplitX, grandTotalLineY, rightMargin, grandTotalLineY, paint)

        paint.textAlign = Paint.Align.LEFT
        boldPaint.textSize = 9.5f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("GRAND TOTAL:", summarySplitX + 8f, y + summaryBoxH - 6f, boldPaint)

        paint.textAlign = Paint.Align.RIGHT
        boldPaint.color = Color.rgb(49, 46, 129)
        canvas.drawText(IndianCurrencyFormatter.format(totalAmt), rightMargin - 8f, y + summaryBoxH - 6f, boldPaint)
        paint.textAlign = Paint.Align.LEFT

        y += summaryBoxH

        // --- 6. Footer: Bank Details, Terms & Signatory ---
        val footerH = 95f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.2f
        canvas.drawRect(leftMargin, y, rightMargin, y + footerH, paint)

        val footerSplitX = leftMargin + 220f
        canvas.drawLine(footerSplitX, y, footerSplitX, y + footerH - 32f, paint)

        // Bank Details
        boldPaint.textSize = 8f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("BANK DETAILS", leftMargin + 8f, y + 12f, boldPaint)

        paint.style = Paint.Style.FILL
        paint.textSize = 7f
        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("Bank Name: $bankName", leftMargin + 8f, y + 23f, paint)
        canvas.drawText("Account No.: $bankAccount", leftMargin + 8f, y + 33f, paint)
        canvas.drawText("IFSC Code: $bankIfsc", leftMargin + 8f, y + 43f, paint)
        canvas.drawText("Branch: $bankBranch", leftMargin + 8f, y + 53f, paint)

        // Terms & Conditions
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("TERMS & CONDITIONS", footerSplitX + 8f, y + 12f, boldPaint)

        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("1. Payment must be made as per agreed terms.", footerSplitX + 8f, y + 23f, paint)
        canvas.drawText("2. Taxes charged per prevailing GST regulations.", footerSplitX + 8f, y + 33f, paint)
        canvas.drawText("3. Disputes subject to seller's local jurisdiction.", footerSplitX + 8f, y + 43f, paint)

        // Declaration & Signatory
        val declY = y + footerH - 32f
        canvas.drawLine(leftMargin, declY, rightMargin, declY, paint)

        val declSplitX = rightMargin - 150f
        canvas.drawLine(declSplitX, declY, declSplitX, y + footerH, paint)

        paint.textSize = 6.8f
        paint.color = Color.rgb(100, 116, 139)
        canvas.drawText("Declaration: We declare that this invoice shows the actual price of the goods/services described and that", leftMargin + 8f, declY + 12f, paint)
        canvas.drawText("all particulars are true and correct.", leftMargin + 8f, declY + 22f, paint)

        // Authorized Signatory
        paint.textAlign = Paint.Align.CENTER
        boldPaint.textSize = 8f
        boldPaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("Authorized Signatory", declSplitX + 75f, declY + 16f, boldPaint)
        paint.textSize = 7f
        paint.color = Color.rgb(100, 116, 139)
        canvas.drawText(supplierName.uppercase(), declSplitX + 75f, declY + 26f, paint)
        paint.textAlign = Paint.Align.LEFT

        pdfDocument.finishPage(page)

        val cleanDocNo = docNumber.replace(Regex("[^a-zA-Z0-9_-]"), "_")
        val pdfFile = File(context.cacheDir, "Invoice_${cleanDocNo}.pdf")
        FileOutputStream(pdfFile).use { out ->
            pdfDocument.writeTo(out)
        }
        pdfDocument.close()

        return pdfFile
    }

    /**
     * Downloads/Saves PDF to public Downloads directory and opens with Intent Chooser
     */
    fun downloadAndOpenPdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?) {
        try {
            val pdfFile = generateInvoicePdf(context, transaction, company)
            val cleanDocNo = transaction.docNumber.ifBlank { "INV-0001" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
            val fileName = "Invoice_${cleanDocNo}.pdf"

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/pdf")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val resolver = context.contentResolver
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (uri != null) {
                    resolver.openOutputStream(uri)?.use { output ->
                        pdfFile.inputStream().use { input ->
                            input.copyTo(output)
                        }
                    }
                }
            } else {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloadsDir.exists()) downloadsDir.mkdirs()
                val targetFile = File(downloadsDir, fileName)
                pdfFile.copyTo(targetFile, overwrite = true)
            }

            Toast.makeText(context, "Invoice saved to Downloads: $fileName", Toast.LENGTH_SHORT).show()

            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                pdfFile
            )

            val viewIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/pdf")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            val chooser = Intent.createChooser(viewIntent, "Open Invoice PDF")
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(chooser)
        } catch (e: Exception) {
            Toast.makeText(context, "Error saving PDF: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
        }
    }

    /**
     * Shares the exact generated PDF file to WhatsApp or Android share sheet safely
     */
    fun sharePdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?, targetWhatsApp: Boolean = false) {
        try {
            val pdfFile = generateInvoicePdf(context, transaction, company)
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                pdfFile
            )

            val docNo = transaction.docNumber.ifBlank { "INV-0001" }
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/pdf"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "Tax Invoice $docNo")
                val msg = "Please find attached Tax Invoice $docNo from ${company?.companyName ?: "Rajugari Ventures"}.\nTotal Amount: ${IndianCurrencyFormatter.format(transaction.summary.totalAmount)}"
                putExtra(Intent.EXTRA_TEXT, msg)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            if (targetWhatsApp) {
                val pm = context.packageManager
                val isRegularInstalled = isPackageInstalled("com.whatsapp", pm)
                val isBusinessInstalled = isPackageInstalled("com.whatsapp.w4b", pm)

                if (isRegularInstalled) {
                    shareIntent.setPackage("com.whatsapp")
                } else if (isBusinessInstalled) {
                    shareIntent.setPackage("com.whatsapp.w4b")
                }
            }

            val chooser = Intent.createChooser(shareIntent, "Share Invoice PDF")
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(chooser)
        } catch (e: Exception) {
            Toast.makeText(context, "Error sharing PDF: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
        }
    }

    private fun isPackageInstalled(packageName: String, packageManager: PackageManager): Boolean {
        return try {
            packageManager.getPackageInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }
}
