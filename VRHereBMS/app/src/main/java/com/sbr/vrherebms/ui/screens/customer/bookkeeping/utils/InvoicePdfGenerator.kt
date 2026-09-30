package com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils

import android.content.Context
import android.content.Intent
import android.graphics.*
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Environment
import android.widget.Toast
import androidx.core.content.FileProvider
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto
import java.io.File
import java.io.FileOutputStream

object InvoicePdfGenerator {

    /**
     * Generates a standard A4 PDF Document (595 x 842 points) matching the web template
     */
    fun generateInvoicePdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?): File {
        val pdfDocument = PdfDocument()
        val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()
        val page = pdfDocument.startPage(pageInfo)
        val canvas = page.canvas

        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        val titlePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        }

        val isSales = transaction.transactionType.equals("Sales", ignoreCase = true)
        val isPurchase = transaction.transactionType.equals("Purchase", ignoreCase = true)
        val isIncome = transaction.transactionType.equals("Income", ignoreCase = true)
        val isExpense = transaction.transactionType.equals("Expense", ignoreCase = true)

        val docTitle = when {
            isIncome -> "RECEIPT VOUCHER"
            isExpense -> "PAYMENT VOUCHER"
            isPurchase -> "PURCHASE INVOICE"
            else -> "TAX INVOICE"
        }

        val copyType = transaction.copyType.ifBlank { "Original for Recipient" }

        // Supplier details (Company or Party depending on transaction)
        val supplierName = if (isSales || isIncome || isExpense) {
            company?.companyName?.ifBlank { null } ?: "VR HERE Business Solutions"
        } else {
            transaction.partyName
        }

        val supplierGstin = if (isSales || isIncome || isExpense) company?.gstin ?: "" else transaction.partyGstin
        val supplierAddress = if (isSales || isIncome || isExpense) company?.address ?: "Tirupati, Andhra Pradesh" else transaction.partyAddress
        val supplierPhone = if (isSales || isIncome || isExpense) company?.phone ?: "" else transaction.partyPhone

        val billToName = if (isSales) transaction.partyName else company?.companyName ?: "VR HERE Business Solutions"
        val billToGstin = if (isSales) transaction.partyGstin else company?.gstin ?: ""
        val billToAddress = if (isSales) transaction.partyAddress else company?.address ?: ""

        val margin = 28f
        val rightMargin = 595f - margin
        var y = 30f

        // 1. Top Copy Indicator
        paint.color = Color.rgb(100, 116, 139)
        paint.textSize = 8.5f
        paint.textAlign = Paint.Align.RIGHT
        canvas.drawText("COPY: ${copyType.uppercase()}", rightMargin, y, paint)
        paint.textAlign = Paint.Align.LEFT
        y += 12f

        // 2. Main Outer Header Box
        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(248, 250, 252)
        canvas.drawRect(margin, y, rightMargin, y + 80f, paint)

        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.5f
        canvas.drawRect(margin, y, rightMargin, y + 80f, paint)

        // Company Details (Left)
        titlePaint.color = Color.rgb(15, 23, 42)
        titlePaint.textSize = 13f
        canvas.drawText(supplierName, margin + 12f, y + 20f, titlePaint)

        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 8.5f
        canvas.drawText(supplierAddress.take(45), margin + 12f, y + 34f, paint)
        if (supplierGstin.isNotBlank()) {
            paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("GSTIN: $supplierGstin", margin + 12f, y + 48f, paint)
            paint.typeface = Typeface.DEFAULT
        }
        if (supplierPhone.isNotBlank()) {
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("Phone: $supplierPhone", margin + 12f, y + 62f, paint)
        }

        // Invoice Metadata Box (Right)
        val metaX = rightMargin - 180f
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1f
        canvas.drawLine(metaX, y, metaX, y + 80f, paint)

        // Document Title Pill
        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawRect(metaX + 10f, y + 8f, rightMargin - 10f, y + 26f, paint)

        paint.color = Color.WHITE
        paint.textSize = 10f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        paint.textAlign = Paint.Align.CENTER
        canvas.drawText(docTitle, metaX + 85f, y + 21f, paint)
        paint.textAlign = Paint.Align.LEFT
        paint.typeface = Typeface.DEFAULT

        // Doc details
        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 8.5f
        canvas.drawText("Invoice No.:", metaX + 10f, y + 40f, paint)
        paint.color = Color.rgb(15, 23, 42)
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText(transaction.docNumber, rightMargin - 90f, y + 40f, paint)
        paint.typeface = Typeface.DEFAULT

        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("Date:", metaX + 10f, y + 54f, paint)
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawText(transaction.docDate.take(10), rightMargin - 90f, y + 54f, paint)

        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("Place of Supply:", metaX + 10f, y + 68f, paint)
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawText(transaction.placeOfSupply.take(16), rightMargin - 90f, y + 68f, paint)

        y += 80f

        // 3. Parties Box (BILL TO & SHIP TO)
        val partiesHeight = 65f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.5f
        canvas.drawRect(margin, y, rightMargin, y + partiesHeight, paint)

        val splitX = margin + (rightMargin - margin) / 2f
        canvas.drawLine(splitX, y, splitX, y + partiesHeight, paint)

        // BILL TO Header
        paint.style = Paint.Style.FILL
        titlePaint.textSize = 9.5f
        titlePaint.color = Color.rgb(79, 70, 229)
        canvas.drawText("BILL TO", margin + 10f, y + 14f, titlePaint)

        titlePaint.textSize = 9f
        titlePaint.color = Color.rgb(15, 23, 42)
        canvas.drawText(billToName.take(30), margin + 10f, y + 27f, titlePaint)

        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 8f
        canvas.drawText(billToAddress.take(35), margin + 10f, y + 38f, paint)
        if (billToGstin.isNotBlank()) {
            canvas.drawText("GSTIN: $billToGstin", margin + 10f, y + 49f, paint)
        }

        // SHIP TO Header
        titlePaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("SHIP TO (Consignee)", splitX + 10f, y + 14f, titlePaint)
        canvas.drawText(billToName.take(30), splitX + 10f, y + 27f, titlePaint)
        canvas.drawText(billToAddress.take(35), splitX + 10f, y + 38f, paint)
        if (billToGstin.isNotBlank()) {
            canvas.drawText("GSTIN: $billToGstin", splitX + 10f, y + 49f, paint)
        }

        y += partiesHeight

        // 4. Compact 10-Column Items Table
        val colWidths = floatArrayOf(24f, 160f, 50f, 32f, 32f, 48f, 40f, 40f, 55f, 58f)
        val colHeaders = arrayOf("#", "Description", "HSN/SAC", "Qty", "Unit", "Rate (₹)", "Disc %", "GST %", "Taxable", "Total (₹)")

        // Table Header Row
        val headerH = 20f
        paint.style = Paint.Style.FILL
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawRect(margin, y, rightMargin, y + headerH, paint)

        paint.color = Color.WHITE
        paint.textSize = 7.5f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)

        var curColX = margin
        for (i in colHeaders.indices) {
            val alignCenter = i == 0 || i == 2 || i == 3 || i == 4
            val alignRight = i >= 5
            val textX = if (alignRight) curColX + colWidths[i] - 4f
            else if (alignCenter) curColX + (colWidths[i] / 2f)
            else curColX + 4f

            if (alignRight) paint.textAlign = Paint.Align.RIGHT
            else if (alignCenter) paint.textAlign = Paint.Align.CENTER
            else paint.textAlign = Paint.Align.LEFT

            canvas.drawText(colHeaders[i], textX, y + 13f, paint)
            curColX += colWidths[i]
        }
        y += headerH

        // Table Items Rows
        paint.typeface = Typeface.DEFAULT
        val rowHeight = 20f

        transaction.items.forEachIndexed { idx, item ->
            // Zebra striping
            paint.style = Paint.Style.FILL
            paint.color = if (idx % 2 == 0) Color.WHITE else Color.rgb(248, 250, 252)
            canvas.drawRect(margin, y, rightMargin, y + rowHeight, paint)

            paint.style = Paint.Style.STROKE
            paint.color = Color.rgb(226, 232, 240)
            paint.strokeWidth = 0.5f
            canvas.drawRect(margin, y, rightMargin, y + rowHeight, paint)

            paint.style = Paint.Style.FILL
            paint.color = Color.rgb(15, 23, 42)
            paint.textSize = 8f

            var colX = margin
            val vals = arrayOf(
                "${idx + 1}",
                item.description.take(24),
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

                if (i == 1 || i == 9) paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
                else paint.typeface = Typeface.DEFAULT

                canvas.drawText(vals[i], textX, y + 13f, paint)
                colX += colWidths[i]
            }

            y += rowHeight
        }

        // 5. Summary & Tax Calculation Box
        val summaryBoxH = 85f
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1.5f
        canvas.drawRect(margin, y, rightMargin, y + summaryBoxH, paint)

        val summarySplitX = margin + 330f
        canvas.drawLine(summarySplitX, y, summarySplitX, y + summaryBoxH, paint)

        // Left: Amount in Words & Bank Details
        paint.style = Paint.Style.FILL
        titlePaint.textSize = 8f
        titlePaint.color = Color.rgb(100, 116, 139)
        canvas.drawText("AMOUNT IN WORDS:", margin + 8f, y + 14f, titlePaint)

        titlePaint.textSize = 8.5f
        titlePaint.color = Color.rgb(15, 23, 42)
        val words = transaction.summary.amountInWords.ifBlank { IndianCurrencyFormatter.numberToWords(transaction.summary.totalAmount) }
        canvas.drawText(words.take(50), margin + 8f, y + 26f, titlePaint)

        paint.color = Color.rgb(203, 213, 225)
        canvas.drawLine(margin + 8f, y + 36f, summarySplitX - 8f, y + 36f, paint)

        paint.color = Color.rgb(71, 85, 105)
        paint.textSize = 8f
        val bankInfo = company?.bankDetails
        canvas.drawText("Bank: ${bankInfo?.bankName ?: "HDFC Bank"} | A/c: ${bankInfo?.accountNumber ?: "50200012345678"}", margin + 8f, y + 48f, paint)
        canvas.drawText("IFSC: ${bankInfo?.ifscCode ?: "HDFC0001234"} | UPI: ${company?.upiId ?: "vrhere@upi"}", margin + 8f, y + 60f, paint)

        // Right: Totals Breakdown
        var rightY = y + 14f
        paint.textSize = 8.5f
        paint.textAlign = Paint.Align.LEFT
        paint.color = Color.rgb(71, 85, 105)
        canvas.drawText("Taxable Subtotal:", summarySplitX + 8f, rightY, paint)
        paint.textAlign = Paint.Align.RIGHT
        paint.color = Color.rgb(15, 23, 42)
        canvas.drawText("₹%.2f".format(transaction.summary.totalTaxableValue), rightMargin - 8f, rightY, paint)

        if (transaction.summary.totalCgst > 0) {
            rightY += 12f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("CGST:", summarySplitX + 8f, rightY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(transaction.summary.totalCgst), rightMargin - 8f, rightY, paint)

            rightY += 12f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("SGST:", summarySplitX + 8f, rightY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(transaction.summary.totalSgst), rightMargin - 8f, rightY, paint)
        } else if (transaction.summary.totalIgst > 0) {
            rightY += 12f
            paint.textAlign = Paint.Align.LEFT
            paint.color = Color.rgb(71, 85, 105)
            canvas.drawText("IGST:", summarySplitX + 8f, rightY, paint)
            paint.textAlign = Paint.Align.RIGHT
            paint.color = Color.rgb(15, 23, 42)
            canvas.drawText("₹%.2f".format(transaction.summary.totalIgst), rightMargin - 8f, rightY, paint)
        }

        // Grand Total Row
        rightY = y + summaryBoxH - 12f
        paint.color = Color.rgb(15, 23, 42)
        paint.strokeWidth = 1f
        canvas.drawLine(summarySplitX, rightY - 14f, rightMargin, rightY - 14f, paint)

        paint.textAlign = Paint.Align.LEFT
        titlePaint.textSize = 10.5f
        titlePaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("GRAND TOTAL:", summarySplitX + 8f, rightY, titlePaint)

        paint.textAlign = Paint.Align.RIGHT
        titlePaint.color = Color.rgb(79, 70, 229)
        val grandTotal = if (transaction.summary.totalAmount > 0) transaction.summary.totalAmount else transaction.items.sumOf { it.total }
        canvas.drawText(IndianCurrencyFormatter.format(grandTotal), rightMargin - 8f, rightY, titlePaint)
        paint.textAlign = Paint.Align.LEFT

        y += summaryBoxH + 12f

        // 6. Terms & Signature Block
        paint.style = Paint.Style.STROKE
        paint.color = Color.rgb(203, 213, 225)
        paint.strokeWidth = 1f
        canvas.drawRect(margin, y, rightMargin, y + 60f, paint)

        paint.style = Paint.Style.FILL
        titlePaint.textSize = 8f
        titlePaint.color = Color.rgb(15, 23, 42)
        canvas.drawText("Terms & Conditions:", margin + 8f, y + 14f, titlePaint)

        paint.color = Color.rgb(100, 116, 139)
        paint.textSize = 7.5f
        canvas.drawText("1. Payment must be made as per agreed terms.", margin + 8f, y + 25f, paint)
        canvas.drawText("2. Taxes charged per prevailing GST regulations.", margin + 8f, y + 35f, paint)
        canvas.drawText("3. Disputes subject to seller's local jurisdiction.", margin + 8f, y + 45f, paint)

        // Signature
        val sigX = rightMargin - 150f
        paint.color = Color.rgb(15, 23, 42)
        paint.textSize = 8f
        paint.typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
        canvas.drawText("For $supplierName", sigX, y + 16f, paint)

        paint.strokeWidth = 0.8f
        canvas.drawLine(sigX, y + 44f, rightMargin - 10f, y + 44f, paint)
        paint.typeface = Typeface.DEFAULT
        paint.textSize = 7.5f
        paint.color = Color.rgb(100, 116, 139)
        canvas.drawText("Authorized Signatory", sigX + 15f, y + 54f, paint)

        pdfDocument.finishPage(page)

        // Save PDF to cache file
        val cleanDocNo = transaction.docNumber.replace(Regex("[^a-zA-Z0-9_-]"), "_")
        val pdfFile = File(context.cacheDir, "Invoice_${cleanDocNo}.pdf")
        FileOutputStream(pdfFile).use { out ->
            pdfDocument.writeTo(out)
        }
        pdfDocument.close()

        return pdfFile
    }

    /**
     * Downloads/Saves PDF and triggers native Android View Intent
     */
    fun downloadAndOpenPdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?) {
        try {
            val pdfFile = generateInvoicePdf(context, transaction, company)
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

            val chooser = Intent.createChooser(viewIntent, "Open PDF Invoice")
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(chooser)
        } catch (e: Exception) {
            Toast.makeText(context, "Error opening PDF: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
        }
    }

    /**
     * Shares the actual generated PDF file to WhatsApp or Android share sheet
     */
    fun sharePdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?, targetWhatsApp: Boolean = false) {
        try {
            val pdfFile = generateInvoicePdf(context, transaction, company)
            val uri: Uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                pdfFile
            )

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/pdf"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "Tax Invoice ${transaction.docNumber}")
                val msg = "Please find attached Tax Invoice ${transaction.docNumber} from ${company?.companyName ?: "VR HERE"}.\nTotal Amount: ${IndianCurrencyFormatter.format(transaction.summary.totalAmount)}"
                putExtra(Intent.EXTRA_TEXT, msg)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            if (targetWhatsApp) {
                shareIntent.setPackage("com.whatsapp")
            }

            try {
                val chooser = Intent.createChooser(shareIntent, "Share Invoice PDF")
                chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(chooser)
            } catch (e: Exception) {
                // Fallback to general chooser if WhatsApp specific package is not found
                shareIntent.setPackage(null)
                val chooser = Intent.createChooser(shareIntent, "Share Invoice PDF")
                chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(chooser)
            }
        } catch (e: Exception) {
            Toast.makeText(context, "Error sharing PDF: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
        }
    }
}
