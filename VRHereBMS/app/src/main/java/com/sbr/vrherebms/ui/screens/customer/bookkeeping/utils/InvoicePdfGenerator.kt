package com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.pdf.PdfDocument
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
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
     * Converts the exact Web HTML Template to a vector A4 PDF using Android's Chromium Print Engine
     */
    fun generateInvoicePdf(
        context: Context,
        transaction: TransactionDto,
        company: CompanyDetailsDto?,
        onComplete: (File) -> Unit
    ) {
        val mainHandler = Handler(Looper.getMainLooper())
        mainHandler.post {
            try {
                val html = InvoiceHtmlBuilder.buildHtml(transaction, company)
                val cleanDocNo = transaction.docNumber.ifBlank { "INV-0001" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
                val pdfFile = File(context.cacheDir, "Invoice_${cleanDocNo}.pdf")

                val webView = WebView(context)
                webView.settings.javaScriptEnabled = true
                webView.settings.domStorageEnabled = true

                webView.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(view: WebView?, url: String?) {
                        try {
                            val printAdapter = webView.createPrintDocumentAdapter("Invoice_${cleanDocNo}")
                            val printAttributes = PrintAttributes.Builder()
                                .setMediaSize(PrintAttributes.MediaSize.ISO_A4)
                                .setResolution(PrintAttributes.Resolution("pdf", "pdf", 300, 300))
                                .setMinMargins(PrintAttributes.Margins.NO_MARGINS)
                                .build()

                            val pfd = ParcelFileDescriptor.open(
                                pdfFile,
                                ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_TRUNCATE
                            )

                            printAdapter.onLayout(
                                null,
                                printAttributes,
                                null,
                                object : PrintDocumentAdapter.LayoutResultCallback() {
                                    override fun onLayoutFinished(info: PrintDocumentInfo?, changed: Boolean) {
                                        printAdapter.onWrite(
                                            arrayOf(PageRange.ALL_PAGES),
                                            pfd,
                                            null,
                                            object : PrintDocumentAdapter.WriteResultCallback() {
                                                override fun onWriteFinished(pages: Array<out PageRange>?) {
                                                    try {
                                                        pfd.close()
                                                    } catch (e: Exception) {}
                                                    onComplete(pdfFile)
                                                }

                                                override fun onWriteFailed(error: CharSequence?) {
                                                    try { pfd.close() } catch (e: Exception) {}
                                                    onComplete(pdfFile)
                                                }
                                            }
                                        )
                                    }

                                    override fun onLayoutFailed(error: CharSequence?) {
                                        try { pfd.close() } catch (e: Exception) {}
                                        onComplete(pdfFile)
                                    }
                                },
                                null
                            )
                        } catch (e: Exception) {
                            onComplete(pdfFile)
                        }
                    }
                }

                webView.loadDataWithBaseURL("https://vrhere.in/", html, "text/html", "UTF-8", null)
            } catch (e: Exception) {
                val cleanDocNo = transaction.docNumber.ifBlank { "INV-0001" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
                val pdfFile = File(context.cacheDir, "Invoice_${cleanDocNo}.pdf")
                onComplete(pdfFile)
            }
        }
    }

    /**
     * Downloads/Saves PDF to public Downloads directory and opens with Intent Chooser
     */
    fun downloadAndOpenPdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?) {
        Toast.makeText(context, "Generating invoice PDF...", Toast.LENGTH_SHORT).show()
        generateInvoicePdf(context, transaction, company) { pdfFile ->
            try {
                val cleanDocNo = transaction.docNumber.ifBlank { "INV-0001" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
                val fileName = "Invoice_${cleanDocNo}.pdf"

                // Save to Public Downloads folder
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

                Toast.makeText(context, "Invoice saved to Downloads: $fileName", Toast.LENGTH_LONG).show()

                // Open with View Intent Chooser
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
                Toast.makeText(context, "Error opening PDF: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
            }
        }
    }

    /**
     * Shares the exact generated PDF file to WhatsApp or Android share sheet safely
     */
    fun sharePdf(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?, targetWhatsApp: Boolean = false) {
        Toast.makeText(context, "Preparing PDF for sharing...", Toast.LENGTH_SHORT).show()
        generateInvoicePdf(context, transaction, company) { pdfFile ->
            try {
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
    }

    /**
     * Triggers Android's Native System Print Dialog (Print / Save as PDF)
     */
    fun printInvoice(context: Context, transaction: TransactionDto, company: CompanyDetailsDto?) {
        val mainHandler = Handler(Looper.getMainLooper())
        mainHandler.post {
            try {
                val html = InvoiceHtmlBuilder.buildHtml(transaction, company)
                val cleanDocNo = transaction.docNumber.ifBlank { "INV-0001" }

                val webView = WebView(context)
                webView.settings.javaScriptEnabled = true
                webView.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(view: WebView?, url: String?) {
                        val printManager = context.getSystemService(Context.PRINT_SERVICE) as? PrintManager
                        val printAdapter = webView.createPrintDocumentAdapter("Invoice_${cleanDocNo}")
                        printManager?.print("Invoice_${cleanDocNo}", printAdapter, PrintAttributes.Builder().build())
                    }
                }
                webView.loadDataWithBaseURL("https://vrhere.in/", html, "text/html", "UTF-8", null)
            } catch (e: Exception) {
                Toast.makeText(context, "Error opening Print dialog: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
            }
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
