package com.sbr.vrherebms.ui.screens.customer.bookkeeping.dialogs

import android.annotation.SuppressLint
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.sbr.vrherebms.data.model.CompanyDetailsDto
import com.sbr.vrherebms.data.model.TransactionDto
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.InvoiceHtmlBuilder
import com.sbr.vrherebms.ui.screens.customer.bookkeeping.utils.InvoicePdfGenerator

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun GSTInvoicePreviewDialog(
    transaction: TransactionDto,
    companyDetails: CompanyDetailsDto?,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val htmlContent = remember(transaction, companyDetails) {
        InvoiceHtmlBuilder.buildHtml(transaction, companyDetails)
    }

    val docTitle = when {
        transaction.transactionType.equals("Income", ignoreCase = true) -> "Receipt Voucher"
        transaction.transactionType.equals("Expense", ignoreCase = true) -> "Payment Voucher"
        transaction.transactionType.equals("Purchase", ignoreCase = true) -> "Purchase Invoice"
        else -> "Tax Invoice"
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 6.dp, vertical = 12.dp),
            shape = RoundedCornerShape(16.dp),
            color = Color(0xFFF8FAFC),
            shadowElevation = 10.dp
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(8.dp)
            ) {
                // Top Web-Style Actions Bar
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = Color.White,
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        TextButton(
                            onClick = onDismiss,
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Color(0xFF334155), modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Back", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                        }

                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            // WhatsApp Button
                            Button(
                                onClick = {
                                    InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = true)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF059669)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("WhatsApp", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }

                            // Share PDF Button
                            Button(
                                onClick = {
                                    InvoicePdfGenerator.sharePdf(context, transaction, companyDetails, targetWhatsApp = false)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Text("Share PDF", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF334155))
                            }

                            // Print / Save PDF Button
                            Button(
                                onClick = {
                                    InvoicePdfGenerator.downloadAndOpenPdf(context, transaction, companyDetails)
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                                shape = RoundedCornerShape(10.dp),
                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                                modifier = Modifier.height(34.dp)
                            ) {
                                Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(13.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Print / Save PDF", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }

                // Pixel-Perfect Embedded Web Viewer displaying exact Web HTML & CSS with Logo
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
                    modifier = Modifier.fillMaxWidth().weight(1f)
                ) {
                    AndroidView(
                        factory = { ctx ->
                            WebView(ctx).apply {
                                settings.javaScriptEnabled = true
                                settings.domStorageEnabled = true
                                settings.loadWithOverviewMode = true
                                settings.useWideViewPort = true
                                settings.builtInZoomControls = true
                                settings.displayZoomControls = false
                                settings.cacheMode = WebSettings.LOAD_NO_CACHE
                                settings.layoutAlgorithm = WebSettings.LayoutAlgorithm.NORMAL

                                webViewClient = object : WebViewClient() {}
                                loadDataWithBaseURL("https://vrhere.in/", htmlContent, "text/html", "UTF-8", null)
                            }
                        },
                        update = { webView ->
                            webView.loadDataWithBaseURL("https://vrhere.in/", htmlContent, "text/html", "UTF-8", null)
                        },
                        modifier = Modifier.fillMaxSize()
                    )
                }
            }
        }
    }
}
