package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView

class RazorpayPaymentInterface(
    private val onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
    private val onFailure: (errorMsg: String) -> Unit
) {
    @JavascriptInterface
    fun onPaymentSuccess(paymentId: String, orderId: String, signature: String) {
        onSuccess(paymentId, orderId, signature)
    }

    @JavascriptInterface
    fun onPaymentFailure(error: String) {
        onFailure(error)
    }

    @JavascriptInterface
    fun onPaymentCancelled() {
        onFailure("Payment cancelled by user")
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun CustomerPaymentWebView(
    key: String,
    orderId: String,
    amount: Long,
    currency: String,
    serviceName: String,
    packageName: String,
    customerName: String,
    customerEmail: String,
    customerPhone: String,
    onSuccess: (paymentId: String, orderId: String, signature: String) -> Unit,
    onFailure: (errorMsg: String) -> Unit,
    onClose: () -> Unit
) {
    var webViewInstance by remember { mutableStateOf<WebView?>(null) }

    // Intercept back button to prompt cancel or close safely
    BackHandler(enabled = true) {
        onClose()
    }

    val htmlContent = remember {
        """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
            <style>
                body {
                    background-color: #F8FAFC;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    padding: 20px;
                    box-sizing: border-box;
                    color: #334155;
                    text-align: center;
                }
                .loader {
                    border: 4px solid #E2E8F0;
                    border-top: 4px solid #6366F1;
                    border-radius: 50%;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                h3 {
                    margin: 0 0 8px 0;
                    font-weight: 800;
                }
                p {
                    font-size: 14px;
                    color: #64748B;
                    margin: 0;
                }
            </style>
        </head>
        <body>
            <div class="loader"></div>
            <h3>Securely Connecting to Gateway</h3>
            <p>Please do not close or press back...</p>

            <script>
                window.onload = function() {
                    var options = {
                        "key": "$key",
                        "amount": "$amount",
                        "currency": "$currency",
                        "name": "VR HERE",
                        "description": "$serviceName - $packageName",
                        "order_id": "$orderId",
                        "prefill": {
                            "name": "$customerName",
                            "email": "$customerEmail",
                            "contact": "$customerPhone"
                        },
                        "theme": {
                            "color": "#6366F1"
                        },
                        "handler": function (response) {
                            AndroidInterface.onPaymentSuccess(
                                response.razorpay_payment_id,
                                response.razorpay_order_id,
                                response.razorpay_signature
                            );
                        },
                        "modal": {
                            "ondismiss": function() {
                                AndroidInterface.onPaymentCancelled();
                            }
                        }
                    };
                    var rzp = new Razorpay(options);
                    rzp.on('payment.failed', function (response){
                        AndroidInterface.onPaymentFailure(response.error.description || 'Payment Failed');
                    });
                    rzp.open();
                };
            </script>
        </body>
        </html>
        """.trimIndent()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.White)
    ) {
        // WebView Header Topbar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
                .background(Color.White)
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onClose,
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = "Cancel Payment",
                    tint = Color(0xFF475569),
                    modifier = Modifier.size(24.dp)
                )
            }

            Text(
                text = "Secure Checkout",
                color = Color(0xFF1E293B),
                fontSize = 16.sp,
                fontWeight = FontWeight.Black,
                modifier = Modifier.weight(1f).padding(horizontal = 12.dp)
            )
        }
        HorizontalDivider(thickness = 1.dp, color = Color(0xFFF1F5F9))

        Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
            AndroidView(
                factory = { context ->
                    WebView(context).apply {
                        webViewInstance = this
                        settings.apply {
                            javaScriptEnabled = true
                            domStorageEnabled = true
                            databaseEnabled = true
                            useWideViewPort = true
                            loadWithOverviewMode = true
                        }
                        webViewClient = WebViewClient()
                        webChromeClient = WebChromeClient()
                        addJavascriptInterface(
                            RazorpayPaymentInterface(onSuccess, onFailure),
                            "AndroidInterface"
                        )
                        loadDataWithBaseURL("https://api.razorpay.com", htmlContent, "text/html", "UTF-8", null)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}
