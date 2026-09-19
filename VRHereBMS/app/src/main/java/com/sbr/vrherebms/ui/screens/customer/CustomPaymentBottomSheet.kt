package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

@SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CustomPaymentBottomSheet(
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
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val coroutineScope = rememberCoroutineScope()
    
    // HTML string mirroring the iOS implementation
    val htmlContent = """
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
                function sendToAndroid(eventData) {
                    if (window.AndroidInterface) {
                        window.AndroidInterface.postMessage(JSON.stringify(eventData));
                    }
                }

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
                            sendToAndroid({
                                "event": "onPaymentSuccess",
                                "paymentId": response.razorpay_payment_id,
                                "orderId": response.razorpay_order_id,
                                "signature": response.razorpay_signature
                            });
                        },
                        "modal": {
                            "ondismiss": function() {
                                sendToAndroid({
                                    "event": "onPaymentCancelled"
                                });
                            }
                        }
                    };
                    var rzp = new Razorpay(options);
                    rzp.on('payment.failed', function (response){
                        sendToAndroid({
                            "event": "onPaymentFailure",
                            "error": response.error.description || 'Payment Failed'
                        });
                    });
                    rzp.open();
                };
            </script>
        </body>
        </html>
    """.trimIndent()

    ModalBottomSheet(
        onDismissRequest = onClose,
        sheetState = sheetState,
        containerColor = Color.White,
        dragHandle = { BottomSheetDefaults.DragHandle() }
    ) {
        Column(
            modifier = Modifier.fillMaxSize() // Use fillMaxSize to expand the sheet fully to its maximum height allowed by ModalBottomSheet
        ) {
            // Header bar mirroring iOS
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 10.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "SECURE CHECKOUT",
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.Black,
                            color = Color(0xFF6366F1),
                            letterSpacing = 0.5.sp
                        )
                        Box(
                            modifier = Modifier
                                .size(5.dp)
                                .background(Color.Green, shape = CircleShape)
                        )
                    }
                    val displayPrice = if (amount > 100) amount / 100 else amount
                    Text(
                        text = "$serviceName • ₹$displayPrice",
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Black,
                        color = Color(0xFF0F172A),
                        maxLines = 1
                    )
                }
                
                IconButton(onClick = {
                    coroutineScope.launch { sheetState.hide() }
                    onClose()
                }) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = Color(0xFF94A3B8)
                    )
                }
            }

            HorizontalDivider(color = Color(0xFFF1F5F9))

            // Embedded Razorpay Payment Webview
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { context ->
                    WebView(context).apply {
                        settings.javaScriptEnabled = true
                        settings.domStorageEnabled = true
                        webViewClient = WebViewClient()

                        addJavascriptInterface(object : Any() {
                            @JavascriptInterface
                            fun postMessage(jsonString: String) {
                                coroutineScope.launch(Dispatchers.Main) {
                                    try {
                                        val data = JSONObject(jsonString)
                                        when (data.getString("event")) {
                                            "onPaymentSuccess" -> {
                                                onSuccess(
                                                    data.optString("paymentId", ""),
                                                    data.optString("orderId", ""),
                                                    data.optString("signature", "")
                                                )
                                            }
                                            "onPaymentFailure" -> {
                                                onFailure(data.optString("error", "Payment Failed"))
                                            }
                                            "onPaymentCancelled" -> {
                                                onFailure("Payment cancelled by user")
                                            }
                                        }
                                    } catch (e: Exception) {
                                        onFailure("Parse error: ${e.message}")
                                    }
                                }
                            }
                        }, "AndroidInterface")

                        loadDataWithBaseURL("https://api.razorpay.com", htmlContent, "text/html", "UTF-8", null)
                    }
                }
            )
        }
    }
}
