package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.util.Log
import android.webkit.*
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

    // Escape string values for JS injection
    val safeServiceName = serviceName.replace("\"", "\\\"").replace("'", "\\'")
    val safePackageName = packageName.replace("\"", "\\\"").replace("'", "\\'")
    val safeCustomerName = customerName.replace("\"", "\\\"").replace("'", "\\'")
    val safeCustomerEmail = customerEmail.replace("\"", "\\\"").replace("'", "\\'")
    val safeCustomerPhone = customerPhone.replace("\"", "\\\"").replace("'", "\\'")
    
    val htmlContent = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <meta charset="utf-8">
            <style>
                * { box-sizing: border-box; }
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
                    color: #334155;
                    text-align: center;
                }
                .loader {
                    border: 4px solid #E2E8F0;
                    border-top: 4px solid #4F46E5;
                    border-radius: 50%;
                    width: 44px;
                    height: 44px;
                    animation: spin 0.8s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                h3 {
                    margin: 0 0 8px 0;
                    font-weight: 800;
                    font-size: 17px;
                    color: #0F172A;
                }
                p {
                    font-size: 13px;
                    color: #64748B;
                    margin: 0;
                    line-height: 1.4;
                }
                #error-box {
                    display: none;
                    margin-top: 16px;
                    padding: 12px;
                    background: #FEE2E2;
                    border-radius: 8px;
                    color: #DC2626;
                    font-size: 12px;
                    max-width: 90%;
                    word-break: break-word;
                }
            </style>
        </head>
        <body>
            <div class="loader" id="loader"></div>
            <h3 id="status-title">Connecting to Payment Gateway</h3>
            <p id="status-desc">Initializing secure checkout session...</p>
            <div id="error-box"></div>

            <script>
                function sendToAndroid(eventData) {
                    try {
                        if (window.AndroidInterface && window.AndroidInterface.postMessage) {
                            window.AndroidInterface.postMessage(JSON.stringify(eventData));
                        }
                    } catch(e) {
                        console.error("Failed sending message to Android:", e);
                    }
                }

                function showError(msg) {
                    var errBox = document.getElementById('error-box');
                    if (errBox) {
                        errBox.style.display = 'block';
                        errBox.innerText = msg;
                    }
                    var statusTitle = document.getElementById('status-title');
                    if (statusTitle) statusTitle.innerText = "Payment Gateway Notice";
                }

                function initRazorpay() {
                    try {
                        if (typeof Razorpay === 'undefined') {
                            showError("Razorpay SDK could not be loaded. Please check your internet connection.");
                            sendToAndroid({
                                "event": "onPaymentFailure",
                                "error": "Razorpay SDK failed to load"
                            });
                            return;
                        }

                        var options = {
                            "key": "$key",
                            "amount": "$amount",
                            "currency": "$currency",
                            "name": "VR HERE Business Solutions",
                            "description": "$safeServiceName - $safePackageName",
                            "order_id": "$orderId",
                            "prefill": {
                                "name": "$safeCustomerName",
                                "email": "$safeCustomerEmail",
                                "contact": "$safeCustomerPhone"
                            },
                            "theme": {
                                "color": "#4F46E5"
                            },
                            "modal": {
                                "ondismiss": function() {
                                    sendToAndroid({
                                        "event": "onPaymentCancelled"
                                    });
                                },
                                "backdropclose": false,
                                "escape": false,
                                "handleback": true
                            },
                            "handler": function (response) {
                                sendToAndroid({
                                    "event": "onPaymentSuccess",
                                    "paymentId": response.razorpay_payment_id || "",
                                    "orderId": response.razorpay_order_id || "$orderId",
                                    "signature": response.razorpay_signature || ""
                                });
                            }
                        };

                        var rzp = new Razorpay(options);
                        rzp.on('payment.failed', function (response) {
                            var errMsg = (response.error && response.error.description) ? response.error.description : 'Payment Failed';
                            showError(errMsg);
                            sendToAndroid({
                                "event": "onPaymentFailure",
                                "error": errMsg
                            });
                        });

                        // Open checkout modal immediately
                        rzp.open();
                    } catch(err) {
                        showError("Initialization Error: " + err.message);
                        sendToAndroid({
                            "event": "onPaymentFailure",
                            "error": err.message
                        });
                    }
                }

                // Dynamically inject Razorpay script tag with robust onload handling
                (function() {
                    var script = document.createElement('script');
                    script.src = "https://checkout.razorpay.com/v1/checkout.js";
                    script.async = true;
                    script.onload = function() {
                        initRazorpay();
                    };
                    script.onerror = function() {
                        showError("Failed to load checkout script from Razorpay CDN.");
                        sendToAndroid({
                            "event": "onPaymentFailure",
                            "error": "Failed to load checkout.js"
                        });
                    };
                    document.head.appendChild(script);
                })();
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
            modifier = Modifier.fillMaxSize()
        ) {
            // Header bar
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
                            color = Color(0xFF4F46E5),
                            letterSpacing = 0.5.sp
                        )
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .background(Color(0xFF22C55E), shape = CircleShape)
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
                factory = { ctx ->
                    WebView(ctx).apply {
                        settings.apply {
                            javaScriptEnabled = true
                            domStorageEnabled = true
                            databaseEnabled = true
                            javaScriptCanOpenWindowsAutomatically = true
                            setSupportMultipleWindows(false)
                            mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                            allowContentAccess = true
                            allowFileAccess = true
                            loadWithOverviewMode = true
                            useWideViewPort = true
                        }

                        webChromeClient = object : WebChromeClient() {
                            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                                Log.d("RazorpayWebView", "JS Console: ${consoleMessage?.message()} [line: ${consoleMessage?.lineNumber()}]")
                                return true
                            }
                        }

                        webViewClient = object : WebViewClient() {
                            override fun onReceivedError(view: WebView?, errorCode: Int, description: String?, failingUrl: String?) {
                                Log.e("RazorpayWebView", "WebView Error: $description ($errorCode) for $failingUrl")
                            }
                        }

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
                                                    data.optString("orderId", orderId),
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

                        // Load with the registered domain URL
                        loadDataWithBaseURL("https://vrhere.in/", htmlContent, "text/html", "UTF-8", null)
                    }
                }
            )
        }
    }
}
