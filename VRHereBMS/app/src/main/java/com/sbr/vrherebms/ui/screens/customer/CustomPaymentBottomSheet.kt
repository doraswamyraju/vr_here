package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.os.Build
import android.util.Log
import android.view.View
import android.webkit.ConsoleMessage
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.json.JSONObject

@SuppressLint("SetJavaScriptEnabled", "JavascriptInterface")
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
    val coroutineScope = rememberCoroutineScope()
    var isVisible by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        isVisible = true
    }

    // Safely quote strings for JavaScript interpolation
    val safeKey = JSONObject.quote(key)
    val safeOrderId = JSONObject.quote(orderId)
    val safeCurrency = JSONObject.quote(currency)
    val safeDescription = JSONObject.quote("$serviceName - $packageName")
    val safeCustomerName = JSONObject.quote(customerName)
    val safeCustomerEmail = JSONObject.quote(customerEmail)
    val safeCustomerPhone = JSONObject.quote(customerPhone)

    val htmlContent = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
            <style>
                * { box-sizing: border-box; }
                html, body {
                    width: 100%;
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    background-color: #F8FAFC;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                }
                .loader-container {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    padding: 20px;
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
                h3 { margin: 0 0 8px 0; font-weight: 800; }
                p { font-size: 14px; color: #64748B; margin: 0; }
            </style>
        </head>
        <body>
            <div id="loader-box" class="loader-container">
                <div class="loader"></div>
                <h3>Securely Connecting to Gateway</h3>
                <p>Please do not close or press back...</p>
            </div>

            <script>
                function sendToAndroid(eventData) {
                    if (window.AndroidInterface && window.AndroidInterface.postMessage) {
                        window.AndroidInterface.postMessage(JSON.stringify(eventData));
                    }
                }

                function initRazorpay() {
                    if (typeof Razorpay === 'undefined') {
                        setTimeout(initRazorpay, 100);
                        return;
                    }

                    try {
                        var options = {
                            "key": $safeKey,
                            "amount": "$amount",
                            "currency": $safeCurrency,
                            "name": "VR HERE",
                            "description": $safeDescription,
                            "order_id": $safeOrderId,
                            "prefill": {
                                "name": $safeCustomerName,
                                "email": $safeCustomerEmail,
                                "contact": $safeCustomerPhone
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
                                "error": (response.error && response.error.description) || 'Payment Failed'
                            });
                        });
                        rzp.open();
                    } catch(err) {
                        sendToAndroid({
                            "event": "onPaymentFailure",
                            "error": err.message || 'Initialization error'
                        });
                    }
                }

                if (document.readyState === 'complete' || document.readyState === 'interactive') {
                    initRazorpay();
                } else {
                    window.addEventListener('DOMContentLoaded', initRazorpay);
                }
            </script>
        </body>
        </html>
    """.trimIndent()

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Transparent),
            contentAlignment = Alignment.BottomCenter
        ) {
            // Dimmed backdrop matching iOS Color.black.opacity(0.5)
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Color.Black.copy(alpha = 0.5f))
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null
                    ) {
                        onClose()
                    }
            )

            // Animated Bottom Sheet Container matching iOS geometry, corner radius (28dp), shadow & height (88%)
            AnimatedVisibility(
                visible = isVisible,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .fillMaxHeight(0.88f)
                        .shadow(elevation = 24.dp, shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp))
                        .background(Color.White, shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp))
                        .clip(RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Sheet Drag Grabber Handle matching iOS Capsule(203, 213, 225) 40x5dp
                    Box(
                        modifier = Modifier
                            .padding(top = 10.dp, bottom = 6.dp)
                            .width(40.dp)
                            .height(5.dp)
                            .background(Color(0xFFCBD5E1), shape = CircleShape)
                    )

                    // Header bar matching iOS HStack
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
                                        .background(Color(0xFF22C55E), shape = CircleShape)
                                )
                            }
                            Text(
                                text = "$serviceName • ₹$amount",
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        // Close button matching iOS Image(systemName: "xmark.circle.fill")
                        Box(
                            modifier = Modifier
                                .size(24.dp)
                                .clip(CircleShape)
                                .background(Color(0xFF94A3B8))
                                .clickable { onClose() },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Close,
                                contentDescription = "Close",
                                tint = Color.White,
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    }

                    HorizontalDivider(color = Color(0xFFF1F5F9), thickness = 1.dp)

                    // Embedded Razorpay Payment Webview
                    AndroidView(
                        modifier = Modifier.fillMaxSize(),
                        factory = { context ->
                            WebView(context).apply {
                                setLayerType(View.LAYER_TYPE_HARDWARE, null)

                                val cookieManager = CookieManager.getInstance()
                                cookieManager.setAcceptCookie(true)
                                cookieManager.setAcceptThirdPartyCookies(this, true)

                                settings.apply {
                                    javaScriptEnabled = true
                                    domStorageEnabled = true
                                    javaScriptCanOpenWindowsAutomatically = true
                                    setSupportMultipleWindows(false)
                                    mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                                    allowFileAccess = true
                                    allowContentAccess = true
                                    useWideViewPort = true
                                    loadWithOverviewMode = true
                                    userAgentString = "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
                                }

                                webViewClient = WebViewClient()
                                webChromeClient = object : WebChromeClient() {
                                    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                                        Log.d("RazorpayWebView", "${consoleMessage?.message()} -- From line ${consoleMessage?.lineNumber()} of ${consoleMessage?.sourceId()}")
                                        return true
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

                                loadDataWithBaseURL("https://api.razorpay.com/", htmlContent, "text/html", "UTF-8", null)
                            }
                        }
                    )
                }
            }
        }
    }
}



