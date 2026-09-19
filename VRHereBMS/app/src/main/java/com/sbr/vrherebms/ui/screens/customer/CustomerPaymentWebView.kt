package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Message
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
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

    @JavascriptInterface
    fun logJs(msg: String) {
        Log.d("RazorpayCheckout", msg)
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
    val context = LocalContext.current
    var webViewInstance by remember { mutableStateOf<WebView?>(null) }

    // Intercept back button to prompt cancel or close safely
    BackHandler(enabled = true) {
        onClose()
    }

    // Display price in Rupees for header
    val displayPriceRupees = if (amount > 1000) amount / 100 else amount

    val htmlContent = remember(key, orderId, amount, customerPhone, customerEmail) {
        """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <title>VR Here Secure Payment</title>
            <style>
                * { box-sizing: border-box; }
                body {
                    background-color: #FFFFFF;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    min-height: 80vh;
                    margin: 0;
                    padding: 24px;
                    color: #1E293B;
                    text-align: center;
                }
                .loader {
                    border: 4px solid #F1F5F9;
                    border-top: 4px solid #DC2626;
                    border-radius: 50%;
                    width: 44px;
                    height: 44px;
                    animation: spin 0.9s linear infinite;
                    margin-bottom: 20px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                h3 {
                    margin: 0 0 6px 0;
                    font-size: 17px;
                    font-weight: 800;
                    color: #0F172A;
                }
                p {
                    font-size: 13px;
                    color: #64748B;
                    margin: 0;
                    line-height: 1.5;
                }
                .badge {
                    display: inline-block;
                    margin-top: 14px;
                    padding: 5px 12px;
                    background: #FEF2F2;
                    color: #DC2626;
                    font-size: 11px;
                    font-weight: 700;
                    border-radius: 20px;
                    border: 1px solid #FECDD3;
                }
            </style>
        </head>
        <body>
            <div class="loader"></div>
            <h3>Connecting to Secure Gateway</h3>
            <p>Please wait while we initialize payment...</p>
            <div class="badge">256-bit Encrypted • RBI Compliant</div>

            <script>
                function log(msg) {
                    if (window.AndroidInterface && window.AndroidInterface.logJs) {
                        window.AndroidInterface.logJs(msg);
                    }
                }

                window.onerror = function(msg, url, line) {
                    log('JS Error: ' + msg + ' on line ' + line);
                };

                function launchCheckout() {
                    log('Starting Razorpay checkout initialization...');
                    try {
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
                                "color": "#DC2626"
                            },
                            "handler": function (response) {
                                log('Payment success callback received');
                                if (window.AndroidInterface) {
                                    window.AndroidInterface.onPaymentSuccess(
                                        response.razorpay_payment_id || '',
                                        response.razorpay_order_id || '$orderId',
                                        response.razorpay_signature || ''
                                    );
                                }
                            },
                            "modal": {
                                "ondismiss": function() {
                                    log('Payment modal dismissed by user');
                                    if (window.AndroidInterface) {
                                        window.AndroidInterface.onPaymentCancelled();
                                    }
                                }
                            }
                        };

                        var rzp = new Razorpay(options);
                        rzp.on('payment.failed', function (response){
                            log('Payment failed: ' + JSON.stringify(response.error));
                            if (window.AndroidInterface) {
                                window.AndroidInterface.onPaymentFailure((response.error && response.error.description) || 'Payment Failed');
                            }
                        });
                        rzp.open();
                        log('Razorpay modal open() called');
                    } catch (e) {
                        log('Exception in launchCheckout: ' + e.message);
                        if (window.AndroidInterface) {
                            window.AndroidInterface.onPaymentFailure(e.message || 'Error launching gateway');
                        }
                    }
                }

                // Dynamic Loader for Razorpay script to guarantee availability
                function loadScript() {
                    if (window.Razorpay) {
                        launchCheckout();
                        return;
                    }
                    var script = document.createElement('script');
                    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
                    script.async = true;
                    script.onload = function() {
                        log('Razorpay checkout.js script loaded');
                        setTimeout(launchCheckout, 100);
                    };
                    script.onerror = function() {
                        log('Failed to load Razorpay checkout.js script');
                        if (window.AndroidInterface) {
                            window.AndroidInterface.onPaymentFailure('Could not load payment gateway. Please check your internet connection.');
                        }
                    };
                    document.head.appendChild(script);
                }

                if (document.readyState === 'complete' || document.readyState === 'interactive') {
                    loadScript();
                } else {
                    window.addEventListener('DOMContentLoaded', loadScript);
                }
            </script>
        </body>
        </html>
        """.trimIndent()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.5f))
    ) {
        // Dismiss backdrop when tapping outside
        Box(
            modifier = Modifier
                .fillMaxSize()
                .clickable { onClose() }
        )

        // Bottom Sheet Container
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .fillMaxHeight(0.90f)
                .background(
                    color = Color.White,
                    shape = androidx.compose.foundation.shape.RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
                )
                .padding(top = 8.dp)
        ) {
            // Sheet Grabber Handle
            Box(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .width(40.dp)
                    .height(5.dp)
                    .background(
                        color = Color(0xFFCBD5E1),
                        shape = androidx.compose.foundation.shape.CircleShape
                    )
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = "SECURE CHECKOUT",
                            color = Color(0xFFDC2626),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 0.5.sp
                        )
                        Box(
                            modifier = Modifier
                                .size(6.dp)
                                .background(Color(0xFF10B981), androidx.compose.foundation.shape.CircleShape)
                        )
                    }
                    Text(
                        text = "$serviceName • ₹$displayPriceRupees",
                        color = Color(0xFF0F172A),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Black,
                        maxLines = 1
                    )
                }

                IconButton(
                    onClick = onClose,
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Cancel Payment",
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(22.dp)
                    )
                }
            }

            HorizontalDivider(thickness = 1.dp, color = Color(0xFFF1F5F9))

            // Embedded Razorpay WebView
            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                AndroidView(
                    factory = { ctx ->
                        WebView(ctx).apply {
                            webViewInstance = this
                            settings.apply {
                                javaScriptEnabled = true
                                domStorageEnabled = true
                                databaseEnabled = true
                                useWideViewPort = true
                                loadWithOverviewMode = true
                                javaScriptCanOpenWindowsAutomatically = true
                                setSupportMultipleWindows(true)
                                mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                                cacheMode = WebSettings.LOAD_DEFAULT
                                userAgentString = "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
                            }
                            webViewClient = object : WebViewClient() {
                                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                                    val url = request?.url?.toString() ?: return false
                                    Log.d("RazorpayCheckout", "Loading URL: $url")
                                    if (url.startsWith("http://") || url.startsWith("https://")) {
                                        return false
                                    }
                                    // Handle UPI, PhonePe, Paytm, GooglePay, WhatsApp deep links
                                    return try {
                                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
                                        context.startActivity(intent)
                                        true
                                    } catch (e: Exception) {
                                        Log.e("RazorpayCheckout", "Cannot open intent URL: $url", e)
                                        true
                                    }
                                }
                            }
                            webChromeClient = object : WebChromeClient() {
                                override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                                    Log.d("RazorpayCheckout_JS", "${consoleMessage?.message()} -- From line ${consoleMessage?.lineNumber()} of ${consoleMessage?.sourceId()}")
                                    return true
                                }

                                override fun onCreateWindow(view: WebView?, isDialog: Boolean, isUserGesture: Boolean, resultMsg: Message?): Boolean {
                                    val newWebView = WebView(view?.context ?: return false).apply {
                                        settings.javaScriptEnabled = true
                                        settings.domStorageEnabled = true
                                        webViewClient = object : WebViewClient() {
                                            override fun shouldOverrideUrlLoading(v: WebView?, req: WebResourceRequest?): Boolean {
                                                val popupUrl = req?.url?.toString() ?: return false
                                                if (popupUrl.startsWith("http://") || popupUrl.startsWith("https://")) {
                                                    view.loadUrl(popupUrl)
                                                    return true
                                                }
                                                return try {
                                                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(popupUrl)))
                                                    true
                                                } catch (e: Exception) {
                                                    true
                                                }
                                            }
                                        }
                                    }
                                    val transport = resultMsg?.obj as? WebView.WebViewTransport
                                    transport?.webView = newWebView
                                    resultMsg?.sendToTarget()
                                    return true
                                }
                            }
                            addJavascriptInterface(
                                RazorpayPaymentInterface(onSuccess, onFailure),
                                "AndroidInterface"
                            )
                            loadDataWithBaseURL("https://vrhere.in", htmlContent, "text/html", "UTF-8", "https://vrhere.in")
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )
            }
        }
    }
}

