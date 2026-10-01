package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView

@SuppressLint("SetJavaScriptEnabled")
@Composable
fun LetsTrackChatDialog(
    isOpen: Boolean,
    customerName: String = "",
    customerEmail: String = "",
    onClose: () -> Unit
) {
    if (!isOpen) return

    var webViewInstance by remember { mutableStateOf<WebView?>(null) }
    var isLoading by remember { mutableStateOf(true) }

    BackHandler(enabled = true) {
        onClose()
    }

    val safeName = customerName.replace("'", "\\'").replace("\"", "\\\"")
    val safeEmail = customerEmail.replace("'", "\\'").replace("\"", "\\\"")

    val htmlContent = remember(safeName, safeEmail) {
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
            <style>
                * { box-sizing: border-box; }
                body, html {
                    margin: 0;
                    padding: 0;
                    width: 100%;
                    height: 100%;
                    background-color: #0F172A;
                    overflow: hidden;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                #loading-view {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 100%;
                    color: #94A3B8;
                    font-size: 13px;
                    font-weight: 600;
                    text-align: center;
                    padding: 20px;
                }
                .spinner {
                    width: 36px;
                    height: 36px;
                    border: 3px solid rgba(99, 102, 241, 0.2);
                    border-top-color: #6366F1;
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                    margin-bottom: 12px;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }

                /* Hide redundant launcher button inside webview since dialog is already open */
                .lt-widget-btn, #letstrack-widget-btn {
                    display: none !important;
                }
            </style>
        </head>
        <body>
            <div id="loading-view">
                <div class="spinner"></div>
                <div>Connecting to VR HERE Live Support...</div>
            </div>

            <script>
                (function() {
                    var origAttachShadow = Element.prototype.attachShadow;
                    Element.prototype.attachShadow = function(init) {
                        var shadow = origAttachShadow.call(this, Object.assign({}, init, { mode: 'open' }));
                        if (this.id === 'letstrack-widget-root') {
                            window.__letsTrackShadowRoot = shadow;
                        }
                        return shadow;
                    };
                })();

                window.LetsTrackConfig = {
                    websiteId: "lt_6a9347d5410be8335e42db43949caf95",
                    user: {
                        name: "$safeName",
                        email: "$safeEmail"
                    }
                };

                function autoOpenWidget() {
                    if (window.LetsTrack) {
                        if (typeof window.LetsTrack.open === 'function') {
                            window.LetsTrack.open();
                            hideLoading();
                            return;
                        }
                        if (typeof window.LetsTrack.toggle === 'function') {
                            window.LetsTrack.toggle();
                            hideLoading();
                            return;
                        }
                    }
                    var rootEl = document.getElementById('letstrack-widget-root');
                    var shadow = (rootEl && rootEl.shadowRoot) || window.__letsTrackShadowRoot;
                    if (shadow) {
                        var chatBtn = shadow.querySelector('.lt-widget-btn, #letstrack-widget-btn, button');
                        if (chatBtn) {
                            chatBtn.click();
                            hideLoading();
                            return;
                        }
                    }
                }

                function hideLoading() {
                    var el = document.getElementById('loading-view');
                    if (el) el.style.display = 'none';
                }

                (function () {
                    var d = document, s = d.createElement('script');
                    s.src = "https://livechat.vrhere.in/widget.js";
                    s.async = true;
                    s.onload = function() {
                        setTimeout(autoOpenWidget, 300);
                        setTimeout(autoOpenWidget, 1000);
                    };
                    d.getElementsByTagName('head')[0].appendChild(s);
                })();
            </script>
        </body>
        </html>
        """.trimIndent()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0F172A))
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            // Clean Native Top Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp)
                    .background(Color(0xFF0F172A))
                    .padding(horizontal = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    IconButton(
                        onClick = onClose,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = Color.White,
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Box(
                        modifier = Modifier
                            .size(9.dp)
                            .background(Color(0xFF10B981), CircleShape)
                    )

                    Column {
                        Text(
                            text = "VR HERE Live Support",
                            color = Color.White,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "LetsTrack Live Agent",
                            color = Color(0xFF94A3B8),
                            fontSize = 10.sp
                        )
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    IconButton(
                        onClick = { webViewInstance?.reload() },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Reload",
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(18.dp)
                        )
                    }

                    IconButton(
                        onClick = onClose,
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Close",
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            HorizontalDivider(thickness = 1.dp, color = Color(0xFF1E293B))

            // Full-bleed Embedded WebView
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
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
                                mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                                cacheMode = WebSettings.LOAD_DEFAULT
                                userAgentString = settings.userAgentString + " VRHereApp/Android"
                            }
                            webChromeClient = WebChromeClient()
                            webViewClient = object : WebViewClient() {
                                override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                                    isLoading = true
                                }
                                override fun onPageFinished(view: WebView?, url: String?) {
                                    isLoading = false
                                }
                            }
                            setBackgroundColor(0xFF0F172A.toInt())
                            loadDataWithBaseURL("https://vrhere.in", htmlContent, "text/html", "UTF-8", null)
                        }
                    },
                    modifier = Modifier.fillMaxSize()
                )

                if (isLoading) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator(
                            color = Color(0xFF6366F1),
                            modifier = Modifier.size(36.dp)
                        )
                    }
                }
            }
        }
    }
}
