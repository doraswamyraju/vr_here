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
            <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
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
            </style>
        </head>
        <body>
            <div id="loading-view">
                <div class="spinner"></div>
                <div>Connecting to VR HERE Live Support...</div>
            </div>

            <script>
                // Pre-populate visitor credentials for instant seamless connection
                try {
                    if ("$safeName".length > 0) {
                        localStorage.setItem('letstrack_visitor_name', "$safeName");
                    }
                    if ("$safeEmail".length > 0) {
                        localStorage.setItem('letstrack_visitor_email', "$safeEmail");
                    }
                } catch(e) {}

                // Intercept shadow DOM creation to make chat fullscreen inside native WebView
                (function() {
                    var origAttachShadow = Element.prototype.attachShadow;
                    Element.prototype.attachShadow = function(init) {
                        var shadow = origAttachShadow.call(this, Object.assign({}, init, { mode: 'open' }));
                        if (this.id === 'letstrack-widget-root') {
                            window.__letsTrackShadowRoot = shadow;
                            
                            // Inject native-fitting responsive CSS directly into Shadow DOM
                            var style = document.createElement('style');
                            style.textContent = `
                                .lt-widget-container {
                                    position: fixed !important;
                                    top: 0 !important;
                                    left: 0 !important;
                                    width: 100vw !important;
                                    height: 100vh !important;
                                    margin: 0 !important;
                                    padding: 0 !important;
                                    z-index: 999999 !important;
                                    display: flex !important;
                                    flex-direction: column !important;
                                }
                                .lt-widget-btn {
                                    display: none !important;
                                }
                                .lt-popup {
                                    display: none !important;
                                }
                                .lt-chat-window {
                                    position: fixed !important;
                                    top: 0 !important;
                                    left: 0 !important;
                                    right: 0 !important;
                                    bottom: 0 !important;
                                    width: 100vw !important;
                                    height: 100vh !important;
                                    max-width: 100vw !important;
                                    max-height: 100vh !important;
                                    margin: 0 !important;
                                    border-radius: 0 !important;
                                    border: none !important;
                                    box-shadow: none !important;
                                    display: flex !important;
                                    opacity: 1 !important;
                                    transform: none !important;
                                    background: #0F172A !important;
                                }
                                .lt-chat-header {
                                    display: none !important;
                                }
                                .lt-chat-body {
                                    flex: 1 !important;
                                    background: #0F172A !important;
                                    padding: 16px !important;
                                }
                                .lt-msg-wrap.visitor .lt-msg-bubble {
                                    background-color: #E11D48 !important;
                                    color: #FFFFFF !important;
                                    font-weight: 500 !important;
                                }
                                .lt-msg-wrap.agent .lt-msg-bubble {
                                    background-color: #1E293B !important;
                                    color: #F8FAFC !important;
                                    border: 1px solid #334155 !important;
                                }
                                .lt-msg-wrap.system .lt-msg-bubble {
                                    background-color: #1E293B !important;
                                    color: #94A3B8 !important;
                                    border: 1px solid #334155 !important;
                                }
                                .lt-msg-sender {
                                    color: #64748B !important;
                                }
                                .lt-chat-footer {
                                    background: #1E293B !important;
                                    border-top: 1px solid #334155 !important;
                                    padding: 12px 14px !important;
                                }
                                .lt-chat-input {
                                    color: #F8FAFC !important;
                                    font-size: 14px !important;
                                }
                                .lt-chat-input::placeholder {
                                    color: #64748B !important;
                                }
                                .lt-send-btn {
                                    color: #E11D48 !important;
                                }
                                .lt-branding-footer {
                                    background: #0F172A !important;
                                    border-top: 1px solid #1E293B !important;
                                    color: #64748B !important;
                                }
                                .pre-chat-form {
                                    background: #1E293B !important;
                                    padding: 20px !important;
                                    border-radius: 16px !important;
                                    border: 1px solid #334155 !important;
                                }
                                .pre-chat-text {
                                    color: #F8FAFC !important;
                                }
                                .pre-chat-input {
                                    background: #0F172A !important;
                                    border: 1px solid #334155 !important;
                                    color: #F8FAFC !important;
                                }
                                .pre-chat-btn {
                                    background-color: #E11D48 !important;
                                }
                            `;
                            shadow.appendChild(style);

                            // Continuous interval to enforce open state & hide launcher button
                            setInterval(function() {
                                var win = shadow.querySelector('.lt-chat-window');
                                if (win) {
                                    if (!win.classList.contains('open')) {
                                        win.classList.add('open');
                                    }
                                    var loader = document.getElementById('loading-view');
                                    if (loader) loader.style.display = 'none';
                                }
                                var btn = shadow.querySelector('.lt-widget-btn');
                                if (btn) {
                                    btn.style.setProperty('display', 'none', 'important');
                                }
                            }, 100);
                        }
                        return shadow;
                    };
                })();

                window.LetsTrackConfig = {
                    websiteId: "lt_6a9347d5410be8335e42db43949caf95"
                };

                (function () {
                    var d = document, s = d.createElement('script');
                    s.src = "https://livechat.vrhere.in/widget.js";
                    s.async = true;
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
