package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
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
                    background: transparent !important;
                    overflow: hidden;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                #loading-view {
                    position: fixed;
                    bottom: 24px;
                    left: 16px;
                    right: 16px;
                    max-width: 400px;
                    height: 200px;
                    margin: 0 auto;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    background: rgba(15, 23, 42, 0.95);
                    backdrop-filter: blur(12px);
                    border-radius: 20px;
                    color: #94A3B8;
                    font-size: 13px;
                    font-weight: 600;
                    text-align: center;
                    padding: 20px;
                    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.4);
                    border: 1px solid rgba(255, 255, 255, 0.1);
                    z-index: 999998;
                }
                .spinner {
                    width: 34px;
                    height: 34px;
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
                // Pre-populate visitor credentials for instant connection
                try {
                    if ("$safeName".length > 0) {
                        localStorage.setItem('letstrack_visitor_name', "$safeName");
                    }
                    if ("$safeEmail".length > 0) {
                        localStorage.setItem('letstrack_visitor_email', "$safeEmail");
                    }
                } catch(e) {}

                // Intercept shadow DOM to style the widget window matching the web version
                (function() {
                    var origAttachShadow = Element.prototype.attachShadow;
                    Element.prototype.attachShadow = function(init) {
                        var shadow = origAttachShadow.call(this, Object.assign({}, init, { mode: 'open' }));
                        if (this.id === 'letstrack-widget-root') {
                            window.__letsTrackShadowRoot = shadow;
                            
                            var style = document.createElement('style');
                            style.textContent = `
                                .lt-widget-container {
                                    position: fixed !important;
                                    bottom: 16px !important;
                                    left: 12px !important;
                                    right: 12px !important;
                                    margin: 0 auto !important;
                                    max-width: 420px !important;
                                    z-index: 999999 !important;
                                    display: flex !important;
                                    flex-direction: column !important;
                                    align-items: center !important;
                                }
                                .lt-widget-btn {
                                    display: none !important;
                                }
                                .lt-popup {
                                    display: none !important;
                                }
                                .lt-chat-window {
                                    width: 100% !important;
                                    max-width: 420px !important;
                                    height: 72vh !important;
                                    max-height: 560px !important;
                                    border-radius: 20px !important;
                                    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.45) !important;
                                    border: 1px solid rgba(255, 255, 255, 0.18) !important;
                                    display: flex !important;
                                    opacity: 1 !important;
                                    transform: none !important;
                                    overflow: hidden !important;
                                    margin-bottom: 0 !important;
                                }
                                .lt-chat-header {
                                    border-top-left-radius: 20px !important;
                                    border-top-right-radius: 20px !important;
                                }
                            `;
                            shadow.appendChild(style);

                            // Auto-open and wire close button to Android
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
                                var closeBtn = shadow.querySelector('#lt-close-btn');
                                if (closeBtn && !closeBtn.__boundToAndroid) {
                                    closeBtn.__boundToAndroid = true;
                                    closeBtn.addEventListener('click', function(e) {
                                        e.preventDefault();
                                        e.stopPropagation();
                                        if (window.AndroidBridge && typeof window.AndroidBridge.closeChat === 'function') {
                                            window.AndroidBridge.closeChat();
                                        }
                                    });
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

    // Modal overlay with subtle darkened backdrop
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.55f))
            .clickable(
                indication = null,
                interactionSource = remember { MutableInteractionSource() }
            ) {
                onClose()
            }
            .navigationBarsPadding()
            .statusBarsPadding(),
        contentAlignment = Alignment.BottomCenter
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.85f)
                .clickable(
                    indication = null,
                    interactionSource = remember { MutableInteractionSource() }
                ) {
                    // Prevent dismiss when tapping inside the chat widget container
                }
        ) {
            AndroidView(
                factory = { ctx ->
                    WebView(ctx).apply {
                        webViewInstance = this
                        setBackgroundColor(0) // Transparent background so only the widget card is visible
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
                        addJavascriptInterface(object {
                            @JavascriptInterface
                            fun closeChat() {
                                post { onClose() }
                            }
                        }, "AndroidBridge")

                        webChromeClient = WebChromeClient()
                        webViewClient = object : WebViewClient() {
                            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                                isLoading = true
                            }
                            override fun onPageFinished(view: WebView?, url: String?) {
                                isLoading = false
                            }
                        }
                        loadDataWithBaseURL("https://vrhere.in", htmlContent, "text/html", "UTF-8", null)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}
