package com.sbr.vrherebms.ui.screens.customer

import android.annotation.SuppressLint
import android.graphics.Bitmap
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.compose.BackHandler
import androidx.compose.animation.*
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
import androidx.compose.ui.draw.shadow
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

    BackHandler(enabled = true) {
        onClose()
    }

    val safeName = customerName.replace("'", "\\'").replace("\"", "\\\"").ifBlank { "Valued Customer" }
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
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body, html {
                    width: 100%;
                    height: 100%;
                    background: transparent !important;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    overflow: hidden;
                    display: flex;
                    align-items: flex-end;
                    justify-content: center;
                }
                .chat-card {
                    width: 100%;
                    height: 100%;
                    background: #FFFFFF;
                    border-radius: 20px 20px 0 0;
                    display: flex;
                    flex-direction: column;
                    overflow: hidden;
                    box-shadow: 0 -10px 40px rgba(0,0,0,0.35);
                }
                @media (min-width: 480px) {
                    .chat-card {
                        border-radius: 20px;
                        height: 94%;
                        margin-bottom: 12px;
                    }
                }
                .chat-header {
                    background: linear-gradient(135deg, #DC2626 0%, #312E81 100%);
                    color: #FFFFFF;
                    padding: 14px 18px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    flex-shrink: 0;
                }
                .header-title-wrap {
                    display: flex;
                    flex-direction: column;
                }
                .chat-title {
                    font-size: 16px;
                    font-weight: 700;
                    letter-spacing: -0.2px;
                }
                .chat-status {
                    font-size: 11px;
                    opacity: 0.9;
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    margin-top: 2px;
                }
                .online-dot {
                    width: 8px;
                    height: 8px;
                    background-color: #10B981;
                    border-radius: 50%;
                    box-shadow: 0 0 8px #10B981;
                }
                .close-btn {
                    background: rgba(255,255,255,0.18);
                    border: none;
                    color: #FFFFFF;
                    width: 32px;
                    height: 32px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    outline: none;
                }
                .close-btn:active {
                    background: rgba(255,255,255,0.35);
                }
                .chat-body {
                    flex: 1;
                    padding: 16px;
                    overflow-y: auto;
                    background: #F8FAFC;
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                    -webkit-overflow-scrolling: touch;
                }
                .msg-wrap {
                    display: flex;
                    flex-direction: column;
                    max-width: 82%;
                    animation: fadeIn 0.2s ease-out;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(6px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .msg-wrap.visitor {
                    align-self: flex-end;
                }
                .msg-wrap.agent, .msg-wrap.system {
                    align-self: flex-start;
                }
                .msg-sender {
                    font-size: 10px;
                    color: #64748B;
                    font-weight: 600;
                    margin-bottom: 3px;
                    padding: 0 4px;
                }
                .msg-bubble {
                    padding: 10px 14px;
                    border-radius: 16px;
                    font-size: 13.5px;
                    line-height: 1.4;
                    word-break: break-word;
                }
                .msg-wrap.visitor .msg-bubble {
                    background: linear-gradient(135deg, #DC2626 0%, #E11D48 100%);
                    color: #FFFFFF;
                    border-bottom-right-radius: 4px;
                    box-shadow: 0 2px 8px rgba(220,38,38,0.25);
                }
                .msg-wrap.agent .msg-bubble {
                    background: #E2E8F0;
                    color: #0F172A;
                    border-bottom-left-radius: 4px;
                }
                .msg-wrap.system .msg-bubble {
                    background: #FEF3C7;
                    color: #92400E;
                    font-size: 12px;
                    border-radius: 12px;
                    text-align: center;
                }
                .typing-indicator {
                    display: none;
                    align-items: center;
                    gap: 4px;
                    padding: 8px 12px;
                    background: #E2E8F0;
                    border-radius: 14px;
                    width: fit-content;
                }
                .typing-dot {
                    width: 6px;
                    height: 6px;
                    background: #64748B;
                    border-radius: 50%;
                    animation: bounce 1.2s infinite ease-in-out;
                }
                .typing-dot:nth-child(2) { animation-delay: 0.2s; }
                .typing-dot:nth-child(3) { animation-delay: 0.4s; }
                @keyframes bounce {
                    0%, 80%, 100% { transform: translateY(0); }
                    40% { transform: translateY(-4px); }
                }
                .chat-footer {
                    padding: 10px 14px;
                    background: #FFFFFF;
                    border-top: 1px solid #E2E8F0;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    flex-shrink: 0;
                }
                .chat-input {
                    flex: 1;
                    border: 1px solid #CBD5E1;
                    border-radius: 20px;
                    padding: 9px 14px;
                    font-size: 14px;
                    color: #0F172A;
                    background: #F8FAFC;
                    outline: none;
                }
                .chat-input:focus {
                    border-color: #DC2626;
                    background: #FFFFFF;
                }
                .send-btn {
                    background: linear-gradient(135deg, #DC2626 0%, #E11D48 100%);
                    border: none;
                    color: #FFFFFF;
                    width: 38px;
                    height: 38px;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                    flex-shrink: 0;
                    box-shadow: 0 2px 8px rgba(220,38,38,0.3);
                }
                .send-btn:active {
                    transform: scale(0.95);
                }
                .branding-footer {
                    padding: 5px 10px;
                    background: #F1F5F9;
                    text-align: center;
                    font-size: 10.5px;
                    color: #64748B;
                    border-top: 1px solid #E2E8F0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 4px;
                    flex-shrink: 0;
                }
            </style>
        </head>
        <body>
            <div class="chat-card">
                <div class="chat-header">
                    <div class="header-title-wrap">
                        <div class="chat-title">VR HERE Live Support</div>
                        <div class="chat-status">
                            <span class="online-dot"></span> Online &bull; Typically replies in seconds
                        </div>
                    </div>
                    <button class="close-btn" id="close-btn" aria-label="Close">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                            <line x1="18" y1="6" x2="6" y2="18"></line>
                            <line x1="6" y1="6" x2="18" y2="18"></line>
                        </svg>
                    </button>
                </div>

                <div class="chat-body" id="chat-body">
                    <div class="typing-indicator" id="typing-indicator">
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                        <div class="typing-dot"></div>
                    </div>
                </div>

                <div class="chat-footer">
                    <input type="text" class="chat-input" id="chat-input" placeholder="Type your message..." autocomplete="off" />
                    <button class="send-btn" id="send-btn" aria-label="Send">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
                        </svg>
                    </button>
                </div>

                <div class="branding-footer">
                    <span>⚡ Powered by <strong>LetsTrack &trade;</strong></span>
                </div>
            </div>

            <script>
                const API_KEY = "lt_6a9347d5410be8335e42db43949caf95";
                const BACKEND_URL = "https://livechat.vrhere.in";
                const customerName = "$safeName";
                const customerEmail = "$safeEmail";

                const body = document.getElementById('chat-body');
                const textInput = document.getElementById('chat-input');
                const sendBtn = document.getElementById('send-btn');
                const typingIndicator = document.getElementById('typing-indicator');
                const closeBtn = document.getElementById('close-btn');

                closeBtn.onclick = function() {
                    if (window.AndroidBridge && typeof window.AndroidBridge.closeChat === 'function') {
                        window.AndroidBridge.closeChat();
                    }
                };

                // Visitor UUID
                let savedVisitorId = localStorage.getItem('letstrack_visitor_uuid');
                const visitorId = savedVisitorId || ('v_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15));
                if (!savedVisitorId) {
                    localStorage.setItem('letstrack_visitor_uuid', visitorId);
                }

                function appendMessage(senderName, senderType, text, shouldScroll) {
                    const msgWrap = document.createElement('div');
                    msgWrap.className = 'msg-wrap ' + senderType.toLowerCase();

                    let msgHtml = '';
                    if (senderType !== 'System') {
                        msgHtml += '<div class="msg-sender">' + senderName + '</div>';
                    }
                    msgHtml += '<div class="msg-bubble">' + text + '</div>';
                    msgWrap.innerHTML = msgHtml;

                    if (typingIndicator && typingIndicator.parentNode === body) {
                        body.insertBefore(msgWrap, typingIndicator);
                    } else {
                        body.appendChild(msgWrap);
                    }

                    if (shouldScroll) {
                        body.scrollTop = body.scrollHeight;
                    }
                }

                // Initial welcome message
                appendMessage('System', 'System', 'Welcome to VR HERE Live Support! How can we assist you today, ' + customerName + '?', true);

                let socket = null;
                let socketReady = false;

                function initSocket() {
                    try {
                        if (typeof io === 'undefined') {
                            console.warn('Socket.io library loading...');
                            setTimeout(initSocket, 500);
                            return;
                        }

                        socket = io(BACKEND_URL + '/visitor', {
                            transports: ['websocket', 'polling']
                        });

                        socket.on('connect', function() {
                            socketReady = true;
                            socket.emit('visitor-init', {
                                apiKey: API_KEY,
                                visitorId: visitorId,
                                currentUrl: '/customer/app',
                                referrer: 'VRHereApp Android',
                                name: customerName,
                                email: customerEmail,
                                browser: 'Android App',
                                os: 'Android',
                                deviceType: 'Mobile'
                            });
                        });

                        socket.on('chat-history', function(data) {
                            if (data && data.messages && data.messages.length > 0) {
                                data.messages.forEach(function(msg) {
                                    appendMessage(msg.senderName, msg.senderType, msg.text, false);
                                });
                                body.scrollTop = body.scrollHeight;
                            }
                        });

                        socket.on('msg-received', function(message) {
                            typingIndicator.style.display = 'none';
                            appendMessage(message.senderName, message.senderType, message.text, true);
                        });

                        socket.on('agent-typing', function(data) {
                            if (data.isTyping) {
                                typingIndicator.style.display = 'flex';
                                body.scrollTop = body.scrollHeight;
                            } else {
                                typingIndicator.style.display = 'none';
                            }
                        });

                    } catch(e) {
                        console.error('Socket init error:', e);
                    }
                }

                function triggerSendMessage() {
                    const textVal = textInput.value.trim();
                    if (!textVal) return;

                    appendMessage(customerName, 'Visitor', textVal, true);
                    textInput.value = '';

                    if (socket && socketReady) {
                        socket.emit('visitor-msg', { text: textVal });
                        socket.emit('visitor-typing', { isTyping: false });
                    }
                }

                sendBtn.onclick = triggerSendMessage;
                textInput.onkeydown = function(e) {
                    if (e.key === 'Enter') {
                        triggerSendMessage();
                        e.preventDefault();
                    }
                };

                let typingTimeout = null;
                textInput.oninput = function() {
                    if (socket && socketReady) {
                        socket.emit('visitor-typing', { isTyping: true });
                    }
                    if (typingTimeout) clearTimeout(typingTimeout);
                    typingTimeout = setTimeout(function() {
                        if (socket && socketReady) {
                            socket.emit('visitor-typing', { isTyping: false });
                        }
                    }, 2000);
                };

                initSocket();
            </script>
        </body>
        </html>
        """.trimIndent()
    }

    // Modal overlay with subtle darkened backdrop
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.6f))
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
                    // Prevent dismiss when clicking inside chat dialog
                }
        ) {
            AndroidView(
                factory = { ctx ->
                    WebView(ctx).apply {
                        setBackgroundColor(0) // Transparent background
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
                        webViewClient = WebViewClient()

                        loadDataWithBaseURL("https://livechat.vrhere.in", htmlContent, "text/html", "UTF-8", null)
                    }
                },
                modifier = Modifier.fillMaxSize()
            )
        }
    }
}
