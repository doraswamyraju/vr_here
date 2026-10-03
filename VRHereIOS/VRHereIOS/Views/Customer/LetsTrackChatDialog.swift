import SwiftUI
import WebKit

// MARK: - Dedicated LetsTrack Live Chat WebView (Connecting to livechat.vrhere.in)
struct LetsTrackWebView: UIViewRepresentable {
    let customerName: String
    let customerEmail: String
    @Binding var isLoading: Bool
    
    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.mediaTypesRequiringUserActionForPlayback = []
        
        // Setup preferences
        let prefs = WKWebpagePreferences()
        prefs.allowsContentJavaScript = true
        config.defaultWebpagePreferences = prefs
        
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.isOpaque = false
        webView.backgroundColor = UIColor(red: 15/255, green: 23/255, blue: 42/255, alpha: 1.0)
        webView.scrollView.isScrollEnabled = true
        webView.scrollView.bounces = false
        
        // Load the official LetsTrack Live Chat Engine HTML
        let visitorName = customerName.isEmpty ? "Customer" : customerName.replacingOccurrences(of: "\"", with: "\\\"")
        let visitorEmail = customerEmail.isEmpty ? "customer@vrhere.in" : customerEmail.replacingOccurrences(of: "\"", with: "\\\"")
        
        let htmlContent = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
          <title>VR HERE Live Chat</title>
          <style>
            * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
            html, body {
              margin: 0;
              padding: 0;
              width: 100%;
              height: 100%;
              background: #0F172A;
              color: #F8FAFC;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
              overflow: hidden;
            }
            #loading-overlay {
              position: fixed;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              background: #0F172A;
              display: flex;
              flex-direction: column;
              align-items: center;
              justify-content: center;
              z-index: 99999;
              transition: opacity 0.3s ease;
            }
            .spinner {
              width: 36px;
              height: 36px;
              border: 3px solid rgba(255, 255, 255, 0.1);
              border-top-color: #DC2626;
              border-radius: 50%;
              animation: spin 0.8s linear infinite;
            }
            @keyframes spin {
              to { transform: rotate(360deg); }
            }
            .loading-text {
              margin-top: 14px;
              font-size: 13px;
              font-weight: 700;
              color: #94A3B8;
              letter-spacing: 0.3px;
            }
          </style>
          
          <script>
            // Shadow DOM hook matching web index.html
            (function() {
              var origAttachShadow = Element.prototype.attachShadow;
              if (origAttachShadow) {
                Element.prototype.attachShadow = function(init) {
                  var shadow = origAttachShadow.call(this, Object.assign({}, init, { mode: 'open' }));
                  if (this.id === 'letstrack-widget-root') {
                    window.__letsTrackShadowRoot = shadow;
                  }
                  return shadow;
                };
              }
            })();

            window.LetsTrackConfig = {
              websiteId: "lt_6a9347d5410be8335e42db43949caf95",
              visitorName: "\(visitorName)",
              visitorEmail: "\(visitorEmail)",
              openByDefault: true
            };

            // Auto-trigger widget open when ready
            function triggerWidgetOpen() {
              setTimeout(function() {
                var overlay = document.getElementById('loading-overlay');
                if (overlay) overlay.style.display = 'none';

                // Click the launcher or dispatch open event
                try {
                  if (window.LetsTrack && typeof window.LetsTrack.open === 'function') {
                    window.LetsTrack.open();
                  } else {
                    var btn = document.querySelector('#letstrack-launcher, .letstrack-launcher-btn, [data-letstrack-launcher]');
                    if (btn) btn.click();
                  }
                } catch(e) {}
              }, 1200);
            }
          </script>
          <script src="https://livechat.vrhere.in/widget.js" async onload="triggerWidgetOpen()"></script>
        </head>
        <body>
          <div id="loading-overlay">
            <div class="spinner"></div>
            <div class="loading-text">Connecting to Live Compliance Desk...</div>
          </div>
        </body>
        </html>
        """
        
        webView.loadHTMLString(htmlContent, baseURL: URL(string: "https://livechat.vrhere.in/"))
        return webView
    }
    
    func updateUIView(_ uiView: WKWebView, context: Context) {}
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, WKNavigationDelegate {
        let parent: LetsTrackWebView
        
        init(_ parent: LetsTrackWebView) {
            self.parent = parent
        }
        
        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            DispatchQueue.main.async {
                self.parent.isLoading = true
            }
        }
        
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                self.parent.isLoading = false
            }
        }
        
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            DispatchQueue.main.async {
                self.parent.isLoading = false
            }
        }
    }
}

// MARK: - Native Container Sheet for LetsTrack Live Chat
struct LetsTrackChatDialog: View {
    @Binding var isOpen: Bool
    let customerName: String
    let customerEmail: String
    
    @State private var isLoadingWeb = true
    @State private var webViewId = UUID()
    
    var body: some View {
        if isOpen {
            ZStack {
                Color.black.opacity(0.65)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                            isOpen = false
                        }
                    }
                
                VStack(spacing: 0) {
                    Spacer().frame(height: 30)
                    
                    // Main Chat Window Container
                    VStack(spacing: 0) {
                        // Header Bar
                        HStack(spacing: 12) {
                            ZStack(alignment: .bottomTrailing) {
                                ZStack {
                                    Circle()
                                        .fill(
                                            LinearGradient(
                                                colors: [Color(red: 220/255, green: 38/255, blue: 38/255), Color(red: 185/255, green: 28/255, blue: 28/255)],
                                                startPoint: .topLeading,
                                                endPoint: .bottomTrailing
                                            )
                                        )
                                        .frame(width: 42, height: 42)
                                    Image(systemName: "headphones")
                                        .font(.system(size: 18, weight: .bold))
                                        .foregroundColor(.white)
                                }
                                
                                Circle()
                                    .fill(Color(red: 34/255, green: 197/255, blue: 94/255))
                                    .frame(width: 10, height: 10)
                                    .overlay(Circle().stroke(Color.white, lineWidth: 1.5))
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text("VR HERE Live Support")
                                        .font(.system(size: 15, weight: .black))
                                        .foregroundColor(.white)
                                    
                                    Text("ONLINE")
                                        .font(.system(size: 8.5, weight: .black))
                                        .foregroundColor(Color(red: 34/255, green: 197/255, blue: 94/255))
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Color(red: 34/255, green: 197/255, blue: 94/255).opacity(0.2))
                                        .clipShape(Capsule())
                                }
                                
                                Text("Real-Time CA & Compliance Desk")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            }
                            
                            Spacer()
                            
                            // Reload Button
                            Button(action: {
                                webViewId = UUID()
                            }) {
                                Image(systemName: "arrow.clockwise")
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(width: 32, height: 32)
                                    .background(Color.white.opacity(0.12))
                                    .clipShape(Circle())
                            }
                            .buttonStyle(PlainButtonStyle())
                            
                            // Close Button
                            Button(action: {
                                withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                    isOpen = false
                                }
                            }) {
                                Image(systemName: "xmark")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.white)
                                    .frame(width: 32, height: 32)
                                    .background(Color.white.opacity(0.12))
                                    .clipShape(Circle())
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                        .padding(16)
                        .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                        
                        // Live Web Chat View
                        ZStack {
                            LetsTrackWebView(
                                customerName: customerName,
                                customerEmail: customerEmail,
                                isLoading: $isLoadingWeb
                            )
                            .id(webViewId)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                            .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                            
                            if isLoadingWeb {
                                VStack(spacing: 12) {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: Color(red: 220/255, green: 38/255, blue: 38/255)))
                                        .scaleEffect(1.2)
                                    Text("Connecting to live support agents...")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                }
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                            }
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: UIScreen.main.bounds.height * 0.78)
                    .background(Color(red: 15/255, green: 23/255, blue: 42/255))
                    .cornerRadius(24)
                    .overlay(
                        RoundedRectangle(cornerRadius: 24)
                            .stroke(Color.white.opacity(0.12), lineWidth: 1)
                    )
                    .shadow(color: Color.black.opacity(0.45), radius: 25, y: 10)
                    .padding(.horizontal, 12)
                    .padding(.bottom, 20)
                }
            }
            .transition(.opacity.combined(with: .move(edge: .bottom)))
            .zIndex(9999)
        }
    }
}
