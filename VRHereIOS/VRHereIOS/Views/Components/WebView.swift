import SwiftUI
import WebKit

#if os(iOS)
import UIKit
typealias ViewRepresentable = UIViewRepresentable
#elseif os(macOS)
import AppKit
typealias ViewRepresentable = NSViewRepresentable
#endif

// --- SwiftUI wrapper for WKWebView ---
struct SwiftUIWebView: ViewRepresentable {
    let urlString: String
    var htmlContent: String? = nil
    let messageHandler: WKScriptMessageHandler?
    let handlerName: String?
    
    private func createWebView(context: Context) -> WKWebView {
        let preferences = WKWebpagePreferences()
        preferences.allowsContentJavaScript = true
        
        let configuration = WKWebViewConfiguration()
        configuration.defaultWebpagePreferences = preferences
        
        if let handler = messageHandler, let name = handlerName {
            configuration.userContentController.add(handler, name: name)
        }
        
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        return webView
    }
    
    private func updateWebView(_ webView: WKWebView, context: Context) {
        if let html = htmlContent {
            webView.loadHTMLString(html, baseURL: URL(string: "https://api.razorpay.com"))
        } else if let url = URL(string: urlString) {
            let request = URLRequest(url: url)
            webView.load(request)
        }
    }
    
    #if os(iOS)
    func makeUIView(context: Context) -> WKWebView {
        return createWebView(context: context)
    }
    
    func updateUIView(_ uiView: WKWebView, context: Context) {
        updateWebView(uiView, context: context)
    }
    #elseif os(macOS)
    func makeNSView(context: Context) -> WKWebView {
        return createWebView(context: context)
    }
    
    func updateNSView(_ nsView: WKWebView, context: Context) {
        updateWebView(nsView, context: context)
    }
    #endif
    
    func makeCoordinator() -> Coordinator {
        Coordinator()
    }
    
    class Coordinator: NSObject, WKNavigationDelegate {
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            print("WebView did finish navigation")
        }
        
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            print("WebView failed navigation: \(error)")
        }
    }
}

// --- Class helper to conform to WKScriptMessageHandler ---
class ScriptMessageHandlerHelper: NSObject, WKScriptMessageHandler {
    let onMessageReceived: (WKScriptMessage) -> Void
    
    init(onMessageReceived: @escaping (WKScriptMessage) -> Void) {
        self.onMessageReceived = onMessageReceived
        super.init()
    }
    
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        onMessageReceived(message)
    }
}

// --- Razorpay Payment WebView View Wrapper ---
struct CustomerPaymentWebView: View {
    let key: String
    let orderId: String
    let amount: Int
    let currency: String
    let serviceName: String
    let packageName: String
    let customerName: String
    let customerEmail: String
    let customerPhone: String
    
    let onSuccess: (String, String, String) -> Void
    let onFailure: (String) -> Void
    let onClose: () -> Void
    
    // Create a message handler helper
    private var handlerHelper: ScriptMessageHandlerHelper {
        ScriptMessageHandlerHelper { message in
            guard message.name == "iOSInterface",
                  let body = message.body as? [String: Any],
                  let event = body["event"] as? String else {
                return
            }
            
            DispatchQueue.main.async {
                switch event {
                case "onPaymentSuccess":
                    let payId = body["paymentId"] as? String ?? ""
                    let ordId = body["orderId"] as? String ?? ""
                    let sig = body["signature"] as? String ?? ""
                    onSuccess(payId, ordId, sig)
                case "onPaymentFailure":
                    let err = body["error"] as? String ?? "Payment Failed"
                    onFailure(err)
                case "onPaymentCancelled":
                    onFailure("Payment cancelled by user")
                default:
                    break
                }
            }
        }
    }
    
    private var htmlContent: String {
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
                function sendToiOS(eventData) {
                    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.iOSInterface) {
                        window.webkit.messageHandlers.iOSInterface.postMessage(eventData);
                    }
                }

                window.onload = function() {
                    var options = {
                        "key": "\(key)",
                        "amount": "\(amount)",
                        "currency": "\(currency)",
                        "name": "VR HERE",
                        "description": "\(serviceName) - \(packageName)",
                        "order_id": "\(orderId)",
                        "prefill": {
                            "name": "\(customerName)",
                            "email": "\(customerEmail)",
                            "contact": "\(customerPhone)"
                        },
                        "theme": {
                            "color": "#6366F1"
                        },
                        "handler": function (response) {
                            sendToiOS({
                                "event": "onPaymentSuccess",
                                "paymentId": response.razorpay_payment_id,
                                "orderId": response.razorpay_order_id,
                                "signature": response.razorpay_signature
                            });
                        },
                        "modal": {
                            "ondismiss": function() {
                                sendToiOS({
                                    "event": "onPaymentCancelled"
                                });
                            }
                        }
                    };
                    var rzp = new Razorpay(options);
                    rzp.on('payment.failed', function (response){
                        sendToiOS({
                            "event": "onPaymentFailure",
                            "error": response.error.description || 'Payment Failed'
                        });
                    });
                    rzp.open();
                };
            </script>
        </body>
        </html>
        """
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header bar
            HStack {
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.title3)
                        .foregroundColor(.textDark)
                        .padding(8)
                }
                Spacer()
                Text("Secure Checkout")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.textDark)
                Spacer()
                Spacer().frame(width: 40) // Balance title
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.white)
            
            Divider()
                .background(Color.borderLight)
            
            SwiftUIWebView(urlString: "", htmlContent: htmlContent, messageHandler: handlerHelper, handlerName: "iOSInterface")
                .edgesIgnoringSafeArea(.bottom)
        }
        .background(Color.white)
    }
}

// --- Customer Service WebView overlay ---
struct CustomerServiceWebView: View {
    let url: String
    let title: String
    let onClose: () -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.title3)
                        .foregroundColor(.textDark)
                        .padding(8)
                }
                Spacer()
                Text(title)
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.textDark)
                Spacer()
                Spacer().frame(width: 40)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.white)
            
            Divider()
                .background(Color.borderLight)
            
            SwiftUIWebView(urlString: url, messageHandler: nil, handlerName: nil)
                .edgesIgnoringSafeArea(.bottom)
        }
        .background(Color.white)
    }
}
