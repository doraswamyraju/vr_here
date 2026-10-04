import SwiftUI
import WebKit
import Combine

// MARK: - LetsTrack Message Model matching Android
struct LetsTrackMessage: Identifiable, Equatable {
    let id: String
    let senderName: String
    let senderType: String // "Visitor" | "Agent" | "System"
    let text: String
    let timestamp: String
    
    init(id: String = UUID().uuidString, senderName: String, senderType: String, text: String, timestamp: String? = nil) {
        self.id = id
        self.senderName = senderName
        self.senderType = senderType
        self.text = text
        if let ts = timestamp {
            self.timestamp = ts
        } else {
            let formatter = DateFormatter()
            formatter.dateFormat = "h:mm a"
            self.timestamp = formatter.string(from: Date())
        }
    }
}

// MARK: - Headless Socket.IO Engine Coordinator for LetsTrack
class LetsTrackSocketCoordinator: NSObject, ObservableObject, WKScriptMessageHandler {
    @Published var isConnected = false
    @Published var isAgentTyping = false
    @Published var messages: [LetsTrackMessage] = []
    
    private var webView: WKWebView?
    private let customerName: String
    private let customerEmail: String
    private let customerPhone: String
    private let visitorId: String
    
    init(customerName: String, customerEmail: String, customerPhone: String = "") {
        self.customerName = customerName.isEmpty ? "Valued Customer" : customerName
        self.customerEmail = customerEmail
        self.customerPhone = customerPhone
        
        // Persistent visitor UUID matching Android SharedPreferences
        if let storedId = UserDefaults.standard.string(forKey: "letstrack_visitor_uuid"), !storedId.isEmpty {
            self.visitorId = storedId
        } else {
            let newId = "v_" + UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(18)
            UserDefaults.standard.set(newId, forKey: "letstrack_visitor_uuid")
            self.visitorId = newId
        }
        
        super.init()
        
        // Initial welcome system message
        self.messages = [
            LetsTrackMessage(
                senderName: "VR HERE Assistant",
                senderType: "System",
                text: "Welcome to VR HERE Live Support! How can we assist you today, \(self.customerName)?"
            )
        ]
        
        setupHeadlessSocket()
    }
    
    private func setupHeadlessSocket() {
        let contentController = WKUserContentController()
        contentController.add(self, name: "chatBridge")
        
        let config = WKWebViewConfiguration()
        config.userContentController = contentController
        
        let web = WKWebView(frame: .zero, configuration: config)
        self.webView = web
        
        let sanitizedName = customerName.replacingOccurrences(of: "\"", with: "\\\"")
        let sanitizedEmail = customerEmail.replacingOccurrences(of: "\"", with: "\\\"")
        let sanitizedPhone = customerPhone.replacingOccurrences(of: "\"", with: "\\\"")
        
        let html = """
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
          <script>
            var socket = null;
            var apiKey = "lt_6a9347d5410be8335e42db43949caf95";
            var visitorId = "\(visitorId)";
            var visitorName = "\(sanitizedName)";
            var visitorEmail = "\(sanitizedEmail)";
            var visitorPhone = "\(sanitizedPhone)";

            // Store in localStorage for web/widget persistence
            try {
              localStorage.setItem('letstrack_visitor_uuid', visitorId);
              if (visitorName) localStorage.setItem('letstrack_visitor_name', visitorName);
              if (visitorEmail) localStorage.setItem('letstrack_visitor_email', visitorEmail);
              if (visitorPhone) localStorage.setItem('letstrack_visitor_phone', visitorPhone);
            } catch (e) {}

            function post(type, data) {
              if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.chatBridge) {
                window.webkit.messageHandlers.chatBridge.postMessage({ type: type, data: data || {} });
              }
            }

            function initSocket() {
              try {
                socket = io("https://livechat.vrhere.in/visitor", {
                  transports: ["websocket", "polling"],
                  reconnection: true,
                  reconnectionAttempts: 15,
                  reconnectionDelay: 1000
                });

                socket.on("connect", function() {
                  post("connected", {});
                  socket.emit("visitor-init", {
                    apiKey: apiKey,
                    visitorId: visitorId,
                    currentUrl: "/customer/app",
                    referrer: "VRHere iOS App",
                    name: visitorName,
                    email: visitorEmail,
                    phoneNumber: visitorPhone,
                    phone: visitorPhone,
                    browser: "VRHere iOS App",
                    os: "iOS",
                    deviceType: "Mobile"
                  });
                });

                socket.on("disconnect", function() {
                  post("disconnected", {});
                });

                socket.on("connect_error", function(err) {
                  post("disconnected", { error: err ? err.message : "" });
                });

                socket.on("visitor-init-success", function(d) {
                  post("connected", d || {});
                });

                socket.on("chat-history", function(d) {
                  post("chat-history", d || {});
                });

                socket.on("msg-received", function(d) {
                  post("msg-received", d || {});
                });

                socket.on("agent-typing", function(d) {
                  post("agent-typing", d || {});
                });
              } catch(e) {
                post("error", { message: e.toString() });
              }
            }

            function sendVisitorMsg(text) {
              if (socket) {
                socket.emit("visitor-msg", { text: text });
                socket.emit("visitor-typing", { isTyping: false });
              }
            }

            function setVisitorTyping(isTyping) {
              if (socket) {
                socket.emit("visitor-typing", { isTyping: isTyping });
              }
            }

            window.onload = initSocket;
          </script>
        </head>
        <body></body>
        </html>
        """
        
        web.loadHTMLString(html, baseURL: URL(string: "https://livechat.vrhere.in/"))
    }
    
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let dict = message.body as? [String: Any],
              let type = dict["type"] as? String else { return }
        let data = dict["data"] as? [String: Any] ?? [:]
        
        DispatchQueue.main.async {
            switch type {
            case "connected":
                self.isConnected = true
            case "disconnected":
                self.isConnected = false
            case "chat-history":
                if let msgs = data["messages"] as? [[String: Any]] {
                    for m in msgs {
                        let text = m["text"] as? String ?? ""
                        if !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            let sType = m["senderType"] as? String ?? "Agent"
                            let sName = m["senderName"] as? String ?? (sType == "Visitor" ? self.customerName : "Support Officer")
                            let msgId = m["_id"] as? String ?? UUID().uuidString
                            if !self.messages.contains(where: { $0.id == msgId }) {
                                self.messages.append(
                                    LetsTrackMessage(
                                        id: msgId,
                                        senderName: sName,
                                        senderType: sType,
                                        text: text
                                    )
                                )
                            }
                        }
                    }
                }
            case "msg-received":
                let text = data["text"] as? String ?? ""
                if !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    let sType = data["senderType"] as? String ?? "Agent"
                    let sName = data["senderName"] as? String ?? "Support Officer"
                    let msgId = data["_id"] as? String ?? UUID().uuidString
                    self.isAgentTyping = false
                    if !self.messages.contains(where: { $0.id == msgId }) {
                        self.messages.append(
                            LetsTrackMessage(
                                id: msgId,
                                senderName: sName,
                                senderType: sType,
                                text: text
                            )
                        )
                    }
                }
            case "agent-typing":
                self.isAgentTyping = data["isTyping"] as? Bool ?? false
            default:
                break
            }
        }
    }
    
    func send(text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        
        let newMsg = LetsTrackMessage(
            senderName: customerName,
            senderType: "Visitor",
            text: trimmed
        )
        messages.append(newMsg)
        
        let escaped = trimmed
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "")
        
        webView?.evaluateJavaScript("sendVisitorMsg(\"\(escaped)\");", completionHandler: nil)
    }
    
    func setTyping(isTyping: Bool) {
        webView?.evaluateJavaScript("setVisitorTyping(\(isTyping));", completionHandler: nil)
    }
    
    func cleanup() {
        webView?.configuration.userContentController.removeScriptMessageHandler(forName: "chatBridge")
        webView?.stopLoading()
        webView = nil
    }
}

// MARK: - Native LetsTrack Live Support Chat Dialog (1:1 with Android)
struct LetsTrackChatDialog: View {
    @Binding var isOpen: Bool
    let customerName: String
    let customerEmail: String
    var customerPhone: String = ""
    
    @StateObject private var socketCoordinator: LetsTrackSocketCoordinator
    @State private var inputText: String = ""
    
    private let quickPrompts = [
        "📋 Track My Filing Status",
        "📑 Download Tax Invoice",
        "💼 MSME / GST Query",
        "📞 Speak with an Expert"
    ]
    
    init(isOpen: Binding<Bool>, customerName: String, customerEmail: String, customerPhone: String = "") {
        self._isOpen = isOpen
        self.customerName = customerName
        self.customerEmail = customerEmail
        self.customerPhone = customerPhone
        self._socketCoordinator = StateObject(
            wrappedValue: LetsTrackSocketCoordinator(customerName: customerName, customerEmail: customerEmail, customerPhone: customerPhone)
        )
    }
    
    var body: some View {
        if isOpen {
            ZStack(alignment: .bottom) {
                // Dimmed Backdrop
                Color.black.opacity(0.55)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                            isOpen = false
                        }
                    }
                
                // Floating Chat Card matching Android LetsTrackChatDialog
                VStack(spacing: 0) {
                    // Header Bar with VR HERE Crimson-to-Navy Gradient
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text("VR HERE Live Support")
                                .font(.system(size: 15, weight: .bold))
                                .foregroundColor(.white)
                            
                            HStack(spacing: 6) {
                                Circle()
                                    .fill(socketCoordinator.isConnected ? Color(red: 16/255, green: 185/255, blue: 129/255) : Color(red: 245/255, green: 158/255, blue: 11/255))
                                    .frame(width: 8, height: 8)
                                    .shadow(color: (socketCoordinator.isConnected ? Color.green : Color.orange).opacity(0.6), radius: 3)
                                
                                Text(socketCoordinator.isConnected ? "Online • Connected to LetsTrack" : "Connecting...")
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(Color.white.opacity(0.9))
                            }
                        }
                        
                        Spacer()
                        
                        // Close Button
                        Button(action: {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                isOpen = false
                            }
                        }) {
                            Image(systemName: "xmark")
                                .font(.system(size: 13, weight: .bold))
                                .foregroundColor(.white)
                                .frame(width: 30, height: 30)
                                .background(Color.white.opacity(0.2))
                                .clipShape(Circle())
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                    .background(
                        LinearGradient(
                            colors: [Color(red: 220/255, green: 38/255, blue: 38/255), Color(red: 49/255, green: 46/255, blue: 129/255)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    )
                    
                    // Messages Thread Area
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(spacing: 12) {
                                ForEach(socketCoordinator.messages) { msg in
                                    let isVisitor = msg.senderType == "Visitor"
                                    let isSystem = msg.senderType == "System"
                                    
                                    VStack(alignment: isVisitor ? .trailing : .leading, spacing: 3) {
                                        if !isVisitor {
                                            Text(msg.senderName)
                                                .font(.system(size: 10, weight: .semibold))
                                                .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                                                .padding(.leading, 6)
                                        }
                                        
                                        VStack(alignment: isVisitor ? .trailing : .leading, spacing: 4) {
                                            Text(msg.text)
                                                .font(.system(size: 13.5))
                                                .lineSpacing(3)
                                                .foregroundColor(
                                                    isVisitor ? .white : (isSystem ? Color(red: 146/255, green: 64/255, blue: 14/255) : Color(red: 15/255, green: 23/255, blue: 42/255))
                                                )
                                            
                                            Text(msg.timestamp)
                                                .font(.system(size: 9.5, weight: .medium))
                                                .foregroundColor(
                                                    isVisitor ? Color.white.opacity(0.75) : (isSystem ? Color(red: 180/255, green: 83/255, blue: 9/255).opacity(0.8) : Color(red: 100/255, green: 116/255, blue: 139/255))
                                                )
                                        }
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 10)
                                        .background(
                                            isVisitor ? Color(red: 220/255, green: 38/255, blue: 38/255) :
                                            (isSystem ? Color(red: 254/255, green: 243/255, blue: 199/255) : Color(red: 226/255, green: 232/255, blue: 240/255))
                                        )
                                        .cornerRadius(16)
                                        .shadow(color: isVisitor ? Color.black.opacity(0.08) : Color.clear, radius: 4, y: 2)
                                    }
                                    .frame(maxWidth: .infinity, alignment: isVisitor ? .trailing : .leading)
                                    .id(msg.id)
                                }
                                
                                // Agent Typing Indicator
                                if socketCoordinator.isAgentTyping {
                                    HStack(spacing: 5) {
                                        AgentTypingDotsView()
                                    }
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 10)
                                    .background(Color(red: 226/255, green: 232/255, blue: 240/255))
                                    .cornerRadius(14)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id("typing_indicator")
                                }
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 12)
                        }
                        .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                        .onChange(of: socketCoordinator.messages.count) { _ in
                            if let last = socketCoordinator.messages.last {
                                withAnimation {
                                    proxy.scrollTo(last.id, anchor: .bottom)
                                }
                            }
                        }
                        .onChange(of: socketCoordinator.isAgentTyping) { typing in
                            if typing {
                                withAnimation {
                                    proxy.scrollTo("typing_indicator", anchor: .bottom)
                                }
                            }
                        }
                    }
                    
                    // Quick Suggestion Chips Row
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(quickPrompts, id: \.self) { prompt in
                                Button(action: {
                                    socketCoordinator.send(text: prompt)
                                }) {
                                    Text(prompt)
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                        .padding(.horizontal, 11)
                                        .padding(.vertical, 6)
                                        .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                                        .cornerRadius(14)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 14)
                                                .stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1)
                                        )
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                    }
                    .background(Color.white)
                    
                    // Input Bar
                    HStack(spacing: 10) {
                        TextField("Type your message...", text: $inputText)
                            .font(.system(size: 13.5))
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10)
                            .background(Color(red: 248/255, green: 250/255, blue: 252/255))
                            .cornerRadius(22)
                            .overlay(
                                RoundedRectangle(cornerRadius: 22)
                                    .stroke(Color(red: 203/255, green: 213/255, blue: 225/255), lineWidth: 1)
                            )
                            .onChange(of: inputText) { val in
                                socketCoordinator.setTyping(isTyping: !val.isEmpty)
                            }
                            .onSubmit {
                                if !inputText.isEmpty {
                                    socketCoordinator.send(text: inputText)
                                    inputText = ""
                                }
                            }
                        
                        // Send Button
                        Button(action: {
                            if !inputText.isEmpty {
                                socketCoordinator.send(text: inputText)
                                inputText = ""
                            }
                        }) {
                            ZStack {
                                Circle()
                                    .fill(
                                        LinearGradient(
                                            colors: [Color(red: 220/255, green: 38/255, blue: 38/255), Color(red: 225/255, green: 29/255, blue: 72/255)],
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        )
                                    )
                                    .frame(width: 40, height: 40)
                                    .shadow(color: Color(red: 220/255, green: 38/255, blue: 38/255).opacity(0.35), radius: 4, y: 2)
                                
                                Image(systemName: "paperplane.fill")
                                    .font(.system(size: 15, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(Color.white)
                    .overlay(
                        Divider(), alignment: .top
                    )
                    
                    // LetsTrack Branding Footer
                    HStack {
                        Spacer()
                        Text("⚡ Powered by LetsTrack™")
                            .font(.system(size: 9.5, weight: .semibold))
                            .foregroundColor(Color(red: 100/255, green: 116/255, blue: 139/255))
                        Spacer()
                    }
                    .padding(.vertical, 5)
                    .background(Color(red: 241/255, green: 245/255, blue: 249/255))
                }
                .frame(maxWidth: .infinity)
                .frame(height: min(UIScreen.main.bounds.height * 0.72, 580))
                .background(Color.white)
                .cornerRadius(20)
                .shadow(color: Color.black.opacity(0.3), radius: 20, y: 8)
                .padding(.horizontal, 8)
                .padding(.bottom, 12)
            }
            .transition(.opacity.combined(with: .move(edge: .bottom)))
            .zIndex(9999)
        }
    }
}

// MARK: - Animated Typing Indicator Dots
struct AgentTypingDotsView: View {
    @State private var dotPhase = 0
    
    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(Color(red: 100/255, green: 116/255, blue: 139/255))
                .frame(width: 5, height: 5)
                .opacity(dotPhase == 0 ? 1.0 : 0.3)
            
            Circle()
                .fill(Color(red: 100/255, green: 116/255, blue: 139/255))
                .frame(width: 5, height: 5)
                .opacity(dotPhase == 1 ? 1.0 : 0.3)
            
            Circle()
                .fill(Color(red: 100/255, green: 116/255, blue: 139/255))
                .frame(width: 5, height: 5)
                .opacity(dotPhase == 2 ? 1.0 : 0.3)
        }
        .onAppear {
            Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { timer in
                dotPhase = (dotPhase + 1) % 3
            }
        }
    }
}
