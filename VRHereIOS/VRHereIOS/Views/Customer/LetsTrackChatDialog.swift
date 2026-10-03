import SwiftUI
import Combine

struct LetsTrackMessage: Identifiable, Equatable {
    let id: String
    let senderName: String
    let senderType: String // "Visitor" | "Agent" | "System"
    let text: String
    let timestamp: String
    
    init(
        id: String = UUID().uuidString,
        senderName: String,
        senderType: String,
        text: String,
        timestamp: String = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .short)
    ) {
        self.id = id
        self.senderName = senderName
        self.senderType = senderType
        self.text = text
        self.timestamp = timestamp
    }
}

struct LetsTrackChatDialog: View {
    @Binding var isOpen: Bool
    let customerName: String
    let customerEmail: String
    
    @State private var inputText: String = ""
    @State private var isAgentTyping: Bool = false
    @State private var isConnected: Bool = true
    @State private var messages: [LetsTrackMessage] = []
    
    private let quickPrompts = [
        "📋 Track My Filing Status",
        "📑 Download Tax Invoice",
        "💼 MSME / GST Query",
        "📞 Speak with an Expert"
    ]
    
    var body: some View {
        if isOpen {
            ZStack {
                Color.black.opacity(0.55)
                    .ignoresSafeArea()
                    .onTapGesture {
                        withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                            isOpen = false
                        }
                    }
                
                VStack(spacing: 0) {
                    // Top Header matching Android LetsTrackChatDialog
                    HStack(spacing: 12) {
                        ZStack(alignment: .bottomTrailing) {
                            ZStack {
                                Circle()
                                    .fill(
                                        LinearGradient(
                                            colors: [Color.primaryRed, Color(red: 180/255, green: 20/255, blue: 20/255)],
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
                                    .font(.system(size: 8, weight: .black))
                                    .foregroundColor(Color(red: 34/255, green: 197/255, blue: 94/255))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color(red: 34/255, green: 197/255, blue: 94/255).opacity(0.2))
                                    .clipShape(Capsule())
                            }
                            
                            Text("Dedicated CA & Compliance Desk")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                        }
                        
                        Spacer()
                        
                        Button(action: {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                isOpen = false
                            }
                        }) {
                            ZStack {
                                Circle()
                                    .fill(Color.white.opacity(0.12))
                                    .frame(width: 32, height: 32)
                                Image(systemName: "xmark")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(16)
                    .background(Color.darkSlate)
                    
                    // Chat Message Stream
                    ScrollViewReader { proxy in
                        ScrollView {
                            VStack(spacing: 12) {
                                ForEach(messages) { msg in
                                    let isMe = msg.senderType.lowercased() == "visitor"
                                    HStack(alignment: .bottom, spacing: 8) {
                                        if isMe { Spacer(minLength: 40) }
                                        
                                        if !isMe {
                                            ZStack {
                                                Circle()
                                                    .fill(Color.primaryRed.opacity(0.15))
                                                    .frame(width: 28, height: 28)
                                                Image(systemName: "person.badge.shield.checkmark.fill")
                                                    .font(.system(size: 12))
                                                    .foregroundColor(.primaryRed)
                                            }
                                        }
                                        
                                        VStack(alignment: isMe ? .trailing : .leading, spacing: 3) {
                                            if !isMe {
                                                Text(msg.senderName)
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(Color.textMuted)
                                                    .padding(.leading, 4)
                                            }
                                            
                                            Text(msg.text)
                                                .font(.system(size: 13, weight: .medium))
                                                .foregroundColor(isMe ? .white : Color.textDark)
                                                .padding(.horizontal, 14)
                                                .padding(.vertical, 10)
                                                .background(isMe ? Color.primaryRed : Color.white)
                                                .cornerRadius(16)
                                                .overlay(
                                                    RoundedRectangle(cornerRadius: 16)
                                                        .stroke(isMe ? Color.clear : Color.borderLight, lineWidth: 1)
                                                )
                                                .shadow(color: Color.black.opacity(0.04), radius: 4, y: 1)
                                            
                                            Text(msg.timestamp)
                                                .font(.system(size: 9))
                                                .foregroundColor(Color.textMuted)
                                                .padding(.horizontal, 4)
                                        }
                                        
                                        if !isMe { Spacer(minLength: 40) }
                                    }
                                    .id(msg.id)
                                }
                                
                                if isAgentTyping {
                                    HStack {
                                        HStack(spacing: 4) {
                                            Circle().fill(Color.textMuted).frame(width: 5, height: 5)
                                            Circle().fill(Color.textMuted).frame(width: 5, height: 5)
                                            Circle().fill(Color.textMuted).frame(width: 5, height: 5)
                                        }
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 8)
                                        .background(Color.white)
                                        .cornerRadius(12)
                                        Spacer()
                                    }
                                }
                            }
                            .padding(16)
                        }
                        .onChange(of: messages.count) { _ in
                            if let last = messages.last {
                                withAnimation {
                                    proxy.scrollTo(last.id, anchor: .bottom)
                                }
                            }
                        }
                    }
                    .background(Color.bgLight)
                    
                    // Quick Action Prompts
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(quickPrompts, id: \.self) { prompt in
                                Button(action: {
                                    sendQuickPrompt(prompt)
                                }) {
                                    Text(prompt)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(Color.textDark)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 7)
                                        .background(Color.white)
                                        .cornerRadius(20)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 20)
                                                .stroke(Color.borderLight, lineWidth: 1)
                                        )
                                        .shadow(color: Color.black.opacity(0.02), radius: 2, y: 1)
                                }
                                .buttonStyle(PlainButtonStyle())
                            }
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                    }
                    .background(Color.white)
                    
                    Divider().background(Color.borderLight)
                    
                    // Bottom Input Row
                    HStack(spacing: 10) {
                        TextField("Type your query or requirement...", text: $inputText)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(Color.textDark)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                            .background(Color.bgInput)
                            .cornerRadius(20)
                            .onSubmit {
                                sendMessage()
                            }
                        
                        Button(action: {
                            sendMessage()
                        }) {
                            ZStack {
                                Circle()
                                    .fill(inputText.trimmingCharacters(in: .whitespaces).isEmpty ? Color.textMuted.opacity(0.4) : Color.primaryRed)
                                    .frame(width: 38, height: 38)
                                Image(systemName: "paperplane.fill")
                                    .font(.system(size: 14))
                                    .foregroundColor(.white)
                            }
                        }
                        .disabled(inputText.trimmingCharacters(in: .whitespaces).isEmpty)
                        .buttonStyle(PlainButtonStyle())
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 10)
                    .background(Color.white)
                }
                .frame(maxWidth: .infinity)
                .frame(height: 520)
                .background(Color.white)
                .cornerRadius(24)
                .overlay(
                    RoundedRectangle(cornerRadius: 24)
                        .stroke(Color.borderLight, lineWidth: 1)
                )
                .shadow(color: Color.black.opacity(0.25), radius: 20, y: 8)
                .padding(.horizontal, 14)
            }
            .transition(.opacity.combined(with: .scale(scale: 0.95)))
            .onAppear {
                if messages.isEmpty {
                    let dName = customerName.isEmpty ? "Valued Client" : customerName
                    messages.append(
                        LetsTrackMessage(
                            senderName: "VR HERE Assistant",
                            senderType: "System",
                            text: "Welcome to VR HERE Live Support! How can our compliance advisors assist you today, \(dName)?"
                        )
                    )
                }
            }
        }
    }
    
    private func sendMessage() {
        let text = inputText.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        
        let clientMsg = LetsTrackMessage(
            senderName: customerName.isEmpty ? "You" : customerName,
            senderType: "Visitor",
            text: text
        )
        messages.append(clientMsg)
        inputText = ""
        
        // Automated intelligent response
        isAgentTyping = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            isAgentTyping = false
            let replyText = generateBotReply(for: text)
            let botMsg = LetsTrackMessage(
                senderName: "VR HERE Advisor",
                senderType: "Agent",
                text: replyText
            )
            messages.append(botMsg)
        }
    }
    
    private func sendQuickPrompt(_ prompt: String) {
        let cleanText = prompt.replacingOccurrences(of: "📋 ", with: "")
            .replacingOccurrences(of: "📑 ", with: "")
            .replacingOccurrences(of: "💼 ", with: "")
            .replacingOccurrences(of: "📞 ", with: "")
        
        let clientMsg = LetsTrackMessage(
            senderName: customerName.isEmpty ? "You" : customerName,
            senderType: "Visitor",
            text: cleanText
        )
        messages.append(clientMsg)
        
        isAgentTyping = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            isAgentTyping = false
            let replyText: String
            if prompt.contains("Track My Filing") {
                replyText = "You can view real-time stage progress for your active filings in the Orders tab. Our team updates MCA & GST portal filing reference numbers immediately upon submission."
            } else if prompt.contains("Download Tax Invoice") {
                replyText = "All GST-compliant invoices with IRN and QR codes are available in your Invoices tab. You can download PDF copies or share them with your accounting department."
            } else if prompt.contains("MSME / GST") {
                replyText = "We assist with new GST/MSME registrations, amendment filings, and monthly return reconciliations. Check the Services catalog to initiate a new registration."
            } else {
                replyText = "Our Senior Chartered Accountant and legal advocates are available directly via WhatsApp (+91 80085 30606) or phone dialer for priority consultation."
            }
            
            let botMsg = LetsTrackMessage(
                senderName: "VR HERE Advisory Team",
                senderType: "Agent",
                text: replyText
            )
            messages.append(botMsg)
        }
    }
    
    private func generateBotReply(for query: String) -> String {
        let q = query.lowercased()
        if q.contains("status") || q.contains("order") || q.contains("filing") {
            return "Your ongoing filings are synced in real-time with the MCA & GST portals. Please check the 'Orders' tab to view your current milestone status or upload requested documents."
        } else if q.contains("invoice") || q.contains("payment") || q.contains("bill") || q.contains("gst") {
            return "Invoices and payment receipts are available for instant download in the 'Invoices' tab. All filings include 100% compliant GST tax invoices."
        } else if q.contains("call") || q.contains("contact") || q.contains("phone") || q.contains("advisor") || q.contains("expert") {
            return "You can reach our dedicated advisory helpline directly at +91 80085 30606 or tap the WhatsApp button to chat instantly with your assigned compliance manager."
        } else {
            return "Thank you for contacting VR HERE Support! Our operations team has received your query and will assist you shortly. You can also explore our full service catalog in the app."
        }
    }
}
