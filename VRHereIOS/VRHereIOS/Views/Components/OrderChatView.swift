import SwiftUI
import UniformTypeIdentifiers

struct OrderChatView: View {
    let orderId: String
    let currentUserRole: String
    let currentUserId: String

    @State private var selectedChannel = "client" // "client" or "internal"
    @State private var messages: [OrderChatMessage] = []
    @State private var messageText = ""
    @State private var isLoading = false
    @State private var isSending = false
    @State private var showFilePicker = false
    @State private var pickedFileData: Data? = nil
    @State private var pickedFileName: String? = nil
    @State private var pickedFileMime: String? = nil
    @State private var errorMessage: String? = nil

    var body: some View {
        VStack(spacing: 10) {
            // Channel Switcher (Visible to Staff Only)
            if currentUserRole != "client" {
                HStack(spacing: 8) {
                    Button(action: {
                        selectedChannel = "client"
                        Task { await fetchMessages() }
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "bubble.left.and.bubble.right.fill")
                                .font(.system(size: 11))
                            Text("Client Channel")
                                .font(.system(size: 12, weight: .bold))
                        }
                        .foregroundColor(selectedChannel == "client" ? .white : Color(hex: "64748B"))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(selectedChannel == "client" ? Color(hex: "4F46E5") : Color(hex: "F1F5F9"))
                        .cornerRadius(10)
                    }

                    Button(action: {
                        selectedChannel = "internal"
                        Task { await fetchMessages() }
                    }) {
                        HStack(spacing: 6) {
                            Image(systemName: "lock.fill")
                                .font(.system(size: 11))
                            Text("Internal Staff Only")
                                .font(.system(size: 12, weight: .bold))
                        }
                        .foregroundColor(selectedChannel == "internal" ? .white : Color(hex: "64748B"))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .background(selectedChannel == "internal" ? Color(hex: "F59E0B") : Color(hex: "F1F5F9"))
                        .cornerRadius(10)
                    }
                }
                .padding(.horizontal, 2)
            }

            // Channel Info Banner
            HStack(spacing: 6) {
                Image(systemName: selectedChannel == "client" ? "info.circle.fill" : "lock.shield.fill")
                    .font(.system(size: 10))
                    .foregroundColor(selectedChannel == "client" ? Color(hex: "4338CA") : Color(hex: "92400E"))
                Text(selectedChannel == "client" ? "Visible to the Client and assigned Service Team." : "🔒 Internal Staff Chat: Visible strictly to Admins, PM, Makers, and Checkers.")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(selectedChannel == "client" ? Color(hex: "4338CA") : Color(hex: "92400E"))
                Spacer()
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(selectedChannel == "client" ? Color(hex: "EEF2FF") : Color(hex: "FEF3C7"))
            .cornerRadius(8)

            // Message Stream
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 10) {
                        if isLoading && messages.isEmpty {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 30)
                        } else if messages.isEmpty {
                            VStack(spacing: 6) {
                                Image(systemName: "bubble.middle.bottom")
                                    .font(.system(size: 32))
                                    .foregroundColor(Color(hex: "CBD5E1"))
                                Text("No messages yet in this channel.")
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundColor(Color(hex: "94A3B8"))
                                Text("Start the conversation below.")
                                    .font(.system(size: 10))
                                    .foregroundColor(Color(hex: "CBD5E1"))
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 40)
                        } else {
                            ForEach(messages) { msg in
                                messageBubble(msg)
                                    .id(msg.id)
                            }
                        }
                    }
                    .padding(.vertical, 6)
                }
                .frame(maxHeight: 380)
                .onChange(of: messages.count) { _ in
                    if let last = messages.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }

            // Attached file pill
            if let fname = pickedFileName {
                HStack {
                    Image(systemName: "paperclip")
                        .font(.system(size: 11))
                        .foregroundColor(Color(hex: "4F46E5"))
                    Text(fname)
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(Color(hex: "1E293B"))
                        .lineLimit(1)
                    Spacer()
                    Button(action: {
                        pickedFileData = nil
                        pickedFileName = nil
                        pickedFileMime = nil
                    }) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 14))
                            .foregroundColor(Color(hex: "EF4444"))
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color(hex: "F1F5F9"))
                .cornerRadius(8)
            }

            // Input Row
            HStack(spacing: 8) {
                Button(action: { showFilePicker = true }) {
                    Image(systemName: "paperclip")
                        .font(.system(size: 15))
                        .foregroundColor(Color(hex: "64748B"))
                        .frame(width: 38, height: 38)
                        .background(Color(hex: "F1F5F9"))
                        .clipShape(Circle())
                }

                TextField("Type message...", text: $messageText)
                    .font(.system(size: 13))
                    .padding(.horizontal, 14)
                    .padding(.vertical, 9)
                    .background(Color(hex: "F8FAFC"))
                    .cornerRadius(20)
                    .overlay(
                        RoundedRectangle(cornerRadius: 20)
                            .stroke(Color(hex: "E2E8F0"), lineWidth: 1)
                    )

                Button(action: { Task { await sendMessage() } }) {
                    if isSending {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                            .frame(width: 38, height: 38)
                            .background(Color(hex: "4F46E5"))
                            .clipShape(Circle())
                    } else {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 28))
                            .foregroundColor((messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && pickedFileData == nil) ? Color(hex: "CBD5E1") : Color(hex: "4F46E5"))
                    }
                }
                .disabled(isSending || (messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && pickedFileData == nil))
            }
            
            if let err = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 11))
                    Text(err)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.red)
                    Spacer()
                }
                .padding(.horizontal, 4)
                .padding(.top, 2)
            }
        }
        .padding(14)
        .background(Color.white)
        .cornerRadius(16)
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color(hex: "E2E8F0"), lineWidth: 1)
        )
        .task {
            await fetchMessages()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                await fetchMessages(silent: true)
            }
        }
        .sheet(isPresented: $showFilePicker) {
            #if os(iOS)
            DocumentPickerView { url in
                if let data = try? Data(contentsOf: url) {
                    pickedFileData = data
                    pickedFileName = url.lastPathComponent
                    pickedFileMime = "application/octet-stream"
                }
            }
            #endif
        }
    }

    @ViewBuilder
    private func messageBubble(_ msg: OrderChatMessage) -> some View {
        let isMe = (msg.sender?.id == currentUserId && !currentUserId.isEmpty) ||
                   (currentUserRole == "admin" && msg.sender?.role == "admin")
        let senderRole = msg.sender?.role ?? "user"
        let senderName = msg.sender?.name ?? "Staff"

        HStack {
            if isMe { Spacer() }

            VStack(alignment: isMe ? .trailing : .leading, spacing: 3) {
                // Sender & Role Badge
                HStack(spacing: 4) {
                    Text(isMe ? "You" : senderName)
                        .font(.system(size: 10, weight: .bold))
                        .foregroundColor(Color(hex: "64748B"))

                    Text(senderRole.uppercased())
                        .font(.system(size: 8, weight: .black))
                        .foregroundColor(.white)
                        .padding(.horizontal, 4)
                        .padding(.vertical, 1)
                        .background(
                            senderRole.lowercased() == "admin" ? Color(hex: "DC2626") :
                            senderRole.lowercased() == "client" ? Color(hex: "059669") : Color(hex: "4F46E5")
                        )
                        .cornerRadius(3)
                }

                // Bubble Content
                VStack(alignment: .leading, spacing: 4) {
                    if !msg.message.isEmpty {
                        Text(msg.message)
                            .font(.system(size: 12))
                            .foregroundColor(isMe ? .white : Color(hex: "1E293B"))
                    }

                    // Attachments
                    ForEach(msg.attachments) { att in
                        if let url = URL(string: att.url) {
                            Link(destination: url) {
                                HStack(spacing: 4) {
                                    Image(systemName: "doc.fill")
                                        .font(.system(size: 10))
                                    Text(att.name.isEmpty ? "Attachment" : att.name)
                                        .font(.system(size: 10, weight: .bold))
                                        .lineLimit(1)
                                }
                                .padding(.horizontal, 6)
                                .padding(.vertical, 3)
                                .background(isMe ? Color.white.opacity(0.2) : Color.white)
                                .foregroundColor(isMe ? .white : Color(hex: "4F46E5"))
                                .cornerRadius(5)
                            }
                        }
                    }

                    // Timestamp
                    let timeStr = msg.createdAt.count >= 16 ? String(msg.createdAt.suffix(from: msg.createdAt.index(msg.createdAt.startIndex, offsetBy: 11)).prefix(5)) : "Now"
                    HStack {
                        Spacer()
                        Text(timeStr)
                            .font(.system(size: 8))
                            .foregroundColor(isMe ? Color.white.opacity(0.7) : Color(hex: "94A3B8"))
                    }
                }
                .padding(10)
                .background(
                    isMe ?
                    (selectedChannel == "internal" ? Color(hex: "F59E0B") : Color(hex: "4F46E5")) :
                    Color(hex: "F1F5F9")
                )
                .cornerRadius(12)
            }
            .frame(maxWidth: 280, alignment: isMe ? .trailing : .leading)

            if !isMe { Spacer() }
        }
    }

    private func fetchMessages(silent: Bool = false) async {
        if !silent { isLoading = true }
        do {
            let fetched = try await NetworkManager.shared.getOrderMessages(orderId: orderId, messageType: selectedChannel)
            await MainActor.run {
                self.messages = fetched
                self.isLoading = false
            }
        } catch {
            await MainActor.run {
                self.isLoading = false
            }
        }
    }

    private func sendMessage() async {
        let text = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty && pickedFileData == nil { return }

        isSending = true
        do {
            let _ = try await NetworkManager.shared.sendOrderMessage(
                orderId: orderId,
                message: text,
                messageType: selectedChannel,
                fileData: pickedFileData,
                fileName: pickedFileName,
                mimeType: pickedFileMime
            )
            await MainActor.run {
                self.messageText = ""
                self.pickedFileData = nil
                self.pickedFileName = nil
                self.pickedFileMime = nil
                self.isSending = false
            }
            await fetchMessages(silent: true)
        } catch {
            await MainActor.run {
                self.isSending = false
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
