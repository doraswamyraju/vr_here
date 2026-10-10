import SwiftUI

// --- Color Styling Extensions ---
extension Color {
    static let primaryRed = Color(red: 200/255, green: 35/255, blue: 35/255) // #C82323
    static let textDark = Color(red: 30/255, green: 41/255, blue: 59/255)    // #1E293B
    static let textMuted = Color(red: 100/255, green: 116/255, blue: 139/255) // #64748B
    static let bgLight = Color(red: 248/255, green: 250/255, blue: 252/255)  // #F8FAFC
    static let borderLight = Color(red: 241/255, green: 245/255, blue: 249/255) // #F1F5F9
    static let bgInput = Color(red: 238/255, green: 242/255, blue: 246/255)   // #EEF2F6
    static let darkSlate = Color(red: 15/255, green: 23/255, blue: 42/255)   // #0F172A
    
    static let slate900 = Color(red: 15/255, green: 23/255, blue: 42/255)
    static let slate400 = Color(red: 148/255, green: 163/255, blue: 184/255)
    static let emerald500 = Color(red: 16/255, green: 185/255, blue: 129/255)
    static let emerald400 = Color(red: 52/255, green: 211/255, blue: 153/255)
    static let indigo500 = Color(red: 99/255, green: 102/255, blue: 241/255)
    static let indigo400 = Color(red: 129/255, green: 140/255, blue: 248/255)
    
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let a, r, g, b: UInt64
        switch hex.count {
        case 3: // RGB (12-bit)
            (a, r, g, b) = (255, (int >> 8) * 17, (int >> 4 & 0xF) * 17, (int & 0xF) * 17)
        case 6: // RGB (24-bit)
            (a, r, g, b) = (255, int >> 16, int >> 8 & 0xFF, int & 0xFF)
        case 8: // ARGB (32-bit)
            (a, r, g, b) = (int >> 24, int >> 16 & 0xFF, int >> 8 & 0xFF, int & 0xFF)
        default:
            (a, r, g, b) = (255, 0, 0, 0)
        }
        self.init(
            .sRGB,
            red: Double(r) / 255,
            green: Double(g) / 255,
            blue: Double(b) / 255,
            opacity: Double(a) / 255
        )
    }
}

// Scale-on-Press Button Style for micro-animations
struct ScaleOnPressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1.0)
            .animation(.spring(response: 0.3, dampingFraction: 0.6, blendDuration: 0), value: configuration.isPressed)
    }
}

// Glassmorphic Card Style
struct GlassCardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .background(Color.white)
            .cornerRadius(16)
            .shadow(color: Color.black.opacity(0.05), radius: 10, x: 0, y: 4)
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.borderLight, lineWidth: 1)
            )
    }
}

extension View {
    func glassCard() -> some View {
        self.modifier(GlassCardModifier())
    }
    
    func glassCardStyle() -> some View {
        self.padding(16)
            .background(Color.white)
            .cornerRadius(16)
    }
    
    func safeSystemIconName(baseName: String, isSelected: Bool) -> String {
        if !isSelected { return baseName }
        
        let nonFillableSymbols = [
            "activity",
            "trending.up",
            "doc.badge.checkmark",
            "phone.badge.checkmark",
            "slider.horizontal.3",
            "arrow.triangle.2.circlepath",
            "signature",
            "doc.text",
            "headphones"
        ]
        
        if nonFillableSymbols.contains(baseName) || baseName.contains(".badge.") || baseName.hasSuffix(".fill") {
            return baseName
        }
        return baseName + ".fill"
    }
    
    func onSwipeBackGesture(perform action: @escaping () -> Void) -> some View {
        self.gesture(
            DragGesture(minimumDistance: 15, coordinateSpace: .local)
                .onEnded { value in
                    let horizontalDistance = value.translation.width
                    let verticalDistance = value.translation.height
                    
                    if abs(verticalDistance) < 50 {
                        if horizontalDistance > 80 { // Left to right
                            action()
                        } else if horizontalDistance < -80 { // Right to left
                            action()
                        }
                    }
                }
        )
    }
}

// Helper for resolving image URLs (including Google Drive links, /uploads/ paths, etc.)
extension String {
    var asImageURL: URL? {
        let trimmed = self.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "null", trimmed != "undefined" else { return nil }
        
        // Google Drive conversion matching Android formatImageUrl
        if trimmed.contains("drive.google.com/file/d/") {
            if let match = trimmed.range(of: #"(?<=/file/d/)[a-zA-Z0-9_-]+"#, options: .regularExpression) {
                let fileId = String(trimmed[match])
                return URL(string: "https://lh3.googleusercontent.com/d/\(fileId)")
            }
        }
        if trimmed.contains("drive.google.com/open?id=") || trimmed.contains("drive.google.com/uc?id=") {
            if let match = trimmed.range(of: #"(?<=id=)[a-zA-Z0-9_-]+"#, options: .regularExpression) {
                let fileId = String(trimmed[match])
                return URL(string: "https://lh3.googleusercontent.com/d/\(fileId)")
            }
        }
        
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            let fixed = trimmed.replacingOccurrences(of: "http://localhost:5000", with: "https://vrhere.in")
                               .replacingOccurrences(of: "http://127.0.0.1:5000", with: "https://vrhere.in")
            return URL(string: fixed)
        }
        
        let clean = trimmed.hasPrefix("/") ? String(trimmed.dropFirst()) : trimmed
        return URL(string: "https://vrhere.in/" + clean)
    }
}

// Polished Horizontal Brand Logo Component
struct VRLogoView: View {
    var height: CGFloat = 26
    var onClick: (() -> Void)? = nil
    
    var body: some View {
        Group {
            if let onClick = onClick {
                Button(action: onClick) {
                    content
                }
                .buttonStyle(PlainButtonStyle())
            } else {
                content
            }
        }
    }
    
    private var content: some View {
        HStack(spacing: 7) {
            Image("logo")
                .renderingMode(.original)
                .resizable()
                .scaledToFit()
                .frame(height: height)
            
            // Vertical Divider line with a red dot centered on it
            ZStack {
                Rectangle()
                    .fill(Color.textMuted.opacity(0.4))
                    .frame(width: 1, height: height * 0.88)
                
                Circle()
                    .fill(Color.primaryRed)
                    .frame(width: 4.5, height: 4.5)
            }
            .frame(width: 6)
            
            VStack(alignment: .leading, spacing: 0) {
                // "Here" with its red underline
                VStack(alignment: .leading, spacing: 1) {
                    Text("Here")
                        .font(.custom("Georgia", size: height * 0.52).bold())
                        .foregroundColor(Color.primaryRed)
                    
                    Rectangle()
                        .fill(Color.primaryRed)
                        .frame(height: 1.2)
                }
                .fixedSize()
                
                Spacer(minLength: 1)
                
                // "Business Management Solutions" subtitle
                Text("Business Management Solutions")
                    .font(.system(size: max(6, height * 0.25), weight: .bold))
                    .foregroundColor(Color.textDark)
            }
            .frame(height: height)
        }
    }
}

// Custom Header Style matching Android VRHeader 1:1
// [Toggle/Back] [Logo] ---------------- [Notification Bell] [User Avatar] [Logout]
struct VRHeader: View {
    var title: String = "DASHBOARD"
    var showMenu: Bool = false
    var onMenuClick: (() -> Void)? = nil
    var showLogout: Bool = false
    var onLogoutClick: (() -> Void)? = nil
    
    var showBack: Bool = false
    var onBackClick: (() -> Void)? = nil
    var onLogoClick: (() -> Void)? = nil
    var showNotifications: Bool = false
    var hasUnreadNotifications: Bool = false
    var unreadNotificationsCount: Int = 0
    var onNotificationsClick: (() -> Void)? = nil
    var userProfilePhoto: String? = nil
    var userName: String = ""
    var onProfileClick: (() -> Void)? = nil
    
    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center) {
                // LEFT SIDE: Menu Toggle / Back + Official Brand Logo
                HStack(spacing: 6) {
                    if showMenu {
                        Button(action: { onMenuClick?() }) {
                            Image(systemName: "line.horizontal.3")
                                .font(.system(size: 20, weight: .semibold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                .padding(6)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    } else if showBack {
                        Button(action: { onBackClick?() }) {
                            Image(systemName: "chevron.left")
                                .font(.system(size: 18, weight: .bold))
                                .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                .padding(6)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                    
                    VRLogoView(height: 26, onClick: onLogoClick)
                }
                
                Spacer()
                
                // RIGHT SIDE: Notification Bell + User Profile Pic + Logout Button
                HStack(spacing: 8) {
                    if showNotifications {
                        Button(action: { onNotificationsClick?() }) {
                            ZStack(alignment: .topTrailing) {
                                Image(systemName: "bell")
                                    .font(.system(size: 19, weight: .medium))
                                    .foregroundColor(Color(red: 51/255, green: 65/255, blue: 85/255))
                                    .padding(6)
                                
                                if hasUnreadNotifications || unreadNotificationsCount > 0 {
                                    Circle()
                                        .fill(Color.primaryRed)
                                        .frame(width: 8, height: 8)
                                        .offset(x: 2, y: -2)
                                }
                            }
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }

                    if !userName.isEmpty || userProfilePhoto != nil {
                        VRAvatarView(
                            photoUrl: userProfilePhoto,
                            name: userName.isEmpty ? "Customer" : userName,
                            size: 30,
                            borderWidth: 1.5,
                            borderColor: Color(red: 226/255, green: 232/255, blue: 240/255),
                            onClick: onProfileClick
                        )
                    }
                    
                    if showLogout {
                        Button(action: { onLogoutClick?() }) {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                                .font(.system(size: 18, weight: .semibold))
                                .foregroundColor(Color.primaryRed)
                                .padding(6)
                        }
                        .buttonStyle(ScaleOnPressButtonStyle())
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color.white)
            
            Divider()
                .background(Color.borderLight)
        }
    }
}

// Modern Avatar View matching Android VRAvatarView
struct VRAvatarView: View {
    var photoUrl: String? = nil
    var name: String = ""
    var size: CGFloat = 30
    var borderWidth: CGFloat = 1.5
    var borderColor: Color = Color.borderLight
    var isSquare: Bool = false
    var cornerRadius: CGFloat = 12
    var onClick: (() -> Void)? = nil
    
    private var resolvedURL: URL? {
        photoUrl?.asImageURL
    }
    
    var initials: String {
        let parts = name.split(separator: " ").filter { !$0.isEmpty }
        if parts.isEmpty { return "C" }
        if parts.count == 1 { return String(parts[0].prefix(1)).uppercased() }
        return (String(parts[0].prefix(1)) + String(parts[1].prefix(1))).uppercased()
    }
    
    var body: some View {
        Group {
            if let onClick = onClick {
                Button(action: onClick) {
                    avatarContent
                }
                .buttonStyle(PlainButtonStyle())
            } else {
                avatarContent
            }
        }
    }
    
    private var avatarContent: some View {
        ZStack {
            if let url = resolvedURL {
                AsyncImage(url: url) { phase in
                    switch phase {
                    case .success(let image):
                        image
                            .renderingMode(.original)
                            .resizable()
                            .scaledToFill()
                            .frame(width: size, height: size)
                            .background(Color.white)
                            .clipShape(RoundedRectangle(cornerRadius: isSquare ? cornerRadius : size / 2))
                    case .empty:
                        ZStack {
                            Color.white
                            ProgressView()
                                .scaleEffect(0.6)
                        }
                        .frame(width: size, height: size)
                        .clipShape(RoundedRectangle(cornerRadius: isSquare ? cornerRadius : size / 2))
                    case .failure:
                        fallbackInitials
                    @unknown default:
                        fallbackInitials
                    }
                }
            } else {
                fallbackInitials
            }
        }
        .frame(width: size, height: size)
        .overlay(
            RoundedRectangle(cornerRadius: isSquare ? cornerRadius : size / 2)
                .stroke(borderColor, lineWidth: borderWidth)
        )
        .shadow(color: Color.black.opacity(0.12), radius: 3, y: 1)
    }
    
    private var fallbackInitials: some View {
        ZStack {
            RoundedRectangle(cornerRadius: isSquare ? cornerRadius : size / 2)
                .fill(
                    LinearGradient(
                        colors: [Color(red: 220/255, green: 38/255, blue: 38/255), Color(red: 185/255, green: 28/255, blue: 28/255)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
            
            Text(initials)
                .font(.system(size: max(10, size * 0.38), weight: .black))
                .foregroundColor(.white)
        }
    }
}

// --- Beautiful Reusable Notifications Sheet ---
struct NotificationsSheet: View {
    let notifications: [NotificationResponse]
    let onMarkAsRead: (String) -> Void
    var onMarkAllAsRead: (() -> Void)? = nil
    var onNotificationClick: ((NotificationResponse) -> Void)? = nil
    let onClose: () -> Void
    
    private var unreadCount: Int {
        notifications.filter { !$0.isRead }.count
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Header bar
            HStack(spacing: 8) {
                Text("Notifications")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                
                if unreadCount > 0 {
                    Text("\(unreadCount) new")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(.primaryRed)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.primaryRed.opacity(0.12))
                        .clipShape(Capsule())
                }
                
                Spacer()
                
                if unreadCount > 0, let onMarkAllAsRead = onMarkAllAsRead {
                    Button(action: onMarkAllAsRead) {
                        Text("Mark all read")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.textDark)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(Color.white)
                            .cornerRadius(8)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.borderLight, lineWidth: 1)
                            )
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                }
                
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.textMuted)
                        .frame(width: 30, height: 30)
                        .background(Color.bgInput)
                        .clipShape(Circle())
                }
                .buttonStyle(ScaleOnPressButtonStyle())
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(Color.white)
            
            Divider()
                .background(Color.borderLight)
            
            if notifications.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "bell.slash")
                        .font(.system(size: 40))
                        .foregroundColor(.textMuted)
                    Text("No notifications recorded.")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.textMuted)
                    Spacer()
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(spacing: 12) {
                        ForEach(notifications) { item in
                            Button(action: {
                                onMarkAsRead(item.id)
                                onNotificationClick?(item)
                            }) {
                                HStack(spacing: 14) {
                                    Circle()
                                        .fill(getNotificationColor(type: item.type))
                                        .frame(width: 8, height: 8)
                                    
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(item.title)
                                            .font(.system(size: 13, weight: item.isRead ? .semibold : .bold))
                                            .foregroundColor(.textDark)
                                            .multilineTextAlignment(.leading)
                                        
                                        Text(item.message)
                                            .font(.system(size: 11))
                                            .foregroundColor(.textMuted)
                                            .multilineTextAlignment(.leading)
                                        
                                        Text(formatDateString(item.createdAt))
                                            .font(.system(size: 9))
                                            .foregroundColor(.textMuted.opacity(0.8))
                                    }
                                    
                                    Spacer()
                                    
                                    if !item.isRead {
                                        Circle()
                                            .fill(Color.blue)
                                            .frame(width: 6, height: 6)
                                    }
                                    
                                    Image(systemName: "chevron.right")
                                        .font(.system(size: 10, weight: .bold))
                                        .foregroundColor(Color.textMuted.opacity(0.5))
                                }
                                .padding(14)
                                .background(Color.white)
                                .cornerRadius(14)
                                .shadow(color: Color.black.opacity(0.02), radius: 6)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 14)
                                        .stroke(Color.borderLight, lineWidth: 1)
                                )
                                .opacity(item.isRead ? 0.7 : 1.0)
                            }
                            .buttonStyle(PlainButtonStyle())
                        }
                    }
                    .padding(20)
                }
            }
        }
        .background(Color.bgLight)
    }
    
    private func getNotificationColor(type: String) -> Color {
        switch type.lowercased() {
        case "alert", "error", "critical": return .red
        case "warning": return .orange
        case "success": return .green
        case "info": return .blue
        default: return .purple
        }
    }
    
    private func formatDateString(_ dateString: String) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: dateString) ?? ISO8601DateFormatter().date(from: dateString) {
            let displayFormatter = DateFormatter()
            displayFormatter.dateStyle = .short
            displayFormatter.timeStyle = .short
            return displayFormatter.string(from: date)
        }
        return dateString
    }
}

// Toast View Overlay
struct ToastView: View {
    let message: String
    
    var body: some View {
        Text(message)
            .font(.system(size: 14, weight: .semibold))
            .foregroundColor(.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.black.opacity(0.85))
            .cornerRadius(24)
            .shadow(color: Color.black.opacity(0.2), radius: 8, x: 0, y: 4)
            .padding(.bottom, 50)
            .transition(.move(edge: .bottom).combined(with: .opacity))
    }
}

// Custom Input Textfield with standard icons
struct CustomInputField: View {
    let label: String
    let placeholder: String
    let iconName: String
    @Binding var text: String
    var isSecure: Bool = false
    @State private var isPasswordVisible: Bool = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label)
                .font(.system(size: 13, weight: .bold))
                .foregroundColor(.textDark)
            
            HStack(spacing: 12) {
                Image(systemName: iconName)
                    .foregroundColor(.textMuted)
                    .frame(width: 20)
                
                if isSecure && !isPasswordVisible {
                    SecureField(placeholder, text: $text)
                        .font(.system(size: 15))
                        .foregroundColor(.textDark)
                } else {
                    TextField(placeholder, text: $text)
                        .font(.system(size: 15))
                        .foregroundColor(.textDark)
                }
                
                if isSecure {
                    Button(action: { isPasswordVisible.toggle() }) {
                        Image(systemName: isPasswordVisible ? "eye" : "eye.slash")
                            .foregroundColor(.textMuted)
                    }
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(Color.bgInput)
            .cornerRadius(12)
        }
    }
}

// Banner Headless Notification System
struct BannerNotificationView: View {
    let title: String
    let message: String
    let type: String
    let onClose: () -> Void
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                HStack(spacing: 8) {
                    Text("VR")
                        .font(.system(size: 9, weight: .black))
                        .foregroundColor(.white)
                        .padding(4)
                        .background(Color.primaryRed)
                        .cornerRadius(4)
                    Text("VR Here BMS • \(type)")
                        .font(.system(size: 10, weight: .black))
                        .foregroundColor(Color.primaryRed.opacity(0.8))
                }
                Spacer()
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.caption2)
                        .foregroundColor(.textMuted)
                }
            }
            
            Text(title)
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(.textDark)
            
            Text(message)
                .font(.system(size: 12))
                .foregroundColor(.textMuted)
                .lineLimit(2)
        }
        .padding(16)
        .background(Color.white)
        .cornerRadius(16)
        .shadow(color: Color.black.opacity(0.12), radius: 12, x: 0, y: 6)
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color.primaryRed.opacity(0.2), lineWidth: 1)
        )
    }
}

struct QuickActionCard: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                    .foregroundColor(color)
                Text(title)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(.textDark)
                Spacer()
            }
            .padding(14)
            .background(Color.white)
            .cornerRadius(14)
            .shadow(color: Color.black.opacity(0.02), radius: 4)
        }
        .buttonStyle(PlainButtonStyle())
    }
}

struct TelemetryRow: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(color)
                .padding(8)
                .background(color.opacity(0.1))
                .clipShape(Circle())
            
            Text(title)
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(.textDark)
            
            Spacer()
            
            Text(value)
                .font(.system(size: 14, weight: .black))
                .foregroundColor(.textDark)
        }
        .padding(12)
        .background(Color.white)
        .cornerRadius(12)
    }
}

// --- Standardized Navigation Data Models ---
struct BMSSidebarItem: Identifiable {
    let id = UUID()
    let label: String
    let iconName: String
    let tabId: String
}

struct BMSDockItem: Identifiable {
    let id: UUID
    let label: String
    let iconName: String
    let tabId: String
    var badgeCount: Int?
    
    init(id: UUID = UUID(), label: String, iconName: String, tabId: String, badgeCount: Int? = nil) {
        self.id = id
        self.label = label
        self.iconName = iconName
        self.tabId = tabId
        self.badgeCount = badgeCount
    }
}

struct BMSAppFloatingDock: View {
    @Binding var activeTab: String
    let dockItems: [BMSDockItem]
    var onTabSelected: ((String) -> Void)? = nil
    
    @Namespace private var animationNamespace
    
    var body: some View {
        HStack(spacing: 6) {
            ForEach(dockItems) { item in
                let isSelected = activeTab == item.tabId
                
                Button(action: {
                    withAnimation(.spring(response: 0.35, dampingFraction: 0.7)) {
                        activeTab = item.tabId
                    }
                    let generator = UIImpactFeedbackGenerator(style: .light)
                    generator.impactOccurred()
                    onTabSelected?(item.tabId)
                }) {                    VStack(spacing: 2) {
                        ZStack(alignment: .topTrailing) {
                            Image(systemName: safeSystemIconName(baseName: item.iconName, isSelected: isSelected))
                                .font(.system(size: 15, weight: isSelected ? .bold : .regular))
                                .foregroundColor(isSelected ? .white : Color.white.opacity(0.55))
                                .scaleEffect(isSelected ? 1.08 : 1.0)
                            
                            if let badge = item.badgeCount, badge > 0 {
                                Text(badge > 99 ? "99+" : "\(badge)")
                                    .font(.system(size: 8, weight: .bold))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 3)
                                    .padding(.vertical, 1)
                                    .background(Color.red)
                                    .clipShape(Capsule())
                                    .offset(x: 8, y: -4)
                            }
                        }
                        
                        Text(item.label)
                            .font(.system(size: 9.5, weight: isSelected ? .black : .medium))
                            .foregroundColor(isSelected ? .white : Color.white.opacity(0.6))
                    }
                    .padding(.vertical, 5)
                    .padding(.horizontal, 4)
                    .frame(maxWidth: .infinity)
                    .background(
                        ZStack {
                            if isSelected {
                                RoundedRectangle(cornerRadius: 13, style: .continuous)
                                    .fill(
                                        LinearGradient(
                                            colors: [Color.primaryRed, Color(red: 220/255, green: 38/255, blue: 38/255)],
                                            startPoint: .topLeading,
                                            endPoint: .bottomTrailing
                                        )
                                    )
                                    .matchedGeometryEffect(id: "activeTabPill", in: animationNamespace)
                                    .shadow(color: Color.primaryRed.opacity(0.45), radius: 6, x: 0, y: 2)
                            }
                        }
                    )
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 4)
        .background(
            ZStack {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .fill(Color(red: 15/255, green: 23/255, blue: 42/255).opacity(0.94))
                
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .stroke(
                        LinearGradient(
                            colors: [.white.opacity(0.25), .white.opacity(0.05), .white.opacity(0.12)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            }
        )
        .shadow(color: Color.black.opacity(0.3), radius: 16, x: 0, y: 8)
        .padding(.horizontal, 16)
        .padding(.bottom, 8)
    }
}

// --- Standardized Navigation Views ---

struct AnimatedGradientBorder: View {
    @State private var rotateAngle: Double = 0.0
    
    var body: some View {
        RoundedRectangle(cornerRadius: 24)
            .stroke(
                AngularGradient(
                    gradient: Gradient(colors: [.red, .purple, .blue, .green, .yellow, .red]),
                    center: .center,
                    startAngle: .degrees(rotateAngle),
                    endAngle: .degrees(rotateAngle + 360)
                ),
                lineWidth: 1.5
            )
            .onAppear {
                withAnimation(Animation.linear(duration: 4.0).repeatForever(autoreverses: false)) {
                    rotateAngle = 360.0
                }
            }
    }
}

struct RightRoundedSidebarShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.minX, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX - 24, y: rect.minY))
        path.addArc(
            center: CGPoint(x: rect.maxX - 24, y: rect.minY + 24),
            radius: 24,
            startAngle: Angle(degrees: 270),
            endAngle: Angle(degrees: 0),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - 24))
        path.addArc(
            center: CGPoint(x: rect.maxX - 24, y: rect.maxY - 24),
            radius: 24,
            startAngle: Angle(degrees: 0),
            endAngle: Angle(degrees: 90),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
    }
}

// 1:1 Android-Parity Customer Sidebar
struct BMSCustomerSidebar: View {
    let userName: String
    let companyName: String
    let profilePhoto: String?
    let activeOrdersCount: Int
    @Binding var activeTab: String
    let onLogout: () -> Void
    let onClose: () -> Void
    
    @State private var isBookkeepingExpanded = false
    @Environment(\.openURL) private var openURL
    
    private struct NavItem {
        let id: String
        let label: String
        let icon: String
        let badge: String?
        let hasSubItems: Bool
    }
    
    private struct NavGroup {
        let title: String
        let items: [NavItem]
    }
    
    private var navGroups: [NavGroup] {
        [
            NavGroup(
                title: "Main Workspace",
                items: [
                    NavItem(id: "Home", label: "Overview", icon: "square.grid.2x2.fill", badge: nil, hasSubItems: false),
                    NavItem(id: "Services", label: "Service Catalog", icon: "briefcase.fill", badge: nil, hasSubItems: false),
                    NavItem(id: "Orders", label: "Orders & Projects", icon: "bag.fill", badge: activeOrdersCount > 0 ? "\(activeOrdersCount)" : nil, hasSubItems: false),
                    NavItem(id: "Referrals", label: "Refer & Earn", icon: "gift.fill", badge: "₹500", hasSubItems: false),
                    NavItem(id: "Invoices", label: "Billing & Invoices", icon: "doc.text.fill", badge: nil, hasSubItems: false)
                ]
            ),
            NavGroup(
                title: "Compliance & Tools",
                items: [
                    NavItem(id: "Vault", label: "Document Vault", icon: "folder.fill", badge: nil, hasSubItems: false),
                    NavItem(id: "Bookkeeping", label: "Bookkeeping & AaaS", icon: "book.fill", badge: nil, hasSubItems: true)
                ]
            ),
            NavGroup(
                title: "Help & Settings",
                items: [
                    NavItem(id: "Support", label: "Support & Tickets", icon: "headphones", badge: nil, hasSubItems: false),
                    NavItem(id: "Account", label: "Account Settings", icon: "person.fill", badge: nil, hasSubItems: false)
                ]
            )
        ]
    }
    
    private let bookkeepingSubItems = [
        ("Executive Dashboard", "square.grid.2x2"),
        ("Sales Invoices", "doc.plaintext"),
        ("Purchase Bills", "cart.fill"),
        ("Income & Expenses", "chart.line.downtrend.xyaxis"),
        ("Bank Statements", "building.columns.fill"),
        ("Customers & Vendors", "building.2.fill"),
        ("Payroll & Timesheets", "person.3.fill"),
        ("Reports & P&L", "chart.bar.fill")
    ]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            
            // 1. Sidebar Brand Header (Pure White Header matching Android)
            HStack {
                VRLogoView(height: 28)
                    .onTapGesture {
                        activeTab = "Home"
                        onClose()
                    }
                
                Spacer()
                
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(Color(red: 30/255, green: 41/255, blue: 59/255))
                        .frame(width: 30, height: 30)
                        .background(Color(red: 238/255, green: 242/255, blue: 246/255))
                        .clipShape(Circle())
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.horizontal, 18)
            .padding(.top, 50)
            .padding(.bottom, 14)
            .background(Color.white)
            
            Divider()
                .background(Color(red: 241/255, green: 245/255, blue: 249/255))
            
            // 2. Navigation Groups
            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 20) {
                    ForEach(navGroups, id: \.title) { group in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(group.title.uppercased())
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                .tracking(1.2)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 4)
                            
                            ForEach(group.items, id: \.id) { item in
                                let isActive = activeTab == item.id
                                
                                if item.hasSubItems {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Button(action: {
                                            if isActive {
                                                withAnimation(.spring(response: 0.35, dampingFraction: 0.75)) {
                                                    isBookkeepingExpanded.toggle()
                                                }
                                            } else {
                                                activeTab = item.id
                                                withAnimation(.spring(response: 0.35, dampingFraction: 0.75)) {
                                                    isBookkeepingExpanded = true
                                                }
                                            }
                                        }) {
                                            HStack {
                                                HStack(spacing: 14) {
                                                    Image(systemName: item.icon)
                                                        .font(.system(size: 18, weight: .semibold))
                                                        .foregroundColor(isActive ? .white : Color(red: 148/255, green: 163/255, blue: 184/255))
                                                        .frame(width: 24)
                                                    
                                                    Text(item.label)
                                                        .font(.system(size: 14, weight: isActive ? .bold : .medium))
                                                        .foregroundColor(isActive ? .white : Color(red: 226/255, green: 232/255, blue: 240/255))
                                                }
                                                
                                                Spacer()
                                                
                                                Image(systemName: isBookkeepingExpanded ? "chevron.down" : "chevron.right")
                                                    .font(.system(size: 12, weight: .bold))
                                                    .foregroundColor(isActive ? .white : Color(red: 148/255, green: 163/255, blue: 184/255))
                                            }
                                            .padding(.horizontal, 14)
                                            .padding(.vertical, 12)
                                            .background(isActive ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color.clear)
                                            .cornerRadius(12)
                                        }
                                        .buttonStyle(PlainButtonStyle())
                                        
                                        if isBookkeepingExpanded {
                                            VStack(alignment: .leading, spacing: 3) {
                                                ForEach(bookkeepingSubItems, id: \.0) { subLabel, subIcon in
                                                    Button(action: {
                                                        activeTab = "Bookkeeping"
                                                        onClose()
                                                    }) {
                                                        HStack(spacing: 10) {
                                                            Image(systemName: subIcon)
                                                                .font(.system(size: 14))
                                                                .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                                                .frame(width: 18)
                                                            
                                                            Text(subLabel)
                                                                .font(.system(size: 12.5, weight: .medium))
                                                                .foregroundColor(Color(red: 203/255, green: 213/255, blue: 225/255))
                                                        }
                                                        .padding(.horizontal, 12)
                                                        .padding(.vertical, 8)
                                                        .frame(maxWidth: .infinity, alignment: .leading)
                                                    }
                                                    .buttonStyle(PlainButtonStyle())
                                                }
                                            }
                                            .padding(.leading, 24)
                                            .padding(.vertical, 6)
                                            .background(Color.white.opacity(0.04))
                                            .cornerRadius(10)
                                            .overlay(
                                                RoundedRectangle(cornerRadius: 10)
                                                    .stroke(Color.white.opacity(0.08), lineWidth: 1)
                                            )
                                        }
                                    }
                                } else {
                                    Button(action: {
                                        activeTab = item.id
                                        onClose()
                                    }) {
                                        HStack {
                                            HStack(spacing: 14) {
                                                Image(systemName: item.icon)
                                                    .font(.system(size: 18, weight: .semibold))
                                                    .foregroundColor(isActive ? .white : Color(red: 148/255, green: 163/255, blue: 184/255))
                                                    .frame(width: 24)
                                                
                                                Text(item.label)
                                                    .font(.system(size: 14, weight: isActive ? .bold : .medium))
                                                    .foregroundColor(isActive ? .white : Color(red: 226/255, green: 232/255, blue: 240/255))
                                            }
                                            
                                            Spacer()
                                            
                                            if let b = item.badge {
                                                Text(b)
                                                    .font(.system(size: 10, weight: .black))
                                                    .foregroundColor(isActive ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color(red: 15/255, green: 23/255, blue: 42/255))
                                                    .padding(.horizontal, 7)
                                                    .padding(.vertical, 3)
                                                    .background(isActive ? Color.white : Color(red: 245/255, green: 158/255, blue: 11/255))
                                                    .clipShape(Capsule())
                                            }
                                        }
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 12)
                                        .background(isActive ? Color(red: 220/255, green: 38/255, blue: 38/255) : Color.clear)
                                        .cornerRadius(12)
                                    }
                                    .buttonStyle(PlainButtonStyle())
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 18)
            }
            
            Divider()
                .background(Color.white.opacity(0.10))
            
            // 3. Quick Direct Helpline & User Footer matching Android
            VStack(spacing: 14) {
                // Direct Helpline Box
                Button(action: {
                    if let url = URL(string: "tel:918008530606") {
                        openURL(url)
                    }
                }) {
                    HStack {
                        HStack(spacing: 12) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.2))
                                    .frame(width: 36, height: 36)
                                Image(systemName: "phone.fill")
                                    .font(.system(size: 15))
                                    .foregroundColor(Color(red: 129/255, green: 140/255, blue: 248/255))
                            }
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Direct Helpline")
                                    .font(.system(size: 12, weight: .bold))
                                    .foregroundColor(.white)
                                Text("+91 80085 30606")
                                    .font(.system(size: 10.5, weight: .medium))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                            }
                        }
                        
                        Spacer()
                        
                        ZStack {
                            Circle()
                                .fill(Color(red: 99/255, green: 102/255, blue: 241/255))
                                .frame(width: 30, height: 30)
                            Image(systemName: "phone.fill")
                                .font(.system(size: 13))
                                .foregroundColor(.white)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .background(Color(red: 30/255, green: 41/255, blue: 59/255))
                    .cornerRadius(14)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(Color.white.opacity(0.08), lineWidth: 1)
                    )
                }
                .buttonStyle(PlainButtonStyle())
                
                // User Info & Sign Out Row
                HStack {
                    Button(action: {
                        activeTab = "Account"
                        onClose()
                    }) {
                        HStack(spacing: 12) {
                            VRAvatarView(
                                photoUrl: profilePhoto,
                                name: userName.isEmpty ? "Customer" : userName,
                                size: 38
                            )
                            .overlay(Circle().stroke(Color.white.opacity(0.3), lineWidth: 1))
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(userName.isEmpty ? "Customer" : userName)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.white)
                                    .lineLimit(1)
                                Text(companyName.isEmpty ? "Verified Customer" : companyName)
                                    .font(.system(size: 10.5, weight: .medium))
                                    .foregroundColor(Color(red: 148/255, green: 163/255, blue: 184/255))
                                    .lineLimit(1)
                            }
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                    
                    Spacer()
                    
                    Button(action: {
                        onClose()
                        onLogout()
                    }) {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(Color(red: 255/255, green: 128/255, blue: 128/255))
                            .frame(width: 36, height: 36)
                            .background(Color(red: 220/255, green: 38/255, blue: 38/255).opacity(0.18))
                            .cornerRadius(10)
                    }
                    .buttonStyle(PlainButtonStyle())
                }
            }
            .padding(16)
            .background(Color(red: 11/255, green: 17/255, blue: 32/255))
        }
        .frame(width: 320)
        .background(Color(red: 2/255, green: 6/255, blue: 23/255))
        .clipShape(RightRoundedSidebarShape())
        .shadow(color: Color.black.opacity(0.35), radius: 25, x: 8, y: 0)
        .edgesIgnoringSafeArea(.all)
    }
}

struct BMSAppSidebar: View {
    let userName: String
    let roleName: String
    let menuItems: [BMSSidebarItem]
    @Binding var activeTab: String
    let onLogout: () -> Void
    let onClose: () -> Void
    
    var body: some View {
        let initials = userName.components(separatedBy: " ")
            .compactMap { $0.first }
            .map { String($0).uppercased() }
            .prefix(2)
            .joined()
            
        VStack(alignment: .leading, spacing: 0) {
            // Header with Brand Logo & Close Button (1:1 Web Header)
            HStack(alignment: .center) {
                HStack(spacing: 8) {
                    Image("logo")
                        .renderingMode(.original)
                        .resizable()
                        .scaledToFit()
                        .frame(height: 28)
                    
                    VStack(alignment: .leading, spacing: 1) {
                        Text("VR Here")
                            .font(.system(size: 15, weight: .black))
                            .foregroundColor(.white)
                        Text("ADMIN STUDIO")
                            .font(.system(size: 8, weight: .black))
                            .foregroundColor(.cyan)
                            .tracking(1)
                    }
                }
                
                Spacer()
                
                Button(action: onClose) {
                    Image(systemName: "xmark")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white.opacity(0.85))
                        .frame(width: 32, height: 32)
                        .background(Color.white.opacity(0.12))
                        .clipShape(Circle())
                }
                .buttonStyle(PlainButtonStyle())
            }
            .padding(.horizontal, 20)
            .padding(.top, 55)
            .padding(.bottom, 16)
            
            // Profile Card (Integrated Glass Bubble)
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(
                            LinearGradient(
                                colors: [Color.indigo, Color.blue],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                        .frame(width: 42, height: 42)
                        .overlay(Circle().stroke(Color.white.opacity(0.3), lineWidth: 1.5))
                    
                    Text(initials.isEmpty ? userName.prefix(1).uppercased() : initials)
                        .font(.system(size: 14, weight: .black))
                        .foregroundColor(.white)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(userName)
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.white)
                        .lineLimit(1)
                    Text(roleName)
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(Color(red: 160/255, green: 175/255, blue: 200/255))
                }
                Spacer()
            }
            .padding(14)
            .background(Color.white.opacity(0.06))
            .cornerRadius(16)
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.white.opacity(0.08), lineWidth: 1))
            .padding(.horizontal, 18)
            .padding(.bottom, 14)
            
            Divider().background(Color.white.opacity(0.08))
            
            // Navigation List (Fast Instant Touch Feedback)
            ScrollView(showsIndicators: false) {
                VStack(spacing: 6) {
                    ForEach(menuItems) { item in
                        let isSelected = activeTab == item.tabId
                        Button(action: {
                            withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                                activeTab = item.tabId
                            }
                            onClose()
                        }) {
                            HStack(spacing: 14) {
                                Image(systemName: safeSystemIconName(baseName: item.iconName, isSelected: isSelected))
                                    .font(.system(size: 16, weight: isSelected ? .bold : .medium))
                                    .foregroundColor(isSelected ? .white : Color(red: 160/255, green: 175/255, blue: 195/255))
                                    .frame(width: 22)
                                
                                Text(item.label)
                                    .font(.system(size: 13, weight: isSelected ? .black : .medium))
                                    .foregroundColor(isSelected ? .white : Color(red: 200/255, green: 210/255, blue: 225/255))
                                
                                Spacer()
                                
                                if isSelected {
                                    Circle()
                                        .fill(Color.cyan)
                                        .frame(width: 5, height: 5)
                                }
                            }
                            .padding(.horizontal, 14)
                            .frame(height: 44)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                Group {
                                    if isSelected {
                                        LinearGradient(
                                            colors: [Color.indigo, Color.blue],
                                            startPoint: .leading,
                                            endPoint: .trailing
                                        )
                                        .shadow(color: Color.indigo.opacity(0.35), radius: 6, x: 0, y: 2)
                                    } else {
                                        Color.clear
                                    }
                                }
                            )
                            .cornerRadius(12)
                            .contentShape(Rectangle()) // Ensures entire row is instantly tappable
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            
            Divider().background(Color.white.opacity(0.08))
            
            // Logout Action Footer
            Button(action: {
                onClose()
                onLogout()
            }) {
                HStack(spacing: 14) {
                    Image(systemName: "rectangle.portrait.and.arrow.right")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(Color(red: 255/255, green: 100/255, blue: 100/255))
                    Text("Sign Out")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 255/255, green: 100/255, blue: 100/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
                .background(Color.red.opacity(0.12))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.red.opacity(0.25), lineWidth: 1)
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(PlainButtonStyle())
            .padding(.horizontal, 18)
            .padding(.vertical, 16)
            .padding(.bottom, 24)
        }
        .frame(width: 290)
        .background(
            Color(red: 6/255, green: 10/255, blue: 24/255)
        )
        .clipShape(RightRoundedSidebarShape())
        .shadow(color: Color.black.opacity(0.4), radius: 30, x: 12, y: 0)
        .edgesIgnoringSafeArea(.all)
    }
}

// 1:1 Floating Action Button (FAB) matching Web QuickActionFAB
struct BMSQuickActionFAB: View {
    let onNewOrder: () -> Void
    let onNewTodo: () -> Void
    
    @State private var isOpen: Bool = false
    
    var body: some View {
        VStack(alignment: .trailing, spacing: 14) {
            if isOpen {
                VStack(alignment: .trailing, spacing: 12) {
                    // New Order Action
                    Button(action: {
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.8)) {
                            isOpen = false
                        }
                        onNewOrder()
                    }) {
                        HStack(spacing: 10) {
                            Text("New Order")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Color.black.opacity(0.8))
                                .cornerRadius(8)
                                .shadow(color: Color.black.opacity(0.15), radius: 4)
                            
                            ZStack {
                                Circle()
                                    .fill(Color(red: 0.06, green: 0.72, blue: 0.51))
                                    .frame(width: 44, height: 44)
                                    .shadow(color: Color.green.opacity(0.35), radius: 6, x: 0, y: 3)
                                Image(systemName: "bag.badge.plus")
                                    .font(.system(size: 17, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    
                    // New Task Action
                    Button(action: {
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.8)) {
                            isOpen = false
                        }
                        onNewTodo()
                    }) {
                        HStack(spacing: 10) {
                            Text("New Task")
                                .font(.system(size: 11, weight: .black))
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Color.black.opacity(0.8))
                                .cornerRadius(8)
                                .shadow(color: Color.black.opacity(0.15), radius: 4)
                            
                            ZStack {
                                Circle()
                                    .fill(Color(red: 0.23, green: 0.51, blue: 0.96))
                                    .frame(width: 44, height: 44)
                                    .shadow(color: Color.blue.opacity(0.35), radius: 6, x: 0, y: 3)
                                Image(systemName: "checkmark.square.fill")
                                    .font(.system(size: 17, weight: .bold))
                                    .foregroundColor(.white)
                            }
                        }
                    }
                    .buttonStyle(PlainButtonStyle())
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            
            // Main Toggle Button
            Button(action: {
                withAnimation(.spring(response: 0.32, dampingFraction: 0.72)) {
                    isOpen.toggle()
                }
            }) {
                ZStack {
                    Circle()
                        .fill(isOpen ? Color(red: 0.15, green: 0.20, blue: 0.30) : Color.indigo)
                        .frame(width: 56, height: 56)
                        .shadow(color: Color.indigo.opacity(0.4), radius: 10, x: 0, y: 4)
                    
                    Image(systemName: "plus")
                        .font(.system(size: 24, weight: .black))
                        .foregroundColor(.white)
                        .rotationEffect(.degrees(isOpen ? 45 : 0))
                }
            }
            .buttonStyle(PlainButtonStyle())
        }
        .padding(.trailing, 20)
        .padding(.bottom, 80)
    }
}

extension Int {
    func formattedWithSeparator() -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return formatter.string(from: NSNumber(value: self)) ?? "\(self)"
    }
}

extension Double {
    func formattedWithSeparator() -> String {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 2
        return formatter.string(from: NSNumber(value: self)) ?? "\(self)"
    }
}
