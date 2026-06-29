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
            "slider.horizontal.3",
            "arrow.triangle.2.circlepath",
            "signature",
            "doc.text"
        ]
        
        if nonFillableSymbols.contains(baseName) || baseName.hasSuffix(".fill") {
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

// Polished Horizontal Brand Logo Component
struct VRLogoView: View {
    var body: some View {
        HStack(spacing: 8) {
            Image("logo")
                .resizable()
                .scaledToFit()
                .frame(height: 26)
            
            // Vertical Divider line with a red dot centered on it
            ZStack {
                Rectangle()
                    .fill(Color.textMuted.opacity(0.4))
                    .frame(width: 1, height: 24)
                
                Circle()
                    .fill(Color.primaryRed)
                    .frame(width: 4.5, height: 4.5)
            }
            .frame(width: 6)
            
            VStack(alignment: .leading, spacing: 0) {
                // "Here" with its red underline
                VStack(alignment: .leading, spacing: 1) {
                    Text("Here")
                        .font(.custom("Georgia", size: 14).bold())
                        .foregroundColor(Color.primaryRed)
                    
                    Rectangle()
                        .fill(Color.primaryRed)
                        .frame(height: 1)
                }
                .fixedSize()
                
                Spacer(minLength: 1)
                
                // "Business Management Solutions" subtitle
                Text("Business Management Solutions")
                    .font(.system(size: 6.5, weight: .bold))
                    .foregroundColor(Color.textDark.opacity(0.85))
            }
            .frame(height: 26)
        }
    }
}

// Custom Header Style
struct VRHeader: View {
    let title: String
    var showMenu: Bool = false
    var onMenuClick: (() -> Void)? = nil
    var showLogout: Bool = false
    var onLogoutClick: (() -> Void)? = nil
    
    var showBack: Bool = false
    var onBackClick: (() -> Void)? = nil
    var showNotifications: Bool = false
    var hasUnreadNotifications: Bool = false
    var onNotificationsClick: (() -> Void)? = nil
    
    var body: some View {
        VStack(spacing: 0) {
            ZStack {
                // Logo in center
                VRLogoView()
                
                HStack {
                    // Left side buttons
                    HStack(spacing: 4) {
                        if showMenu {
                            Button(action: { onMenuClick?() }) {
                                Image(systemName: "line.horizontal.3")
                                    .font(.title3)
                                    .foregroundColor(.textMuted)
                                    .padding(8)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        
                        if showBack {
                            Button(action: { onBackClick?() }) {
                                Image(systemName: "chevron.left")
                                    .font(.title3)
                                    .foregroundColor(.textMuted)
                                    .padding(8)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                    
                    Spacer()
                    
                    // Right side buttons
                    HStack(spacing: 4) {
                        if showNotifications {
                            Button(action: { onNotificationsClick?() }) {
                                ZStack(alignment: .topTrailing) {
                                    Image(systemName: "bell")
                                        .font(.title3)
                                        .foregroundColor(.textMuted)
                                        .padding(8)
                                    
                                    if hasUnreadNotifications {
                                        Circle()
                                            .fill(Color.red)
                                            .frame(width: 8, height: 8)
                                            .offset(x: 4, y: -4)
                                    }
                                }
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                        
                        if showLogout {
                            Button(action: { onLogoutClick?() }) {
                                Image(systemName: "rectangle.portrait.and.arrow.right")
                                    .font(.title3)
                                    .foregroundColor(.red)
                                    .padding(8)
                            }
                            .buttonStyle(ScaleOnPressButtonStyle())
                        }
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color.white)
            
            Divider()
                .background(Color.borderLight)
        }
    }
}

// --- Beautiful Reusable Notifications Sheet ---
struct NotificationsSheet: View {
    let notifications: [NotificationResponse]
    let onMarkAsRead: (String) -> Void
    let onClose: () -> Void
    
    var body: some View {
        VStack(spacing: 0) {
            // Header bar
            HStack {
                Text("Notifications")
                    .font(.system(size: 18, weight: .black))
                    .foregroundColor(.textDark)
                
                Spacer()
                
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
    let id = UUID()
    let label: String
    let iconName: String
    let tabId: String
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
        path.addLine(to: CGPoint(x: rect.maxX - 48, y: rect.minY))
        path.addArc(
            center: CGPoint(x: rect.maxX - 48, y: rect.minY + 48),
            radius: 48,
            startAngle: Angle(degrees: 270),
            endAngle: Angle(degrees: 0),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - 48))
        path.addArc(
            center: CGPoint(x: rect.maxX - 48, y: rect.maxY - 48),
            radius: 48,
            startAngle: Angle(degrees: 0),
            endAngle: Angle(degrees: 90),
            clockwise: false
        )
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
        path.closeSubpath()
        return path
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
            // Close Button header
            HStack {
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
            .padding(.horizontal, 24)
            .padding(.top, 55)
            .padding(.bottom, 12)
            
            // 2. Profile Details Section (Integrated Glass bubble)
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(LinearGradient(gradient: Gradient(colors: [Color(red: 99/255, green: 102/255, blue: 241/255), Color(red: 139/255, green: 92/255, blue: 246/255)]), startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 46, height: 46)
                        .overlay(Circle().stroke(Color.white.opacity(0.35), lineWidth: 1.5))
                    
                    Text(initials.isEmpty ? userName.prefix(1).uppercased() : initials)
                        .font(.system(size: 15, weight: .black))
                        .foregroundColor(.white)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(userName)
                        .font(.system(size: 15, weight: .bold))
                        .foregroundColor(.white)
                        .lineLimit(1)
                    Text(roleName)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(Color(red: 180/255, green: 190/255, blue: 210/255))
                }
                Spacer()
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(18)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(Color.white.opacity(0.08), lineWidth: 1))
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
            
            Divider().background(Color.white.opacity(0.08))
            
            // 3. Navigation List
            ScrollView(showsIndicators: false) {
                VStack(spacing: 8) {
                    ForEach(menuItems) { item in
                        let isSelected = activeTab == item.tabId
                        Button(action: {
                            withAnimation(.spring(response: 0.35, dampingFraction: 0.7)) {
                                activeTab = item.tabId
                            }
                            onClose()
                        }) {
                            HStack(spacing: 16) {
                                Image(systemName: safeSystemIconName(baseName: item.iconName, isSelected: isSelected))
                                    .font(.system(size: 16))
                                    .foregroundColor(isSelected ? Color(red: 129/255, green: 140/255, blue: 248/255) : Color(red: 160/255, green: 175/255, blue: 195/255))
                                    .frame(width: 24)
                                Text(item.label)
                                    .font(.system(size: 13, weight: isSelected ? .bold : .medium))
                                    .foregroundColor(isSelected ? .white : Color(red: 180/255, green: 190/255, blue: 210/255))
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 16)
                            .frame(height: 44)
                            .background(isSelected ? Color(red: 99/255, green: 102/255, blue: 241/255).opacity(0.20) : Color.clear)
                            .cornerRadius(12)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(isSelected ? Color.white.opacity(0.12) : Color.clear, lineWidth: 1)
                            )
                        }
                        .buttonStyle(PlainButtonStyle())
                    }
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
            }
            
            Divider().background(Color.white.opacity(0.08))
            
            // 4. Logout Action Footer
            Button(action: {
                onClose()
                onLogout()
            }) {
                HStack(spacing: 16) {
                    Image(systemName: "rectangle.portrait.and.arrow.right")
                        .font(.system(size: 18))
                        .foregroundColor(Color(red: 255/255, green: 100/255, blue: 100/255))
                    Text("Sign Out")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(Color(red: 255/255, green: 100/255, blue: 100/255))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .background(Color.red.opacity(0.10))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color.red.opacity(0.20), lineWidth: 1)
                )
            }
            .buttonStyle(PlainButtonStyle())
            .padding(.horizontal, 20)
            .padding(.bottom, 40)
        }
        .frame(width: 290)
        .background(
            ZStack {
                // Blur material layer
                Rectangle()
                    .fill(.ultraThinMaterial)
                
                // Color refraction tint layer (liquid-like soft gradients)
                LinearGradient(colors: [Color.darkSlate.opacity(0.55), Color(red: 10/255, green: 15/255, blue: 30/255).opacity(0.75)], startPoint: .top, endPoint: .bottom)
                
                // Refractive gradient highlights
                LinearGradient(colors: [.white.opacity(0.03), .purple.opacity(0.05), .blue.opacity(0.05), .clear], startPoint: .topLeading, endPoint: .bottomTrailing)
                
                // Specular reflection diagonal stripe
                LinearGradient(colors: [.clear, .white.opacity(0.06), .clear], startPoint: .topLeading, endPoint: .bottomTrailing)
                
                // Glow at top leading corner
                RadialGradient(colors: [.white.opacity(0.12), .clear], center: .topLeading, startRadius: 0, endRadius: 300)
            }
        )
        .clipShape(RightRoundedSidebarShape())
        .overlay(
            RightRoundedSidebarShape()
                .stroke(LinearGradient(colors: [.white.opacity(0.35), .white.opacity(0.08), .white.opacity(0.15), .white.opacity(0.28)], startPoint: .topLeading, endPoint: .bottomTrailing), lineWidth: 1.5)
        )
        .shadow(color: Color.black.opacity(0.3), radius: 25, x: 10, y: 0)
        .edgesIgnoringSafeArea(.all)
    }
}

struct BMSAppFloatingDock: View {
    @Binding var activeTab: String
    let dockItems: [BMSDockItem]
    var onTabSelected: ((String) -> Void)? = nil
    
    var body: some View {
        HStack(spacing: 0) {
            ForEach(dockItems) { item in
                let isSelected = activeTab == item.tabId
                
                Button(action: {
                    activeTab = item.tabId
                    onTabSelected?(item.tabId)
                }) {
                    VStack(spacing: 4) {
                        Image(systemName: safeSystemIconName(baseName: item.iconName, isSelected: isSelected))
                            .font(.system(size: 16))
                            .foregroundColor(isSelected ? .white : .textMuted)
                        
                        Text(item.label)
                            .font(.system(size: 9, weight: isSelected ? .black : .semibold))
                            .foregroundColor(isSelected ? .white : .textMuted)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 10)
        .background(Color.darkSlate)
        .cornerRadius(24)
        .overlay(
            AnimatedGradientBorder()
        )
        .shadow(color: Color.black.opacity(0.15), radius: 10, x: 0, y: 5)
        .padding(.horizontal, 16)
        .padding(.bottom, 10)
    }
}
