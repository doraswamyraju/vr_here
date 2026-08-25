import SwiftUI
import AudioToolbox

struct IncomingWorkRequestSheet: View {
    let order: OrderResponse
    let onAccept: () -> Void
    let onDecline: () -> Void
    
    @State private var pulseScale: CGFloat = 1.0
    
    var body: some View {
        ZStack {
            Color.slate900.ignoresSafeArea()
            
            VStack(spacing: 24) {
                Spacer()
                
                // Pulsing Incoming Call Badge
                ZStack {
                    Circle()
                        .fill(Color.emerald500.opacity(0.2))
                        .frame(width: 110, height: 110)
                        .scaleEffect(pulseScale)
                        .animation(Animation.easeInOut(duration: 1.2).repeatForever(autoreverses: true), value: pulseScale)
                    
                    Circle()
                        .fill(Color.emerald500)
                        .frame(width: 80, height: 80)
                        .shadow(color: Color.emerald500.opacity(0.6), radius: 15, x: 0, y: 5)
                    
                    Image(systemName: "bell.badge.fill")
                        .font(.system(size: 32, weight: .bold))
                        .foregroundColor(.white)
                }
                
                VStack(spacing: 8) {
                    Text("⚡ INCOMING WORK BROADCAST")
                        .font(.system(size: 11, weight: .black))
                        .tracking(2)
                        .foregroundColor(.emerald400)
                    
                    Text("First to Accept Gets Assigned!")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white.opacity(0.7))
                }
                
                // Project Details Card
                VStack(spacing: 16) {
                    VStack(spacing: 4) {
                        Text("PAYOUT AMOUNT")
                            .font(.system(size: 10, weight: .black))
                            .tracking(1.5)
                            .foregroundColor(.slate400)
                        
                        let payout = Int(order.freelancerPayout ?? 0)
                        Text("₹\(payout)")
                            .font(.system(size: 38, weight: .black))
                            .foregroundColor(.emerald400)
                    }
                    
                    Divider().background(Color.white.opacity(0.1))
                    
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("SERVICE")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.slate400)
                            Spacer()
                            Text(order.category?.uppercased() ?? "GENERAL")
                                .font(.system(size: 9, weight: .black))
                                .foregroundColor(.indigo400)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 3)
                                .background(Color.indigo500.opacity(0.15))
                                .cornerRadius(6)
                        }
                        
                        Text(order.serviceName)
                            .font(.system(size: 16, weight: .black))
                            .foregroundColor(.white)
                        
                        if !order.packageName.isEmpty {
                            Text(order.packageName)
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(.white.opacity(0.7))
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(24)
                .background(Color.white.opacity(0.06))
                .cornerRadius(24)
                .overlay(
                    RoundedRectangle(cornerRadius: 24)
                        .stroke(Color.white.opacity(0.1), lineWidth: 1)
                )
                .padding(.horizontal, 24)
                
                Spacer()
                
                // Action Buttons
                VStack(spacing: 12) {
                    Button(action: {
                        onAccept()
                    }) {
                        HStack(spacing: 10) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 20))
                            Text("ACCEPT & CLAIM WORK NOW")
                                .font(.system(size: 14, weight: .black))
                        }
                        .foregroundColor(.slate900)
                        .frame(maxWidth: .infinity)
                        .frame(height: 56)
                        .background(Color.emerald400)
                        .cornerRadius(18)
                        .shadow(color: Color.emerald500.opacity(0.4), radius: 12, x: 0, y: 6)
                    }
                    .buttonStyle(ScaleOnPressButtonStyle())
                    
                    Button(action: {
                        onDecline()
                    }) {
                        Text("Decline / Dismiss")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.slate400)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 24)
            }
        }
        .onAppear {
            pulseScale = 1.25
            // Play incoming call sound & vibration alert
            AudioServicesPlaySystemSound(1005)
            AudioServicesPlaySystemSound(kSystemSoundID_Vibrate)
        }
    }
}
