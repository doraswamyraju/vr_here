import SwiftUI
import UserNotifications

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

// --- App Entry Point ---
@main
struct VRHereIOSApp: App {
    @StateObject private var authViewModel = AuthViewModel()
    @StateObject private var customerViewModel = CustomerDashboardViewModel()
    @StateObject private var employeeViewModel = EmployeeDashboardViewModel()
    @StateObject private var partnerViewModel = PartnerDashboardViewModel()
    @StateObject private var adminViewModel = AdminDashboardViewModel()
    @StateObject private var freelancerViewModel = FreelancerDashboardViewModel()
    
    @State private var isShowingRegister = false
    
    #if os(iOS)
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate
    #elseif os(macOS)
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    #endif
    
    var body: some Scene {
        WindowGroup {
            NavigationView {
                Group {
                    if authViewModel.isUserLoggedIn() {
                        let role = authViewModel.getUserRole()
                        switch role {
                        case "admin":
                            AdminDashboardView(
                                authViewModel: authViewModel,
                                adminViewModel: adminViewModel,
                                userName: authViewModel.getUserName(),
                                onLogout: { authViewModel.logout() }
                            )
                        case "employee":
                            EmployeeDashboardView(
                                viewModel: employeeViewModel,
                                userName: authViewModel.getUserName(),
                                onLogout: { authViewModel.logout() }
                            )
                        case "partner":
                            PartnerDashboardView(
                                viewModel: partnerViewModel,
                                userName: authViewModel.getUserName(),
                                onLogout: { authViewModel.logout() },
                                onDeleteAccount: { authViewModel.deleteAccount() }
                            )
                        case "freelancer":
                            FreelancerDashboardView(
                                viewModel: freelancerViewModel,
                                userName: authViewModel.getUserName(),
                                onLogout: { authViewModel.logout() },
                                onDeleteAccount: { authViewModel.deleteAccount() }
                            )
                        default:
                            CustomerDashboardView(
                                viewModel: customerViewModel,
                                userName: authViewModel.getUserName(),
                                onLogout: { authViewModel.logout() },
                                onDeleteAccount: { authViewModel.deleteAccount() }
                            )
                        }
                    } else {
                        if isShowingRegister {
                            RegisterView(viewModel: authViewModel, onNavigateToLogin: {
                                isShowingRegister = false
                            }, onRegistrationSuccess: {
                                isShowingRegister = false
                            })
                        } else {
                            LoginView(viewModel: authViewModel, onNavigateToRegister: {
                                isShowingRegister = true
                            }, onLoginSuccess: { role in
                                // Auth transition happens reactively via authState published changes
                            })
                        }
                    }
                }
                #if os(iOS)
                .navigationBarHidden(true)
                #endif
            }
            #if os(iOS)
            .navigationViewStyle(StackNavigationViewStyle())
            #endif
            .onAppear {
                registerForPushNotifications()
            }
        }
    }
    
    // Request push notification permissions on boot
    private func registerForPushNotifications() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            guard granted else { return }
            #if os(iOS)
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
            #elseif os(macOS)
            DispatchQueue.main.async {
                NSApplication.shared.registerForRemoteNotifications()
            }
            #endif
        }
    }
}

// --- Push Notification Delegates & Stubs ---
#if os(iOS)
class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }
    
    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let tokenString = deviceToken.map { String(format: "%02x", $0) }.joined()
        print("Valid APNs Device Token: \(tokenString)")
        SessionManager.shared.saveFcmToken(tokenString)
        
        if SessionManager.shared.isLoggedIn() {
            Task {
                _ = try? await NetworkManager.shared.updateFcmToken(token: tokenString)
            }
        }
    }
    
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([[.banner, .sound, .badge]])
    }
}
#elseif os(macOS)
class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
    }
    
    func application(_ application: NSApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let tokenString = deviceToken.map { String(format: "%02.x", $0) }.joined()
        print("Device Token: \(tokenString)")
        SessionManager.shared.saveFcmToken(tokenString)
        
        if SessionManager.shared.isLoggedIn() {
            Task {
                _ = try? await NetworkManager.shared.updateFcmToken(token: tokenString)
            }
        }
    }
    
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([[.banner, .sound, .badge]])
    }
}
#endif
