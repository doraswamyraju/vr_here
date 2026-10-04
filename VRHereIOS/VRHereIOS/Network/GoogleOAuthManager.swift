import Foundation
import UIKit
import AuthenticationServices
import Combine

@MainActor
final class GoogleOAuthManager: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    static let shared = GoogleOAuthManager()
    
    // iOS Client ID from GoogleService-Info.plist
    private let clientId = "674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1.apps.googleusercontent.com"
    private let redirectUri = "com.googleusercontent.apps.674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1:/oauth2redirect"
    private let customScheme = "com.googleusercontent.apps.674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1"
    
    func startGoogleSignIn(completion: @escaping (Result<(idToken: String?, accessToken: String?), Error>) -> Void) {
        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid email profile"),
            URLQueryItem(name: "prompt", value: "select_account")
        ]
        
        guard let authURL = components.url else {
            completion(.failure(NSError(domain: "VRHereAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid auth URL"])))
            return
        }
        
        let session = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: customScheme
        ) { [weak self] callbackURL, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let callbackURL = callbackURL else {
                completion(.failure(NSError(domain: "VRHereAuth", code: -2, userInfo: [NSLocalizedDescriptionKey: "Callback URL not found"])))
                return
            }
            
            guard let urlComponents = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
                  let code = urlComponents.queryItems?.first(where: { $0.name == "code" })?.value else {
                completion(.failure(NSError(domain: "VRHereAuth", code: -3, userInfo: [NSLocalizedDescriptionKey: "Authorization code not found in callback"])))
                return
            }
            
            // Exchange code with Google token endpoint
            Task {
                await self?.exchangeCodeForTokens(code: code, completion: completion)
            }
        }
        
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        session.start()
    }
    
    private func exchangeCodeForTokens(code: String, completion: @escaping (Result<(idToken: String?, accessToken: String?), Error>) -> Void) async {
        guard let tokenURL = URL(string: "https://oauth2.googleapis.com/token") else {
            completion(.failure(NSError(domain: "VRHereAuth", code: -4, userInfo: [NSLocalizedDescriptionKey: "Invalid token endpoint URL"])))
            return
        }
        
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let params = [
            "client_id": clientId,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirectUri
        ]
        
        let bodyString = params.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }.joined(separator: "&")
        request.httpBody = bodyString.data(using: .utf8)
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                let errString = String(data: data, encoding: .utf8) ?? "Unknown token error"
                completion(.failure(NSError(domain: "VRHereAuth", code: -5, userInfo: [NSLocalizedDescriptionKey: "Google token exchange failed: \(errString)"])))
                return
            }
            
            if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let idToken = json["id_token"] as? String
                let accessToken = json["access_token"] as? String
                completion(.success((idToken: idToken, accessToken: accessToken)))
            } else {
                completion(.failure(NSError(domain: "VRHereAuth", code: -6, userInfo: [NSLocalizedDescriptionKey: "Failed to parse Google token response"])))
            }
        } catch {
            completion(.failure(error))
        }
    }
    
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first(where: { $0.isKeyWindow }) else {
            return ASPresentationAnchor()
        }
        return window
    }
}
