import Foundation
import UIKit
import AuthenticationServices
import Combine

@MainActor
final class GoogleOAuthManager: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    static let shared = GoogleOAuthManager()
    
    private let clientId = "674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1.apps.googleusercontent.com"
    private let redirectUri = "com.googleusercontent.apps.674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1:/oauth2redirect"
    private let customScheme = "com.googleusercontent.apps.674627570227-0hds8k55egipj5g6tai0kqrvm8cse9v1"
    
    func startGoogleSignIn(completion: @escaping (Result<(idToken: String?, code: String?), Error>) -> Void) {
        let nonce = UUID().uuidString
        var components = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "id_token code"),
            URLQueryItem(name: "scope", value: "openid email profile"),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "prompt", value: "select_account")
        ]
        
        guard let authURL = components.url else {
            completion(.failure(NSError(domain: "VRHereAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid auth URL"])))
            return
        }
        
        let session = ASWebAuthenticationSession(
            url: authURL,
            callbackURLScheme: customScheme
        ) { callbackURL, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let callbackURL = callbackURL else {
                completion(.failure(NSError(domain: "VRHereAuth", code: -2, userInfo: [NSLocalizedDescriptionKey: "Callback URL not found"])))
                return
            }
            
            var extractedIdToken: String? = nil
            var extractedCode: String? = nil
            
            // Extract from Query Items
            if let urlComponents = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
               let items = urlComponents.queryItems {
                extractedCode = items.first(where: { $0.name == "code" })?.value
                extractedIdToken = items.first(where: { $0.name == "id_token" })?.value
            }
            
            // Extract from Fragment / Hash (Google Implicit Response: #id_token=...&code=...)
            if let fragment = callbackURL.fragment {
                let fragmentItems = fragment.components(separatedBy: "&")
                for item in fragmentItems {
                    let parts = item.components(separatedBy: "=")
                    if parts.count == 2 {
                        let key = parts[0]
                        let val = parts[1]
                        if key == "id_token" {
                            extractedIdToken = val
                        } else if key == "code" {
                            extractedCode = val
                        }
                    }
                }
            }
            
            if extractedIdToken != nil || extractedCode != nil {
                completion(.success((idToken: extractedIdToken, code: extractedCode)))
            } else {
                completion(.failure(NSError(domain: "VRHereAuth", code: -3, userInfo: [NSLocalizedDescriptionKey: "Google token or authorization code not found in response"])))
            }
        }
        
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        session.start()
    }
    
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first(where: { $0.isKeyWindow }) else {
            return ASPresentationAnchor()
        }
        return window
    }
}
