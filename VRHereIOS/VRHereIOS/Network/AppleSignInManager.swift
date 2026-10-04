import Foundation
import UIKit
import AuthenticationServices
import Combine

struct AppleUserFullName: Codable {
    let givenName: String?
    let familyName: String?
}

struct AppleSignInResult {
    let identityToken: String?
    let userIdentifier: String
    let email: String?
    let fullName: AppleUserFullName?
}

@MainActor
final class AppleSignInManager: NSObject, ObservableObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    static let shared = AppleSignInManager()
    
    private var completion: ((Result<AppleSignInResult, Error>) -> Void)?
    
    func startAppleSignIn(completion: @escaping (Result<AppleSignInResult, Error>) -> Void) {
        self.completion = completion
        
        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        request.requestedScopes = [.fullName, .email]
        
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }
    
    // MARK: - ASAuthorizationControllerDelegate
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if let appleIDCredential = authorization.credential as? ASAuthorizationAppleIDCredential {
            let userIdentifier = appleIDCredential.user
            let identityTokenData = appleIDCredential.identityToken
            let identityToken = identityTokenData.flatMap { String(data: $0, encoding: .utf8) }
            let email = appleIDCredential.email
            
            var fullNameObj: AppleUserFullName? = nil
            if let fullName = appleIDCredential.fullName {
                fullNameObj = AppleUserFullName(
                    givenName: fullName.givenName,
                    familyName: fullName.familyName
                )
            }
            
            let result = AppleSignInResult(
                identityToken: identityToken,
                userIdentifier: userIdentifier,
                email: email,
                fullName: fullNameObj
            )
            
            completion?(.success(result))
            completion = nil
        } else {
            completion?(.failure(NSError(domain: "AppleAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid Apple credential format"])))
            completion = nil
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        completion?(.failure(error))
        completion = nil
    }
    
    // MARK: - ASAuthorizationControllerPresentationContextProviding
    
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first(where: { $0.isKeyWindow }) else {
            return ASPresentationAnchor()
        }
        return window
    }
}
