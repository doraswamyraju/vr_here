import Foundation
import FirebaseAuth
import FirebaseFirestore

class FirebaseNotificationHelper {
    static let shared = FirebaseNotificationHelper()
    
    private var listenerRegistration: ListenerRegistration?
    
    func startListening(onUpdate: @escaping ([NotificationResponse]) -> Void) {
        guard let userId = SessionManager.shared.getUserId(),
              let customToken = SessionManager.shared.getFirebaseCustomToken() else {
            return
        }
        
        if Auth.auth().currentUser == nil {
            if !customToken.hasPrefix("mock-") {
                Auth.auth().signIn(withCustomToken: customToken) { [weak self] authResult, error in
                    if let error = error {
                        print("Firebase custom token authentication failed: \(error.localizedDescription)")
                        return
                    }
                    print("Signed in to Firebase, subscribing to listener.")
                    self?.subscribeToFirestore(userId: userId, onUpdate: onUpdate)
                }
            } else {
                print("Mock Firebase custom token detected, skipping listener.")
            }
        } else {
            subscribeToFirestore(userId: userId, onUpdate: onUpdate)
        }
    }
    
    private func subscribeToFirestore(userId: String, onUpdate: @escaping ([NotificationResponse]) -> Void) {
        stopListening()
        
        let db = Firestore.firestore()
        listenerRegistration = db.collection("users")
            .document(userId)
            .collection("notifications")
            .order(by: "createdAt", descending: true)
            .addSnapshotListener { querySnapshot, error in
                if let error = error {
                    print("Error listening for notifications: \(error.localizedDescription)")
                    return
                }
                
                guard let documents = querySnapshot?.documents else {
                    return
                }
                
                let list = documents.compactMap { doc -> NotificationResponse? in
                    let idVal = doc.documentID
                    let data = doc.data()
                    let title = data["title"] as? String ?? ""
                    let message = data["message"] as? String ?? ""
                    let type = data["type"] as? String ?? "System"
                    let isRead = data["isRead"] as? Bool ?? false
                    let createdAt = data["createdAt"] as? String ?? ""
                    
                    return NotificationResponse(
                        idVal: idVal,
                        title: title,
                        message: message,
                        type: type,
                        isRead: isRead,
                        createdAt: createdAt
                    )
                }
                onUpdate(list)
            }
    }
    
    func markAsRead(notificationId: String) {
        guard let userId = SessionManager.shared.getUserId() else { return }
        let db = Firestore.firestore()
        db.collection("users")
            .document(userId)
            .collection("notifications")
            .document(notificationId)
            .updateData(["isRead": true]) { error in
                if let error = error {
                    print("Error updating read status: \(error.localizedDescription)")
                }
            }
    }
    
    func stopListening() {
        listenerRegistration?.remove()
        listenerRegistration = nil
    }
}
