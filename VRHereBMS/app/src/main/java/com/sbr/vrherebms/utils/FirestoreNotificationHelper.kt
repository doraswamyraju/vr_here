package com.sbr.vrherebms.utils

import android.content.Context
import android.util.Log
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.ListenerRegistration
import com.google.firebase.firestore.Query
import com.sbr.vrherebms.data.local.SessionManager
import com.sbr.vrherebms.data.model.NotificationResponse

object FirestoreNotificationHelper {
    private var listenerRegistration: ListenerRegistration? = null

    fun startListening(
        context: Context,
        onNotificationsUpdated: (List<NotificationResponse>) -> Unit
    ) {
        val sessionManager = SessionManager(context)
        val userId = sessionManager.getUserId() ?: return
        val cachedToken = sessionManager.getFirebaseCustomToken() ?: return

        val auth = FirebaseAuth.getInstance()
        if (auth.currentUser == null) {
            if (!cachedToken.startsWith("mock-")) {
                auth.signInWithCustomToken(cachedToken)
                    .addOnCompleteListener { task ->
                        if (task.isSuccessful) {
                            Log.d("FirestoreNotifHelper", "Signed in to Firebase, subscribing to listener")
                            subscribeToFirestore(userId, onNotificationsUpdated)
                        } else {
                            Log.e("FirestoreNotifHelper", "Firebase sign-in failed", task.exception)
                        }
                    }
            } else {
                Log.w("FirestoreNotifHelper", "Mock Firebase token detected, cannot subscribe in real-time.")
            }
        } else {
            subscribeToFirestore(userId, onNotificationsUpdated)
        }
    }

    private fun subscribeToFirestore(
        userId: String,
        onNotificationsUpdated: (List<NotificationResponse>) -> Unit
    ) {
        stopListening()

        val db = FirebaseFirestore.getInstance()
        listenerRegistration = db.collection("users")
            .document(userId)
            .collection("notifications")
            .orderBy("createdAt", Query.Direction.DESCENDING)
            .addSnapshotListener { snapshot, e ->
                if (e != null) {
                    Log.w("FirestoreNotifHelper", "Listen failed.", e)
                    return@addSnapshotListener
                }

                if (snapshot != null) {
                    val list = mutableListOf<NotificationResponse>()
                    for (doc in snapshot) {
                        try {
                            val id = doc.id
                            val title = doc.getString("title") ?: ""
                            val message = doc.getString("message") ?: ""
                            val type = doc.getString("type") ?: "System"
                            val isRead = doc.getBoolean("isRead") ?: false
                            
                            list.add(NotificationResponse(
                                id = id,
                                user = userId,
                                title = title,
                                message = message,
                                type = type,
                                isRead = isRead
                            ))
                        } catch (ex: Exception) {
                            Log.e("FirestoreNotifHelper", "Error parsing doc", ex)
                        }
                    }
                    onNotificationsUpdated(list)
                }
            }
    }

    fun markAsRead(context: Context, notificationId: String) {
        val sessionManager = SessionManager(context)
        val userId = sessionManager.getUserId() ?: return
        val db = FirebaseFirestore.getInstance()
        
        db.collection("users")
            .document(userId)
            .collection("notifications")
            .document(notificationId)
            .update("isRead", true)
            .addOnSuccessListener {
                Log.d("FirestoreNotifHelper", "Document $notificationId successfully marked as read")
            }
            .addOnFailureListener { e ->
                Log.w("FirestoreNotifHelper", "Error updating document", e)
            }
    }

    fun stopListening() {
        listenerRegistration?.remove()
        listenerRegistration = null
    }
}
