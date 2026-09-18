package com.sbr.vrherebms.data.local

import android.content.Context
import android.content.SharedPreferences

class SessionManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREF_NAME = "vrhere_session_prefs"
        private const val KEY_AUTH_TOKEN = "auth_token"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_USER_NAME = "user_name"
        private const val KEY_USER_EMAIL = "user_email"
        private const val KEY_USER_ROLE = "user_role"
        private const val KEY_USER_ACTIVE = "user_active"
        private const val KEY_PROFILE_PHOTO = "user_profile_photo"
        private const val KEY_COMPANY_LOGO = "user_company_logo"
        private const val KEY_COMPANY_NAME = "user_company_name"
    }

    fun saveSession(
        token: String,
        userId: String,
        name: String,
        email: String,
        role: String,
        isActive: Boolean,
        profilePhoto: String? = null,
        companyLogo: String? = null,
        companyName: String? = null
    ) {
        prefs.edit().apply {
            putString(KEY_AUTH_TOKEN, token)
            putString(KEY_USER_ID, userId)
            putString(KEY_USER_NAME, name)
            putString(KEY_USER_EMAIL, email)
            putString(KEY_USER_ROLE, role)
            putBoolean(KEY_USER_ACTIVE, isActive)
            putString(KEY_PROFILE_PHOTO, profilePhoto)
            putString(KEY_COMPANY_LOGO, companyLogo)
            putString(KEY_COMPANY_NAME, companyName)
            apply()
        }
    }

    fun saveProfilePhoto(url: String?) {
        prefs.edit().putString(KEY_PROFILE_PHOTO, url).apply()
    }

    fun getProfilePhoto(): String? {
        return prefs.getString(KEY_PROFILE_PHOTO, null)
    }

    fun saveCompanyLogo(url: String?) {
        prefs.edit().putString(KEY_COMPANY_LOGO, url).apply()
    }

    fun getCompanyLogo(): String? {
        return prefs.getString(KEY_COMPANY_LOGO, null)
    }

    fun saveCompanyName(name: String?) {
        prefs.edit().putString(KEY_COMPANY_NAME, name).apply()
    }

    fun getCompanyName(): String? {
        return prefs.getString(KEY_COMPANY_NAME, "")
    }

    fun getAvatarUrl(): String? {
        val photo = getProfilePhoto()
        if (!photo.isNullOrBlank()) return photo
        val logo = getCompanyLogo()
        if (!logo.isNullOrBlank()) return logo
        return null
    }

    fun getAuthToken(): String? {
        return prefs.getString(KEY_AUTH_TOKEN, null)
    }

    fun getUserId(): String? {
        return prefs.getString(KEY_USER_ID, null)
    }

    fun getUserName(): String? {
        return prefs.getString(KEY_USER_NAME, "")
    }

    fun getUserEmail(): String? {
        return prefs.getString(KEY_USER_EMAIL, "")
    }

    fun getUserRole(): String? {
        return prefs.getString(KEY_USER_ROLE, "")
    }

    fun isUserActive(): Boolean {
        return prefs.getBoolean(KEY_USER_ACTIVE, false)
    }

    fun savePhone(phone: String) {
        prefs.edit().putString("user_phone", phone).apply()
    }

    fun getPhone(): String {
        return prefs.getString("user_phone", "") ?: ""
    }

    fun saveFcmToken(token: String) {
        prefs.edit().putString("fcm_token", token).apply()
    }

    fun getFcmToken(): String? {
        return prefs.getString("fcm_token", null)
    }

    fun clearSession() {
        prefs.edit().clear().apply()
    }

    fun isLoggedIn(): Boolean {
        return getAuthToken() != null
    }
}
