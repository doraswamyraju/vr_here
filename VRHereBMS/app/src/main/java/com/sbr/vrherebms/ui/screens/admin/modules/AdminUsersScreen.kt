package com.sbr.vrherebms.ui.screens.admin.modules

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.UserProfile
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminUsersScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedSubTab by remember { mutableStateOf("App Users") }
    var searchQuery by remember { mutableStateOf("") }
    var selectedRoleFilter by remember { mutableStateOf("ALL") }

    // Dialog controllers
    var showAddUserDialog by remember { mutableStateOf(false) }
    var selectedUserForProfile by remember { mutableStateOf<UserProfile?>(null) }
    var selectedUserForEdit by remember { mutableStateOf<UserProfile?>(null) }
    var generatedPasswordLink by remember { mutableStateOf<String?>(null) }

    // Initial load
    LaunchedEffect(Unit) {
        adminViewModel.syncDashboardData(silent = true)
    }

    val roleFilters = listOf("ALL", "customer", "employee", "freelancer", "partner", "admin")

    val filteredUsers = adminViewModel.users.filter { u ->
        val matchesSearch = u.name.contains(searchQuery, ignoreCase = true) ||
                u.email.contains(searchQuery, ignoreCase = true) ||
                (u.phone ?: "").contains(searchQuery)

        val matchesRole = if (selectedRoleFilter == "ALL") true else u.role.equals(selectedRoleFilter, ignoreCase = true)

        matchesSearch && matchesRole
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Subtab Switcher: App Users vs Webmail Accounts
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
                .padding(4.dp)
        ) {
            listOf("App Users", "Webmail Accounts").forEach { tab ->
                val isSelected = selectedSubTab == tab
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .background(if (isSelected) Color.White else Color.Transparent, RoundedCornerShape(10.dp))
                        .clickable { selectedSubTab = tab }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = tab,
                        fontSize = 12.sp,
                        fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                        color = if (isSelected) Color(0xFF4F46E5) else Color(0xFF64748B)
                    )
                }
            }
        }

        if (selectedSubTab == "App Users") {
            // Header Row: Search + Add User button
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    placeholder = { Text("Search users by name, email, or phone...", fontSize = 12.sp) },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B)) },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF4F46E5),
                        unfocusedBorderColor = Color(0xFFE2E8F0),
                        focusedContainerColor = Color.White,
                        unfocusedContainerColor = Color.White
                    ),
                    singleLine = true
                )

                Button(
                    onClick = { showAddUserDialog = true },
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)
                ) {
                    Icon(Icons.Default.PersonAdd, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add User", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }

            // Role Filter Chips Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                roleFilters.forEach { role ->
                    val isSelected = selectedRoleFilter == role
                    Box(
                        modifier = Modifier
                            .background(if (isSelected) Color(0xFF4F46E5) else Color.White, RoundedCornerShape(20.dp))
                            .border(1.dp, if (isSelected) Color(0xFF4F46E5) else Color(0xFFE2E8F0), RoundedCornerShape(20.dp))
                            .clickable { selectedRoleFilter = role }
                            .padding(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = role.uppercase(),
                            color = if (isSelected) Color.White else Color(0xFF64748B),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Black
                        )
                    }
                }
            }

            // Users List
            if (filteredUsers.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.PeopleOutline, contentDescription = null, tint = Color(0xFF94A3B8), modifier = Modifier.size(54.dp))
                        Spacer(modifier = Modifier.height(10.dp))
                        Text("No users found matching current filters.", color = Color(0xFF64748B), fontSize = 13.sp)
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(filteredUsers) { user ->
                        UserCardItem(
                            user = user,
                            onViewProfile = { selectedUserForProfile = user },
                            onEdit = { selectedUserForEdit = user },
                            onGenerateResetLink = {
                                scope.launch {
                                    try {
                                        val res = api.generatePasswordResetLink(mapOf("userId" to user.id))
                                        if (res.isSuccessful && res.body() != null) {
                                            generatedPasswordLink = res.body()!!.link
                                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                            val clip = ClipData.newPlainText("Password Link", res.body()!!.link)
                                            clipboard.setPrimaryClip(clip)
                                            Toast.makeText(context, "Password reset link generated & copied to clipboard!", Toast.LENGTH_LONG).show()
                                        } else {
                                            Toast.makeText(context, "Failed to generate reset link", Toast.LENGTH_SHORT).show()
                                        }
                                    } catch (e: Exception) {
                                        Toast.makeText(context, "Network error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }
                        )
                    }
                }
            }
        } else {
            // Webmail Accounts Tab
            WebmailAccountsView()
        }
    }

    // Modal 1: Add User Dialog
    if (showAddUserDialog) {
        var name by remember { mutableStateOf("") }
        var email by remember { mutableStateOf("") }
        var phone by remember { mutableStateOf("") }
        var password by remember { mutableStateOf("") }
        var role by remember { mutableStateOf("client") }

        AlertDialog(
            onDismissRequest = { showAddUserDialog = false },
            title = { Text("Add New System User", fontWeight = FontWeight.Black) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Full Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = email, onValueChange = { email = it }, label = { Text("Email Address") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = phone, onValueChange = { phone = it }, label = { Text("Phone Number") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Temporary Password") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = {
                Button(onClick = {
                    scope.launch {
                        try {
                            val res = api.createAdminUser(mapOf(
                                "name" to name,
                                "email" to email,
                                "phone" to phone,
                                "password" to password,
                                "role" to role
                            ))
                            if (res.isSuccessful) {
                                Toast.makeText(context, "User created successfully!", Toast.LENGTH_SHORT).show()
                                adminViewModel.syncDashboardData(silent = true)
                                showAddUserDialog = false
                            }
                        } catch (e: Exception) {
                            Toast.makeText(context, "Error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
                        }
                    }
                }) {
                    Text("Create User")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddUserDialog = false }) { Text("Cancel") }
            }
        )
    }

    // Modal 2: View Profile Sheet
    selectedUserForProfile?.let { user ->
        Dialog(onDismissRequest = { selectedUserForProfile = null }) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("User Profile", fontSize = 16.sp, fontWeight = FontWeight.Black)
                        IconButton(onClick = { selectedUserForProfile = null }) {
                            Icon(Icons.Default.Clear, contentDescription = null)
                        }
                    }

                    Text("Name: ${user.name}", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                    Text("Email: ${user.email}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Phone: ${user.phone ?: "No phone recorded"}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("Role: ${user.role.uppercase()}", fontSize = 12.sp, fontWeight = FontWeight.Bold, color = Color(0xFF4F46E5))
                    Text("GSTIN: ${user.gstin ?: "N/A"}", fontSize = 12.sp, color = Color(0xFF64748B))
                    Text("PAN: ${user.panNumber ?: "N/A"}", fontSize = 12.sp, color = Color(0xFF64748B))
                }
            }
        }
    }
}

// MARK: - User Card Item
@Composable
private fun UserCardItem(
    user: UserProfile,
    onViewProfile: () -> Unit,
    onEdit: () -> Unit,
    onGenerateResetLink: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        border = BorderStroke(1.dp, Color(0xFFE2E8F0)),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .background(Color(0xFFEFF6FF), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(user.name.take(1).uppercase(), fontSize = 14.sp, fontWeight = FontWeight.Black, color = Color(0xFF2563EB))
                    }
                    Column {
                        Text(user.name, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text(user.email, fontSize = 11.sp, color = Color(0xFF64748B))
                    }
                }

                Box(
                    modifier = Modifier
                        .background(Color(0xFFEEF2FF), RoundedCornerShape(6.dp))
                        .padding(horizontal = 8.dp, vertical = 3.dp)
                ) {
                    Text(user.role.uppercase(), fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF4F46E5))
                }
            }

            Divider(color = Color(0xFFF1F5F9))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = onViewProfile,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFF1F5F9)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(vertical = 6.dp)
                ) {
                    Text("Profile", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                }

                Button(
                    onClick = onGenerateResetLink,
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.weight(1.5f),
                    contentPadding = PaddingValues(vertical = 6.dp)
                ) {
                    Icon(Icons.Default.LockReset, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("24h Reset Link", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
private fun WebmailAccountsView() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(top = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("ENTERPRISE WEBMAIL DIRECTORY", fontSize = 10.sp, fontWeight = FontWeight.Black, color = Color(0xFF94A3B8))
        
        listOf(
            "admin@vrhere.in" to "1.2 GB / 5.0 GB",
            "support@vrhere.in" to "0.8 GB / 5.0 GB",
            "billing@vrhere.in" to "2.4 GB / 10.0 GB"
        ).forEach { (account, quota) ->
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                border = BorderStroke(1.dp, Color(0xFFE2E8F0))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(account, fontSize = 13.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B))
                        Text("Quota: $quota", fontSize = 10.sp, color = Color(0xFF64748B))
                    }
                    Box(
                        modifier = Modifier
                            .background(Color(0xFFD1FAE5), RoundedCornerShape(6.dp))
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        Text("ACTIVE", fontSize = 9.sp, fontWeight = FontWeight.Black, color = Color(0xFF065F46))
                    }
                }
            }
        }
    }
}
