package com.sbr.vrherebms.ui.components

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.data.model.OrderChatMessage
import com.sbr.vrherebms.data.remote.VRHereAPI
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.FileOutputStream

@Composable
fun OrderChatComponent(
    orderId: String,
    currentUserRole: String, // "admin", "employee", "freelancer", "client"
    currentUserId: String,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var selectedChannel by remember { mutableStateOf("client") } // "client" or "internal"
    var messageText by remember { mutableStateOf("") }
    var messages by remember { mutableStateOf<List<OrderChatMessage>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var isSending by remember { mutableStateOf(false) }
    var selectedFileUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf<String?>(null) }

    val listState = rememberLazyListState()

    // Function to load messages
    fun loadMessages(silent: Boolean = false) {
        if (!silent) isLoading = true
        coroutineScope.launch {
            try {
                val res = api.getOrderMessages(orderId, selectedChannel)
                if (res.isSuccessful) {
                    messages = res.body() ?: emptyList()
                    if (messages.isNotEmpty()) {
                        listState.animateScrollToItem(messages.size - 1)
                    }
                }
            } catch (e: Exception) {
                // Ignore silent network glitches
            } finally {
                isLoading = false
            }
        }
    }

    // Auto refresh timer
    LaunchedEffect(orderId, selectedChannel) {
        loadMessages()
        while (isActive) {
            delay(4000)
            loadMessages(silent = true)
        }
    }

    // File picker launcher
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            selectedFileUri = uri
            selectedFileName = uri.lastPathSegment?.substringAfterLast('/') ?: "Attachment"
        }
    }

    // Function to send message
    fun sendMessage() {
        val trimmed = messageText.trim()
        if (trimmed.isEmpty() && selectedFileUri == null) return

        isSending = true
        coroutineScope.launch {
            try {
                val textBody = trimmed.toRequestBody("text/plain".toMediaTypeOrNull())
                val channelBody = selectedChannel.toRequestBody("text/plain".toMediaTypeOrNull())

                var filePart: MultipartBody.Part? = null
                selectedFileUri?.let { uri ->
                    try {
                        val inputStream = context.contentResolver.openInputStream(uri)
                        val tempFile = File.createTempFile("upload_", "_chat", context.cacheDir)
                        val outputStream = FileOutputStream(tempFile)
                        inputStream?.copyTo(outputStream)
                        inputStream?.close()
                        outputStream.close()

                        val reqFile = tempFile.asRequestBody(
                            (context.contentResolver.getType(uri) ?: "application/octet-stream").toMediaTypeOrNull()
                        )
                        filePart = MultipartBody.Part.createFormData("file", tempFile.name, reqFile)
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }

                val response = api.sendOrderMessage(
                    orderId = orderId,
                    message = textBody,
                    messageType = channelBody,
                    file = filePart
                )

                if (response.isSuccessful) {
                    messageText = ""
                    selectedFileUri = null
                    selectedFileName = null
                    loadMessages(silent = true)
                } else {
                    Toast.makeText(context, "Failed to send message", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(context, "Network error: ${e.localizedMessage}", Toast.LENGTH_SHORT).show()
            } finally {
                isSending = false
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .height(550.dp)
            .background(Color.White, RoundedCornerShape(16.dp))
            .border(1.dp, Color(0xFFE2E8F0), RoundedCornerShape(16.dp))
            .padding(12.dp)
    ) {
        // Channel Selector (Dual-Channel support: Client vs Staff Internal)
        if (currentUserRole != "client") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFF1F5F9), RoundedCornerShape(12.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                val isClientSelected = selectedChannel == "client"
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isClientSelected) Color(0xFF4F46E5) else Color.Transparent,
                    modifier = Modifier
                        .weight(1f)
                        .clickable {
                            selectedChannel = "client"
                        }
                ) {
                    Row(
                        modifier = Modifier.padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Chat,
                            contentDescription = null,
                            tint = if (isClientSelected) Color.White else Color(0xFF64748B),
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Client Channel",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isClientSelected) Color.White else Color(0xFF64748B)
                        )
                    }
                }

                val isInternalSelected = selectedChannel == "internal"
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = if (isInternalSelected) Color(0xFFF59E0B) else Color.Transparent,
                    modifier = Modifier
                        .weight(1f)
                        .clickable {
                            selectedChannel = "internal"
                        }
                ) {
                    Row(
                        modifier = Modifier.padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Lock,
                            contentDescription = null,
                            tint = if (isInternalSelected) Color.White else Color(0xFF64748B),
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Internal Staff Only",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isInternalSelected) Color.White else Color(0xFF64748B)
                        )
                    }
                }
            }
            Spacer(modifier = Modifier.height(10.dp))
        }

        // Channel Banner
        val channelBannerText = if (selectedChannel == "client") {
            "Messages in this channel are visible to the Client and the assigned Service Team."
        } else {
            "🔒 Internal Staff Chat: Visible strictly to Admins, PM, Makers, and Checkers."
        }
        val channelBannerBg = if (selectedChannel == "client") Color(0xFFEEF2FF) else Color(0xFFFEF3C7)
        val channelBannerFg = if (selectedChannel == "client") Color(0xFF4338CA) else Color(0xFF92400E)

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(channelBannerBg, RoundedCornerShape(8.dp))
                .padding(horizontal = 10.dp, vertical = 6.dp)
        ) {
            Text(channelBannerText, fontSize = 10.sp, color = channelBannerFg, fontWeight = FontWeight.Medium)
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Message List Stream
        if (isLoading && messages.isEmpty()) {
            Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp, color = Color(0xFF4F46E5))
            }
        } else if (messages.isEmpty()) {
            Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(Icons.Default.Forum, contentDescription = null, tint = Color(0xFFCBD5E1), modifier = Modifier.size(40.dp))
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("No messages yet in this channel.", fontSize = 12.sp, color = Color(0xFF94A3B8))
                    Text("Start the conversation below.", fontSize = 10.sp, color = Color(0xFFCBD5E1))
                }
            }
        } else {
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(messages) { msg ->
                    val senderId = msg.sender?.id ?: ""
                    val isMe = senderId == currentUserId || (currentUserRole == "admin" && msg.sender?.role == "admin" && senderId.isNotEmpty())
                    val senderRole = msg.sender?.role ?: "user"
                    val senderName = msg.sender?.name ?: "Staff"

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = if (isMe) Arrangement.End else Arrangement.Start
                    ) {
                        Column(
                            horizontalAlignment = if (isMe) Alignment.End else Alignment.Start,
                            modifier = Modifier.widthIn(max = 280.dp)
                        ) {
                            // Sender Name & Role Pill
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                Text(
                                    text = if (isMe) "You" else senderName,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF64748B)
                                )
                                Box(
                                    modifier = Modifier
                                        .background(
                                            when (senderRole.lowercase()) {
                                                "admin" -> Color(0xFFDC2626)
                                                "client" -> Color(0xFF059669)
                                                else -> Color(0xFF4F46E5)
                                            },
                                            RoundedCornerShape(4.dp)
                                        )
                                        .padding(horizontal = 4.dp, vertical = 1.dp)
                                ) {
                                    Text(
                                        text = senderRole.uppercase(),
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Black,
                                        color = Color.White
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(2.dp))

                            // Bubble
                            Surface(
                                shape = RoundedCornerShape(
                                    topStart = 14.dp,
                                    topEnd = 14.dp,
                                    bottomStart = if (isMe) 14.dp else 2.dp,
                                    bottomEnd = if (isMe) 2.dp else 14.dp
                                ),
                                color = if (isMe) {
                                    if (selectedChannel == "internal") Color(0xFFF59E0B) else Color(0xFF4F46E5)
                                } else {
                                    Color(0xFFF1F5F9)
                                },
                                tonalElevation = 1.dp
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    if (msg.message.isNotEmpty()) {
                                        Text(
                                            text = msg.message,
                                            fontSize = 12.sp,
                                            color = if (isMe) Color.White else Color(0xFF1E293B)
                                        )
                                    }

                                    // Attachments
                                    msg.safeAttachments.forEach { att ->
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Row(
                                            modifier = Modifier
                                                .background(
                                                    if (isMe) Color.White.copy(alpha = 0.2f) else Color.White,
                                                    RoundedCornerShape(6.dp)
                                                )
                                                .clickable {
                                                    try {
                                                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(att.url))
                                                        context.startActivity(intent)
                                                    } catch (e: Exception) {
                                                        Toast.makeText(context, "Cannot open file URL", Toast.LENGTH_SHORT).show()
                                                    }
                                                }
                                                .padding(horizontal = 6.dp, vertical = 4.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                Icons.Default.AttachFile,
                                                contentDescription = null,
                                                tint = if (isMe) Color.White else Color(0xFF4F46E5),
                                                modifier = Modifier.size(12.dp)
                                            )
                                            Spacer(modifier = Modifier.width(4.dp))
                                            Text(
                                                text = att.name.ifEmpty { "Attachment" },
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = if (isMe) Color.White else Color(0xFF4F46E5),
                                                maxLines = 1
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(2.dp))
                                    val timeStr = if (msg.createdAt.length >= 16) {
                                        msg.createdAt.substring(11, 16)
                                    } else "Just now"
                                    Text(
                                        text = timeStr,
                                        fontSize = 8.sp,
                                        color = if (isMe) Color.White.copy(alpha = 0.7f) else Color(0xFF94A3B8),
                                        modifier = Modifier.align(Alignment.End)
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Selected File Indicator
        selectedFileName?.let { fname ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFFF1F5F9), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.AttachFile, contentDescription = null, tint = Color(0xFF4F46E5), modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(fname, fontSize = 10.sp, fontWeight = FontWeight.Bold, color = Color(0xFF1E293B), maxLines = 1)
                }
                IconButton(
                    onClick = {
                        selectedFileUri = null
                        selectedFileName = null
                    },
                    modifier = Modifier.size(20.dp)
                ) {
                    Icon(Icons.Default.Close, contentDescription = "Remove", tint = Color(0xFFEF4444), modifier = Modifier.size(14.dp))
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
        }

        // Input Field Strip
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            IconButton(
                onClick = { filePickerLauncher.launch("*/*") },
                modifier = Modifier
                    .size(38.dp)
                    .background(Color(0xFFF1F5F9), CircleShape)
            ) {
                Icon(Icons.Default.AttachFile, contentDescription = "Attach File", tint = Color(0xFF64748B), modifier = Modifier.size(18.dp))
            }

            OutlinedTextField(
                value = messageText,
                onValueChange = { messageText = it },
                placeholder = { Text("Type message...", fontSize = 12.sp) },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(20.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF4F46E5),
                    unfocusedBorderColor = Color(0xFFE2E8F0),
                    focusedContainerColor = Color(0xFFF8FAFC),
                    unfocusedContainerColor = Color(0xFFF8FAFC)
                ),
                singleLine = true
            )

            IconButton(
                onClick = { sendMessage() },
                enabled = !isSending && (messageText.trim().isNotEmpty() || selectedFileUri != null),
                modifier = Modifier
                    .size(38.dp)
                    .background(
                        if (messageText.trim().isNotEmpty() || selectedFileUri != null) Color(0xFF4F46E5) else Color(0xFFCBD5E1),
                        CircleShape
                    )
            ) {
                if (isSending) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Color.White, strokeWidth = 2.dp)
                } else {
                    Icon(Icons.Default.Send, contentDescription = "Send", tint = Color.White, modifier = Modifier.size(16.dp))
                }
            }
        }
    }
}
