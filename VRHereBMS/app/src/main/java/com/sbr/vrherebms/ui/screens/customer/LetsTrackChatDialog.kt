package com.sbr.vrherebms.ui.screens.customer

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.socket.client.IO
import io.socket.client.Socket
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

data class LetsTrackMessage(
    val id: String = UUID.randomUUID().toString(),
    val senderName: String,
    val senderType: String, // "Visitor" | "Agent" | "System"
    val text: String,
    val timestamp: String = SimpleDateFormat("hh:mm a", Locale.getDefault()).format(Date())
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LetsTrackChatDialog(
    isOpen: Boolean,
    customerName: String = "",
    customerEmail: String = "",
    onClose: () -> Unit
) {
    if (!isOpen) return

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var inputText by remember { mutableStateOf("") }
    var isAgentTyping by remember { mutableStateOf(false) }
    var isSocketConnected by remember { mutableStateOf(false) }

    val displayName = customerName.ifBlank { "Valued Customer" }

    // Persistent visitor UUID
    val sharedPrefs = remember { context.getSharedPreferences("letstrack_prefs", Context.MODE_PRIVATE) }
    val visitorId = remember {
        var id = sharedPrefs.getString("visitor_uuid", null)
        if (id.isNullOrBlank()) {
            id = "v_" + UUID.randomUUID().toString().replace("-", "").take(18)
            sharedPrefs.edit().putString("visitor_uuid", id).apply()
        }
        id
    }

    val messages = remember {
        mutableStateListOf(
            LetsTrackMessage(
                senderName = "VR HERE Assistant",
                senderType = "System",
                text = "Welcome to VR HERE Live Support! How can we assist you today, $displayName?"
            )
        )
    }

    val quickPrompts = remember {
        listOf(
            "📋 Track My Filing Status",
            "📑 Download Tax Invoice",
            "💼 MSME / GST Query",
            "📞 Speak with an Expert"
        )
    }

    var socketRef by remember { mutableStateOf<Socket?>(null) }

    // Real Socket.io connection to LetsTrack Live Support Engine
    DisposableEffect(key1 = isOpen) {
        var socket: Socket? = null
        try {
            val options = IO.Options.builder()
                .setTransports(arrayOf("websocket", "polling"))
                .setReconnection(true)
                .setReconnectionAttempts(10)
                .setReconnectionDelay(1000)
                .build()

            socket = IO.socket("https://livechat.vrhere.in/visitor", options)
            socketRef = socket

            socket.on(Socket.EVENT_CONNECT) {
                scope.launch { isSocketConnected = true }
                // Send visitor initial handshake to LetsTrack Server
                val initData = JSONObject().apply {
                    put("apiKey", "lt_6a9347d5410be8335e42db43949caf95")
                    put("visitorId", visitorId)
                    put("currentUrl", "/customer/app")
                    put("referrer", "VRHere Android App")
                    put("name", displayName)
                    put("email", customerEmail)
                    put("browser", "VRHere App")
                    put("os", "Android")
                    put("deviceType", "Mobile")
                }
                socket?.emit("visitor-init", initData)
            }

            socket.on(Socket.EVENT_DISCONNECT) {
                scope.launch { isSocketConnected = false }
            }

            socket.on(Socket.EVENT_CONNECT_ERROR) {
                scope.launch { isSocketConnected = false }
            }

            socket.on("visitor-init-success") {
                scope.launch { isSocketConnected = true }
            }

            // Real-time Chat History from LetsTrack
            socket.on("chat-history") { args ->
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    val data = args[0] as JSONObject
                    val msgs = data.optJSONArray("messages")
                    if (msgs != null && msgs.length() > 0) {
                        scope.launch {
                            for (i in 0 until msgs.length()) {
                                val item = msgs.optJSONObject(i) ?: continue
                                val text = item.optString("text", "")
                                if (text.isNotBlank()) {
                                    val senderType = item.optString("senderType", "Agent")
                                    val senderName = item.optString("senderName", if (senderType == "Visitor") displayName else "Support Officer")
                                    val msgId = item.optString("_id", UUID.randomUUID().toString())
                                    if (messages.none { it.id == msgId }) {
                                        messages.add(
                                            LetsTrackMessage(
                                                id = msgId,
                                                senderName = senderName,
                                                senderType = senderType,
                                                text = text
                                            )
                                        )
                                    }
                                }
                            }
                            delay(50)
                            if (messages.isNotEmpty()) {
                                listState.animateScrollToItem(messages.size - 1)
                            }
                        }
                    }
                }
            }

            // Real-time Incoming Message from LetsTrack Agent
            socket.on("msg-received") { args ->
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    val data = args[0] as JSONObject
                    val text = data.optString("text", "")
                    if (text.isNotBlank()) {
                        val senderType = data.optString("senderType", "Agent")
                        val senderName = data.optString("senderName", "Support Officer")
                        val msgId = data.optString("_id", UUID.randomUUID().toString())

                        scope.launch {
                            isAgentTyping = false
                            if (messages.none { it.id == msgId }) {
                                messages.add(
                                    LetsTrackMessage(
                                        id = msgId,
                                        senderName = senderName,
                                        senderType = senderType,
                                        text = text
                                    )
                                )
                                delay(50)
                                listState.animateScrollToItem(messages.size - 1)
                            }
                        }
                    }
                }
            }

            // Live Agent Typing Indicator
            socket.on("agent-typing") { args ->
                if (args.isNotEmpty() && args[0] is JSONObject) {
                    val data = args[0] as JSONObject
                    val isTyping = data.optBoolean("isTyping", false)
                    scope.launch {
                        isAgentTyping = isTyping
                        if (isTyping && messages.isNotEmpty()) {
                            listState.animateScrollToItem(messages.size - 1)
                        }
                    }
                }
            }

            socket.connect()
        } catch (e: Exception) {
            e.printStackTrace()
        }

        onDispose {
            try {
                socket?.disconnect()
                socket?.off()
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    fun sendMessage(text: String) {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return

        val newMsg = LetsTrackMessage(
            senderName = displayName,
            senderType = "Visitor",
            text = trimmed
        )
        messages.add(newMsg)
        inputText = ""

        // Emit to real LetsTrack backend
        try {
            socketRef?.let { s ->
                val payload = JSONObject().apply {
                    put("text", trimmed)
                }
                s.emit("visitor-msg", payload)
                s.emit("visitor-typing", JSONObject().apply { put("isTyping", false) })
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        scope.launch {
            delay(50)
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = true,
            dismissOnClickOutside = true,
            decorFitsSystemWindows = false
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.55f))
                .clickable(
                    indication = null,
                    interactionSource = remember { MutableInteractionSource() }
                ) {
                    onClose()
                }
                .statusBarsPadding()
                .navigationBarsPadding()
                .imePadding(),
            contentAlignment = Alignment.BottomCenter
        ) {
            // Main Floating Chat Card with padding and bounded size
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 6.dp)
                    .heightIn(min = 380.dp, max = 560.dp)
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        // Keep open when clicking inside card
                    },
                shape = RoundedCornerShape(20.dp),
                color = Color.White,
                shadowElevation = 16.dp
            ) {
                Column(
                    modifier = Modifier.fillMaxSize()
                ) {
                    // Header Bar with VR HERE Crimson-to-Navy Gradient
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                Brush.linearGradient(
                                    listOf(Color(0xFFDC2626), Color(0xFF312E81))
                                )
                            )
                            .padding(horizontal = 16.dp, vertical = 12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "VR HERE Live Support",
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(7.dp)
                                            .background(
                                                if (isSocketConnected) Color(0xFF10B981) else Color(0xFFF59E0B),
                                                CircleShape
                                            )
                                            .shadow(3.dp, CircleShape)
                                    )
                                    Text(
                                        text = if (isSocketConnected) "Online • Connected to LetsTrack" else "Connecting...",
                                        fontSize = 10.5.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White.copy(alpha = 0.9f)
                                    )
                                }
                            }

                            // Dismiss Close Button
                            Surface(
                                modifier = Modifier
                                    .size(30.dp)
                                    .clickable { onClose() },
                                shape = CircleShape,
                                color = Color.White.copy(alpha = 0.2f)
                            ) {
                                Box(
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Close,
                                        contentDescription = "Close Chat",
                                        tint = Color.White,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }
                        }
                    }

                    // Message Thread Area
                    LazyColumn(
                        state = listState,
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .background(Color(0xFFF8FAFC))
                            .padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        items(messages, key = { it.id }) { msg ->
                            val isVisitor = msg.senderType == "Visitor"
                            val isSystem = msg.senderType == "System"

                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = if (isVisitor) Alignment.End else Alignment.Start
                            ) {
                                if (!isVisitor) {
                                    Text(
                                        text = msg.senderName,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color(0xFF64748B),
                                        modifier = Modifier.padding(start = 6.dp, bottom = 2.dp)
                                    )
                                }

                                Surface(
                                    shape = RoundedCornerShape(
                                        topStart = 16.dp,
                                        topEnd = 16.dp,
                                        bottomStart = if (isVisitor) 16.dp else 4.dp,
                                        bottomEnd = if (isVisitor) 4.dp else 16.dp
                                    ),
                                    color = when {
                                        isVisitor -> Color(0xFFDC2626)
                                        isSystem -> Color(0xFFFEF3C7)
                                        else -> Color(0xFFE2E8F0)
                                    },
                                    shadowElevation = if (isVisitor) 2.dp else 0.dp
                                ) {
                                    Column(
                                        modifier = Modifier.padding(horizontal = 13.dp, vertical = 9.dp)
                                    ) {
                                        Text(
                                            text = msg.text,
                                            fontSize = 13.sp,
                                            lineHeight = 18.sp,
                                            color = when {
                                                isVisitor -> Color.White
                                                isSystem -> Color(0xFF92400E)
                                                else -> Color(0xFF0F172A)
                                            }
                                        )
                                        Spacer(modifier = Modifier.height(2.dp))
                                        Text(
                                            text = msg.timestamp,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Medium,
                                            color = when {
                                                isVisitor -> Color.White.copy(alpha = 0.75f)
                                                isSystem -> Color(0xFFB45309).copy(alpha = 0.8f)
                                                else -> Color(0xFF64748B)
                                            },
                                            modifier = Modifier.align(Alignment.End)
                                        )
                                    }
                                }
                            }
                        }

                        // Agent Typing Indicator
                        if (isAgentTyping) {
                            item {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    modifier = Modifier
                                        .background(Color(0xFFE2E8F0), RoundedCornerShape(12.dp))
                                        .padding(horizontal = 12.dp, vertical = 8.dp)
                                ) {
                                    val infiniteTransition = rememberInfiniteTransition(label = "typing")
                                    val dot1Alpha by infiniteTransition.animateFloat(
                                        initialValue = 0.3f,
                                        targetValue = 1f,
                                        animationSpec = infiniteRepeatable(
                                            animation = tween(600, easing = LinearEasing),
                                            repeatMode = RepeatMode.Reverse
                                        ),
                                        label = "dot1"
                                    )
                                    val dot2Alpha by infiniteTransition.animateFloat(
                                        initialValue = 0.3f,
                                        targetValue = 1f,
                                        animationSpec = infiniteRepeatable(
                                            animation = tween(600, delayMillis = 200, easing = LinearEasing),
                                            repeatMode = RepeatMode.Reverse
                                        ),
                                        label = "dot2"
                                    )
                                    val dot3Alpha by infiniteTransition.animateFloat(
                                        initialValue = 0.3f,
                                        targetValue = 1f,
                                        animationSpec = infiniteRepeatable(
                                            animation = tween(600, delayMillis = 400, easing = LinearEasing),
                                            repeatMode = RepeatMode.Reverse
                                        ),
                                        label = "dot3"
                                    )

                                    Box(modifier = Modifier.size(5.dp).background(Color(0xFF64748B).copy(alpha = dot1Alpha), CircleShape))
                                    Box(modifier = Modifier.size(5.dp).background(Color(0xFF64748B).copy(alpha = dot2Alpha), CircleShape))
                                    Box(modifier = Modifier.size(5.dp).background(Color(0xFF64748B).copy(alpha = dot3Alpha), CircleShape))
                                }
                            }
                        }
                    }

                    // Quick Suggestion Chips Row
                    LazyRow(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color.White)
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(quickPrompts) { prompt ->
                            Surface(
                                shape = RoundedCornerShape(14.dp),
                                color = Color(0xFFF1F5F9),
                                border = BorderStroke(1.dp, Color(0xFFCBD5E1)),
                                modifier = Modifier.clickable { sendMessage(prompt) }
                            ) {
                                Text(
                                    text = prompt,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color(0xFF334155),
                                    modifier = Modifier.padding(horizontal = 9.dp, vertical = 5.dp)
                                )
                            }
                        }
                    }

                    // Input Bar
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        color = Color.White,
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = inputText,
                                onValueChange = {
                                    inputText = it
                                    // Send typing indicator to LetsTrack
                                    try {
                                        socketRef?.emit("visitor-typing", JSONObject().apply { put("isTyping", it.isNotEmpty()) })
                                    } catch (e: Exception) {}
                                },
                                placeholder = { Text("Type your message...", fontSize = 13.sp, color = Color(0xFF94A3B8)) },
                                modifier = Modifier.weight(1f),
                                shape = RoundedCornerShape(24.dp),
                                colors = OutlinedTextFieldDefaults.colors(
                                    unfocusedBorderColor = Color(0xFFCBD5E1),
                                    focusedBorderColor = Color(0xFFDC2626),
                                    focusedContainerColor = Color.White,
                                    unfocusedContainerColor = Color(0xFFF8FAFC)
                                ),
                                singleLine = true,
                                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                                keyboardActions = KeyboardActions(onSend = { sendMessage(inputText) })
                            )

                            // Send Button
                            Surface(
                                modifier = Modifier
                                    .size(40.dp)
                                    .clickable { sendMessage(inputText) },
                                shape = CircleShape,
                                color = Color(0xFFDC2626),
                                shadowElevation = 3.dp
                            ) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .background(
                                            Brush.linearGradient(
                                                listOf(Color(0xFFDC2626), Color(0xFFE11D48))
                                            )
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.AutoMirrored.Filled.Send,
                                        contentDescription = "Send Message",
                                        tint = Color.White,
                                        modifier = Modifier.size(17.dp)
                                    )
                                }
                            }
                        }
                    }

                    // LetsTrack Branding Footer
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color(0xFFF1F5F9))
                            .padding(vertical = 4.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "⚡ Powered by LetsTrack™",
                            fontSize = 9.5.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFF64748B)
                        )
                    }
                }
            }
        }
    }
}
