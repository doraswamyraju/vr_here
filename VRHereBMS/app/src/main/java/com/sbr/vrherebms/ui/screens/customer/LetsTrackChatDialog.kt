package com.sbr.vrherebms.ui.screens.customer

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
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

    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var inputText by remember { mutableStateOf("") }
    var isAgentTyping by remember { mutableStateOf(false) }

    val displayName = customerName.ifBlank { "Valued Customer" }

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

    fun sendMessage(text: String) {
        val trimmed = text.trim()
        if (trimmed.isBlank()) return

        messages.add(
            LetsTrackMessage(
                senderName = displayName,
                senderType = "Visitor",
                text = trimmed
            )
        )
        inputText = ""

        scope.launch {
            delay(100)
            listState.animateScrollToItem(messages.size - 1)

            // Simulate live agent response
            isAgentTyping = true
            delay(1400)
            isAgentTyping = false

            val replyText = when {
                trimmed.contains("status", ignoreCase = true) || trimmed.contains("track", ignoreCase = true) ->
                    "Your active filings and projects can be tracked in real-time under the 'Orders' tab in your navigation bar."
                trimmed.contains("invoice", ignoreCase = true) || trimmed.contains("tax", ignoreCase = true) ->
                    "You can view, download, and verify all official GST & Proforma Invoices from the 'Invoices' tab."
                trimmed.contains("speak", ignoreCase = true) || trimmed.contains("expert", ignoreCase = true) || trimmed.contains("call", ignoreCase = true) ->
                    "Our compliance experts are available at +91 8008530606. You can also tap the phone icon from the bottom menu to dial directly."
                else ->
                    "Thank you for reaching out! A dedicated VR HERE compliance officer has received your message and will follow up shortly."
            }

            messages.add(
                LetsTrackMessage(
                    senderName = "Live Support Officer",
                    senderType = "Agent",
                    text = replyText
                )
            )
            delay(100)
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            dismissOnBackPress = true,
            dismissOnClickOutside = true
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black.copy(alpha = 0.6f))
                .clickable(
                    indication = null,
                    interactionSource = remember { MutableInteractionSource() }
                ) {
                    onClose()
                }
                .navigationBarsPadding()
                .statusBarsPadding(),
            contentAlignment = Alignment.BottomCenter
        ) {
            // Main Floating Chat Card Container
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .fillMaxHeight(0.82f)
                    .clickable(
                        indication = null,
                        interactionSource = remember { MutableInteractionSource() }
                    ) {
                        // Prevent dismiss when tapping inside chat container
                    },
                shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
                color = Color.White,
                shadowElevation = 16.dp
            ) {
                Column(
                    modifier = Modifier.fillMaxSize()
                ) {
                    // Header Bar with VR HERE Gradient
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(
                                Brush.linearGradient(
                                    listOf(Color(0xFFDC2626), Color(0xFF312E81))
                                )
                            )
                            .padding(horizontal = 18.dp, vertical = 14.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column {
                                Text(
                                    text = "VR HERE Live Support",
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color.White
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(8.dp)
                                            .background(Color(0xFF10B981), CircleShape)
                                            .shadow(4.dp, CircleShape)
                                    )
                                    Text(
                                        text = "Online • Typically replies in seconds",
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = Color.White.copy(alpha = 0.9f)
                                    )
                                }
                            }

                            // Dismiss Close Button
                            Surface(
                                modifier = Modifier
                                    .size(32.dp)
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
                                        modifier = Modifier.size(18.dp)
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
                            .padding(horizontal = 16.dp, vertical = 12.dp),
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
                                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)
                                    ) {
                                        Text(
                                            text = msg.text,
                                            fontSize = 13.5.sp,
                                            lineHeight = 19.sp,
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

                                    Box(modifier = Modifier.size(6.dp).background(Color(0xFF64748B).copy(alpha = dot1Alpha), CircleShape))
                                    Box(modifier = Modifier.size(6.dp).background(Color(0xFF64748B).copy(alpha = dot2Alpha), CircleShape))
                                    Box(modifier = Modifier.size(6.dp).background(Color(0xFF64748B).copy(alpha = dot3Alpha), CircleShape))
                                }
                            }
                        }
                    }

                    // Quick Suggestion Chips Row
                    LazyRow(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(Color.White)
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(quickPrompts) { prompt ->
                            Surface(
                                shape = RoundedCornerShape(16.dp),
                                color = Color(0xFFF1F5F9),
                                border = BorderStroke(1.dp, Color(0xFFCBD5E1)),
                                modifier = Modifier.clickable { sendMessage(prompt) }
                            ) {
                                Text(
                                    text = prompt,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = Color(0xFF334155),
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
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
                                .padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = inputText,
                                onValueChange = { inputText = it },
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
                                    .size(42.dp)
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
                                        modifier = Modifier.size(18.dp)
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
                            .padding(vertical = 5.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "⚡ Powered by LetsTrack™",
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Color(0xFF64748B)
                        )
                    }
                }
            }
        }
    }
}
