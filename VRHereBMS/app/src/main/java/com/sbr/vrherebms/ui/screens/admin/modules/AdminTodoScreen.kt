package com.sbr.vrherebms.ui.screens.admin.modules

import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminTodoScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var selectedPriorityFilter by remember { mutableStateOf("All") }

    val priorities = listOf("All", "High", "Medium", "Low")

    // Filter todos dynamically
    val filteredTodos = adminViewModel.todos.filter { todo ->
        val matchesSearch = todo.title.contains(searchQuery, ignoreCase = true) ||
                (todo.description?.contains(searchQuery, ignoreCase = true) ?: false)

        val matchesPriority = if (selectedPriorityFilter == "All") true else todo.priority.equals(selectedPriorityFilter, ignoreCase = true)

        matchesSearch && matchesPriority
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
            .padding(16.dp)
    ) {
        // 1. Search textfield
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search task lists...", fontSize = 14.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = "Search", tint = Color(0xFF64748B)) },
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Color(0xFFF59E0B),
                unfocusedBorderColor = Color(0xFFE2E8F0)
            ),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(12.dp))

        // 2. Priority Filter row
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            priorities.forEach { level ->
                val isSelected = selectedPriorityFilter == level
                val bg = if (isSelected) Color(0xFFF59E0B) else Color.White
                val textColor = if (isSelected) Color.White else Color(0xFF64748B)
                val border = if (isSelected) Color.Transparent else Color(0xFFE2E8F0)

                Box(
                    modifier = Modifier
                        .background(bg, RoundedCornerShape(20.dp))
                        .clickable { selectedPriorityFilter = level }
                        .border(1.dp, border, RoundedCornerShape(20.dp))
                        .padding(horizontal = 14.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = "$level priority",
                        color = textColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. To-Do Cards List
        if (filteredTodos.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Default.PlaylistAddCheck,
                        contentDescription = null,
                        tint = Color(0xFF94A3B8),
                        modifier = Modifier.size(64.dp)
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Text("No tasks active on your board.", color = Color(0xFF64748B), fontSize = 14.sp)
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredTodos) { todo ->
                    var isDoneState by remember { mutableStateOf(todo.status == "Completed") }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFEEF2F6)),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // Checkbox task completing
                            IconButton(onClick = {
                                isDoneState = !isDoneState
                                Toast.makeText(context, if (isDoneState) "Task Completed!" else "Task Marked Pending", Toast.LENGTH_SHORT).show()
                            }) {
                                Icon(
                                    imageVector = if (isDoneState) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                                    contentDescription = null,
                                    tint = if (isDoneState) Color(0xFF10B981) else Color(0xFF94A3B8),
                                    modifier = Modifier.size(24.dp)
                                )
                            }

                            // Title, Description, Assignment Details
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = todo.title,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isDoneState) Color(0xFF94A3B8) else Color(0xFF1E293B),
                                    textDecoration = if (isDoneState) TextDecoration.LineThrough else TextDecoration.None
                                )

                                todo.description?.let { desc ->
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = desc,
                                        fontSize = 12.sp,
                                        color = Color(0xFF64748B),
                                        maxLines = 2
                                    )
                                }

                                Spacer(modifier = Modifier.height(8.dp))

                                Row(
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    // Assignee box indicator
                                    val assigneeName = todo.assignedTo?.name ?: "General Team"
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                                    ) {
                                        Icon(Icons.Default.AccountCircle, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(14.dp))
                                        Text(assigneeName, color = Color(0xFF64748B), fontSize = 11.sp)
                                    }

                                    // Priority Indicator Pill
                                    val pillBg = when (todo.priority.lowercase()) {
                                        "high" -> Color(0xFFFEE2E2)
                                        "medium" -> Color(0xFFFEF3C7)
                                        else -> Color(0xFFECFDF5)
                                    }
                                    val pillColor = when (todo.priority.lowercase()) {
                                        "high" -> Color(0xFFEF4444)
                                        "medium" -> Color(0xFFD97706)
                                        else -> Color(0xFF10B981)
                                    }
                                    Box(
                                        modifier = Modifier
                                            .background(pillBg, RoundedCornerShape(6.dp))
                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                    ) {
                                        Text(
                                            text = todo.priority.uppercase(),
                                            color = pillColor,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.ExtraBold
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
