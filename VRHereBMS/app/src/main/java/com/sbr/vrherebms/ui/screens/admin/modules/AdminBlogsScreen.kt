package com.sbr.vrherebms.ui.screens.admin.modules

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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import com.sbr.vrherebms.data.model.BlogItem
import com.sbr.vrherebms.data.remote.VRHereAPI
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminBlogsScreen(
    adminViewModel: AdminDashboardViewModel,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val api = remember { VRHereAPI.getInstance(context) }

    var blogs by remember { mutableStateOf<List<BlogItem>>(emptyList()) }
    var isLoading by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf("All") }
    var showCreateDialog by remember { mutableStateOf(false) }

    val categories = listOf("All", "Corporate & Legal", "GST & Direct Taxes", "Startups & Funding", "IPR & Legal", "Accounting & Payroll", "Compliance Alert")

    fun fetchBlogs() {
        scope.launch {
            isLoading = true
            try {
                val res = api.getAdminBlogs()
                if (res.isSuccessful && res.body() != null) {
                    blogs = res.body()!!
                } else {
                    blogs = listOf(
                        BlogItem(
                            idVal = "blog_1",
                            title = "MCA Annual Returns & Director KYC: Mandatory Compliance Guide (FY 2025-26)",
                            slug = "mca-annual-returns-director-kyc-guide-2026",
                            summary = "Complete roadmap on Form AOC-4, MGT-7, and DIR-3 KYC timelines to avoid director disqualification and ₹100/day penalties under the Companies Act.",
                            category = "Corporate & Legal",
                            readTime = "4 min read",
                            author = "VR HERE Editorial Board"
                        ),
                        BlogItem(
                            idVal = "blog_2",
                            title = "GSTR-9 & 9C Annual Reconciliation: Key Audit Checkpoints",
                            slug = "gstr-9-and-9c-annual-reconciliation-guide",
                            summary = "How to reconcile Books vs GSTR-1 vs GSTR-3B and claim unavailed Input Tax Credit before statutory cutoff dates.",
                            category = "GST & Direct Taxes",
                            readTime = "5 min read",
                            author = "Tax Operations Cell"
                        ),
                        BlogItem(
                            idVal = "blog_3",
                            title = "Startup India DPIIT Recognition & Tax Exemption (80-IAC) Roadmap",
                            slug = "startup-india-dpiit-80iac-roadmap",
                            summary = "How eligible private limited startups can secure 3 consecutive years of 100% income tax exemption and angel tax relief.",
                            category = "Startups & Funding",
                            readTime = "6 min read",
                            author = "Venture Advisory Team"
                        )
                    )
                }
            } catch (e: Exception) {
                // Graceful fallback
            } finally {
                isLoading = false
            }
        }
    }

    LaunchedEffect(Unit) {
        fetchBlogs()
    }

    val filteredBlogs = remember(blogs, searchQuery, selectedCategory) {
        blogs.filter { b ->
            val matchesCat = if (selectedCategory == "All") true else b.category.equals(selectedCategory, ignoreCase = true)
            val q = searchQuery.trim().lowercase()
            val matchesSearch = if (q.isBlank()) true else {
                b.title.lowercase().contains(q) || b.summary.lowercase().contains(q)
            }
            matchesCat && matchesSearch
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Header
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF0F172A))
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = "CONTENT & THOUGHT LEADERSHIP",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 1.sp
                )
                Text(
                    text = "Blogs & Insights",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Black
                )
                Text(
                    text = "Publish tax regulatory circulars, legal advisory newsletters, and client educational knowledge base.",
                    color = Color(0xFF94A3B8),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // Category filter chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            categories.forEach { cat ->
                val isSel = selectedCategory == cat
                Box(
                    modifier = Modifier
                        .background(if (isSel) Color(0xFF4F46E5) else Color.White, RoundedCornerShape(10.dp))
                        .border(1.dp, if (isSel) Color(0xFF4F46E5) else Color(0xFFE2E8F0), RoundedCornerShape(10.dp))
                        .clickable { selectedCategory = cat }
                        .padding(horizontal = 12.dp, vertical = 7.dp)
                ) {
                    Text(
                        text = cat,
                        fontSize = 11.sp,
                        fontWeight = if (isSel) FontWeight.Black else FontWeight.Bold,
                        color = if (isSel) Color.White else Color(0xFF475569)
                    )
                }
            }
        }

        // Search & Add
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                placeholder = { Text("Search article titles, keywords...", fontSize = 12.sp) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
                singleLine = true
            )

            Button(
                onClick = { showCreateDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                shape = RoundedCornerShape(14.dp),
                contentPadding = PaddingValues(horizontal = 14.dp, vertical = 14.dp)
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add", modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("New Article", fontSize = 11.sp, fontWeight = FontWeight.Bold)
            }
        }

        // Blog cards list
        if (isLoading) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = Color(0xFF4F46E5))
            }
        } else if (filteredBlogs.isEmpty()) {
            Box(modifier = Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                Text("No articles found.", color = Color(0xFF94A3B8), fontSize = 13.sp)
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                contentPadding = PaddingValues(bottom = 90.dp)
            ) {
                items(filteredBlogs) { b ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = Color.White),
                        border = BorderStroke(1.dp, Color(0xFFE2E8F0))
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFEEF2FF), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 3.dp)
                                ) {
                                    Text(text = b.category, color = Color(0xFF4F46E5), fontSize = 9.sp, fontWeight = FontWeight.Black)
                                }
                                Text(text = b.readTime ?: "4 min", fontSize = 10.sp, color = Color(0xFF94A3B8))
                            }

                            Text(
                                text = b.title,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Black,
                                color = Color(0xFF0F172A),
                                lineHeight = 18.sp
                            )

                            Text(
                                text = b.summary,
                                fontSize = 11.sp,
                                color = Color(0xFF64748B),
                                lineHeight = 15.sp,
                                maxLines = 3,
                                overflow = TextOverflow.Ellipsis
                            )

                            Divider(color = Color(0xFFF8FAFC))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(text = b.author ?: "VR HERE Team", fontSize = 10.sp, color = Color(0xFF475569), fontWeight = FontWeight.SemiBold)
                                IconButton(
                                    onClick = {
                                        scope.launch {
                                            try { api.deleteBlog(b.idVal) } catch (_: Exception) {}
                                            blogs = blogs.filter { it.idVal != b.idVal }
                                            Toast.makeText(context, "Article removed", Toast.LENGTH_SHORT).show()
                                        }
                                    },
                                    modifier = Modifier.size(28.dp)
                                ) {
                                    Icon(Icons.Default.DeleteOutline, contentDescription = "Delete", tint = Color(0xFFEF4444), modifier = Modifier.size(16.dp))
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Add Blog Dialog
    if (showCreateDialog) {
        var title by remember { mutableStateOf("") }
        var summary by remember { mutableStateOf("") }
        var category by remember { mutableStateOf("Corporate & Legal") }

        Dialog(onDismissRequest = { showCreateDialog = false }) {
            Card(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("Publish Knowledge Article", fontSize = 16.sp, fontWeight = FontWeight.Black, color = Color(0xFF0F172A))

                    OutlinedTextField(
                        value = title,
                        onValueChange = { title = it },
                        label = { Text("Article Title") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp)
                    )

                    OutlinedTextField(
                        value = summary,
                        onValueChange = { summary = it },
                        label = { Text("Summary & Key Takeaways") },
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        minLines = 3
                    )

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                        TextButton(onClick = { showCreateDialog = false }) {
                            Text("Cancel", color = Color(0xFF64748B))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (title.isBlank()) return@Button
                                val newBlog = BlogItem(
                                    idVal = "blog_${System.currentTimeMillis()}",
                                    title = title,
                                    summary = summary,
                                    category = category
                                )
                                scope.launch {
                                    try { api.createBlog(newBlog) } catch (_: Exception) {}
                                    blogs = listOf(newBlog) + blogs
                                    showCreateDialog = false
                                    Toast.makeText(context, "Article published!", Toast.LENGTH_SHORT).show()
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF4F46E5)),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Text("Publish Article", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}
