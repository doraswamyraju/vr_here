package com.sbr.vrherebms.ui.screens.admin.modules

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sbr.vrherebms.viewmodel.AdminDashboardViewModel

data class SOPArticle(
    val id: String,
    val title: String,
    val summary: String,
    val category: String,
    val instructions: List<String>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminKbScreen(
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    var searchQuery by remember { mutableStateOf("") }
    var activeCategory by remember { mutableStateOf("All") }

    val categories = listOf("All", "Incorporation", "GST Filings", "Trademarks", "MCA Filing")

    val articles = listOf(
        SOPArticle(
            "1",
            "SPICe+ Company Incorporation Form SOP",
            "Standard operating guide for digital signature generation, PAN/TAN declarations, and Spice form drafting.",
            "Incorporation",
            listOf(
                "Generate DSC (Digital Signature Certificate) for all proposed directors.",
                "Reserve company name using the RUN (Reserve Unique Name) web service on MCA portal.",
                "Prepare MoA (Memorandum of Association) and AoA (Articles of Association) drafts under SPICe+ Part B.",
                "Upload digital signatures and submit form along with PAN/TAN generation declarations."
            )
        ),
        SOPArticle(
            "2",
            "GST GSTR-1 & 3B Filing Guidelines SOP",
            "Filing procedures for monthly GSTR-1 outward supplies and GSTR-3B summary input tax credits.",
            "GST Filings",
            listOf(
                "Gather sales spreadsheets and client billing invoices for the tax month.",
                "Reconcile outward supplies and populate table 4, 5, and 6 on GSTR-1 dashboard.",
                "Perform GSTR-2B Input Tax Credit reconciliation to ensure matches in draft ITC claims.",
                "File GSTR-3B return summary and deposit statutory liability after setting off cash ledger credits."
            )
        ),
        SOPArticle(
            "3",
            "Trademark Reply to Opposition objection reply SOP",
            "Objection replies, TM classifications, and legal documentation guidelines for intellectual property registries.",
            "Trademarks",
            listOf(
                "Download Trademark examination report from Intellectual Property repository.",
                "Draft formal objection response citing user claims, brand reputation index, and judicial precedents.",
                "Complete Form TM-A filings under appropriate statutory classes.",
                "Upload objections reply within 30 days of examiner's objection notice dispatch."
            )
        )
    )

    val filteredArticles = remember(searchQuery, activeCategory) {
        articles.filter {
            val matchesSearch = it.title.contains(searchQuery, ignoreCase = true) || it.summary.contains(searchQuery, ignoreCase = true)
            val matchesCat = activeCategory == "All" || it.category.equals(activeCategory, ignoreCase = true)
            matchesSearch && matchesCat
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF1F5F9))
    ) {
        // 1. Purple Header
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1B4B))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "KNOWLEDGE BASE HUB",
                    color = Color(0xFF38BDF8),
                    fontSize = 10.sp,
                    fontWeight = FontWeight.ExtraBold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Standard Operating SOPs",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Black
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Access tutorials, compliance worksheets templates, and standard instructions manuals for operational execution.",
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }

        // 2. Categories scroll
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(categories) { cat ->
                val isSelected = activeCategory == cat
                Box(
                    modifier = Modifier
                        .background(
                            if (isSelected) Color(0xFF4F46E5) else Color.White,
                            RoundedCornerShape(12.dp)
                        )
                        .border(
                            1.dp,
                            if (isSelected) Color.Transparent else Color(0xFFE2E8F0),
                            RoundedCornerShape(12.dp)
                        )
                        .clickable { activeCategory = cat }
                        .padding(horizontal = 14.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = cat,
                        color = if (isSelected) Color.White else Color(0xFF64748B),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Black
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // 3. Search Field
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search SOP tutorial articles...", fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = Color(0xFF64748B)) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = Color.White,
                unfocusedContainerColor = Color.White,
                focusedBorderColor = Color(0xFF4F46E5),
                unfocusedBorderColor = Color(0xFFE2E8F0)
            ),
            singleLine = true
        )

        Spacer(modifier = Modifier.height(16.dp))

        // 4. Articles Accordion List
        LazyColumn(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(filteredArticles) { article ->
                var isExpanded by remember { mutableStateOf(false) }

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { isExpanded = !isExpanded },
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                    border = BorderStroke(1.dp, Color(0xFFEEF2F6))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFFEFF6FF), RoundedCornerShape(6.dp))
                                        .padding(horizontal = 8.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = article.category.uppercase(),
                                        color = Color(0xFF3B82F6),
                                        fontSize = 8.sp,
                                        fontWeight = FontWeight.Black
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = article.title,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF1E293B)
                                )
                            }

                            Icon(
                                imageVector = if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                contentDescription = null,
                                tint = Color(0xFF64748B)
                            )
                        }

                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = article.summary,
                            fontSize = 11.sp,
                            color = Color(0xFF64748B),
                            lineHeight = 16.sp
                        )

                        // Accordion expansion animation
                        AnimatedVisibility(
                            visible = isExpanded,
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut()
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 16.dp),
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Divider(color = Color(0xFFF1F5F9))
                                Text(
                                    text = "Step-by-Step Filing Procedures:",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp,
                                    color = Color(0xFF1E293B)
                                )

                                article.instructions.forEachIndexed { index, step ->
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .size(18.dp)
                                                .background(Color(0xFF4F46E5), CircleShape),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Text(
                                                text = (index + 1).toString(),
                                                fontSize = 9.sp,
                                                color = Color.White,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = step,
                                                fontSize = 11.sp,
                                                color = Color(0xFF475569),
                                                lineHeight = 16.sp
                                            )
                                        }
                                    }
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.End
                                ) {
                                    Button(
                                        onClick = {
                                            val textToCopy = article.instructions.joinToString("\n") { it }
                                            clipboard.setPrimaryClip(ClipData.newPlainText("SOP Guide", textToCopy))
                                            Toast.makeText(context, "SOP instructions copied to clipboard!", Toast.LENGTH_SHORT).show()
                                        },
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = Color(0xFFEFF6FF),
                                            contentColor = Color(0xFF3B82F6)
                                        ),
                                        shape = RoundedCornerShape(8.dp),
                                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                                        modifier = Modifier.height(32.dp)
                                    ) {
                                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(12.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Copy Guide", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (filteredArticles.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 40.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No SOP articles matches search criteria.",
                            color = Color(0xFF64748B),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }
    }
}
