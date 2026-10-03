import Foundation
import Combine

enum DashboardState {
    case idle
    case loading
    case success
    case error(String)
}

@MainActor
class CustomerDashboardViewModel: ObservableObject {
    @Published var dashboardState: DashboardState = .idle
    
    @Published var orders: [OrderResponse] = []
    @Published var payments: [PaymentResponse] = []
    @Published var tickets: [TicketResponse] = []
    @Published var notifications: [NotificationResponse] = []
    @Published var blogs: [BlogResponse] = []
    @Published var offers: [OfferResponse] = []
    @Published var financeRecords: [FinanceRecordResponse] = []
    
    @Published var activeBannerNotification: NotificationResponse? = nil
    
    @Published var ticketSubject = ""
    @Published var ticketDescription = ""
    @Published var ticketPriority = "Low"
    @Published var ticketReplyMessage = ""
    
    @Published var toastMessage: String? = nil
    @Published var ticketCreatedEvent = false
    
    func dismissBanner() {
        activeBannerNotification = nil
    }
    
    func refreshAllData(silent: Bool = false) {
        Task {
            await refreshAllDataAsync(silent: silent)
        }
    }
    
    func refreshAllDataAsync(silent: Bool = false) async {
        if !silent {
            dashboardState = .loading
        }
        
        var hasErrors = false
        var lastErrorMessage = ""
        
        // 1. Fetch Orders
        do {
            orders = try await NetworkManager.shared.getOrders()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Orders: \(error.localizedDescription)"
                print("Orders sync failed: \(error)")
            }
        }
        
        // 2. Fetch Payments
        do {
            payments = try await NetworkManager.shared.getPayments()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Payments: \(error.localizedDescription)"
                print("Payments sync failed: \(error)")
            }
        }
        
        // 3. Fetch Tickets
        do {
            tickets = try await NetworkManager.shared.getTickets()
        } catch {
            if !error.isCancellationError {
                hasErrors = true
                lastErrorMessage = "Tickets: \(error.localizedDescription)"
                print("Tickets sync failed: \(error)")
            }
        }
        
        // 4. Fetch Blogs & Regulatory Insights
        do {
            let fetchedBlogs = try await NetworkManager.shared.getBlogs()
            if !fetchedBlogs.isEmpty {
                blogs = fetchedBlogs
            } else if blogs.isEmpty {
                blogs = defaultBlogs()
            }
        } catch {
            if blogs.isEmpty {
                blogs = defaultBlogs()
            }
            print("Blogs sync failed, using fallbacks: \(error)")
        }
        
        // 5. Fetch Promotional Offers
        do {
            let fetchedOffers = try await NetworkManager.shared.getOffers()
            if !fetchedOffers.isEmpty {
                offers = fetchedOffers
            } else if offers.isEmpty {
                offers = defaultOffers()
            }
        } catch {
            if offers.isEmpty {
                offers = defaultOffers()
            }
            print("Offers sync failed, using fallbacks: \(error)")
        }
        
        // 6. Fetch Finance Records
        do {
            financeRecords = try await NetworkManager.shared.getFinanceRecords()
        } catch {
            print("Finance records sync failed: \(error)")
        }
        
        // 7. Fetch Notifications
        do {
            let newNotifications = try await NetworkManager.shared.getNotifications()
            if !notifications.isEmpty && !newNotifications.isEmpty {
                let newUnreads = newNotifications.filter { item in
                    !item.isRead && !notifications.contains(where: { $0.id == item.id })
                }
                if let latest = newUnreads.first {
                    activeBannerNotification = latest
                }
            }
            notifications = newNotifications
        } catch {
            if !error.isCancellationError {
                print("Notifications sync failed: \(error)")
            }
        }
        
        // 8. Sync User Profile (phone, name, email)
        do {
            let profile = try await NetworkManager.shared.getProfile()
            if let p = profile.phone, !p.isEmpty {
                SessionManager.shared.savePhone(p)
            }
        } catch {
            // Non-blocking
        }
        
        if hasErrors {
            if !silent {
                dashboardState = .error(lastErrorMessage)
                toastMessage = lastErrorMessage
            }
        } else {
            dashboardState = .success
        }
    }
    
    private func defaultBlogs() -> [BlogResponse] {
        return [
            BlogResponse(
                idVal: "blog_1",
                title: "MCA Mandates Biometric Verification for Key Directorships in FY 2026-27",
                slug: "mca-mandates-biometric-verification-directorships",
                summary: "The Ministry of Corporate Affairs has introduced mandatory digital identity & biometric KYC protocols for newly appointed executive directors.",
                category: "Corporate & Legal",
                categoryColor: "#DC2626",
                readTime: "3 min read",
                coverImageUrl: nil,
                keyTakeaways: [
                    "Applies to all private & public limited directorships starting April 2026.",
                    "Existing directors must complete aadhaar-linked facial authentication on V3 portal.",
                    "Non-compliance leads to temporary deactivation of DIN numbers."
                ],
                fullArticle: "The Ministry of Corporate Affairs (MCA) has issued an updated compliance advisory mandating two-factor biometrics and live liveness verification for all new Director Identification Number (DIN) applications.\n\nKey steps include linking updated phone numbers with DigiLocker and completing the live e-KYC flow prior to submitting SPICe+ Part B forms."
            ),
            BlogResponse(
                idVal: "blog_2",
                title: "GST E-Invoicing Threshold Lowered: Critical Action Items for MSMEs",
                slug: "gst-e-invoicing-threshold-msme-advisory",
                summary: "CBIC has expanded the mandatory B2B e-invoicing framework. Understand the applicability, IRN generation, and QR code guidelines.",
                category: "GST & Direct Taxes",
                categoryColor: "#2563EB",
                readTime: "4 min read",
                coverImageUrl: nil,
                keyTakeaways: [
                    "B2B invoices must generate IRN via IRP portal in real time.",
                    "Mandatory 6-digit HSN code verification for all outward supplies.",
                    "Integrated automated accounting prevents input tax credit (ITC) mismatch."
                ],
                fullArticle: "The Central Board of Indirect Taxes and Customs (CBIC) continues to streamline the Goods and Services Tax framework by integrating automated invoice reference numbers (IRN).\n\nVR HERE Business Management Solutions provides end-to-end bookkeeping and GSTR filing to keep your enterprise 100% compliant."
            ),
            BlogResponse(
                idVal: "blog_3",
                title: "Startup India Seed Fund Scheme (SISFS) 2026 Expansion Announced",
                slug: "startup-india-seed-fund-scheme-expansion",
                summary: "DPIIT announced an enhanced capital allocation of ₹1,200 Cr for DPIIT-recognized early-stage startups and tech innovations.",
                category: "Startups & Funding",
                categoryColor: "#16A34A",
                readTime: "5 min read",
                coverImageUrl: nil,
                keyTakeaways: [
                    "Grants up to ₹20 Lakhs for proof of concept and prototype development.",
                    "Convertible debentures up to ₹50 Lakhs for market entry and commercialization.",
                    "Fast-tracked DPIIT recognition assistance through VR HERE."
                ],
                fullArticle: "Early-stage entrepreneurs can now access expanded seed capital under the Startup India initiative. Eligible companies must be incorporated within the last two years with an innovative product or tech thesis."
            )
        ]
    }
    
    private func defaultOffers() -> [OfferResponse] {
        return [
            OfferResponse(
                idVal: "offer_1",
                title: "Annual Compliance Shield 2026-27",
                subtitle: "ROC Filings, AGM, Director KYC & Statutory Audit Sign-off bundled",
                badgeTag: "SAVE ₹12,000",
                badgeColor: "#DC2626",
                targetServiceKey: "pvt_ltd_compliance",
                discountAmount: 12000,
                originalPrice: 29999,
                discountedPrice: 17999,
                eligibilityText: "Applicable for all Private Limited & OPC entities",
                ctaText: "Get Protected →",
                isActive: true,
                priority: 1
            ),
            OfferResponse(
                idVal: "offer_2",
                title: "Trademark & Brand Protection Fast-Track",
                subtitle: "Search, Filing, Power of Attorney & Objection Management",
                badgeTag: "ALL-INCLUSIVE",
                badgeColor: "#4F46E5",
                targetServiceKey: "trademark_filing",
                discountAmount: 3000,
                originalPrice: 9999,
                discountedPrice: 6999,
                eligibilityText: "Govt fee for MSME / Startup recognized enterprises included",
                ctaText: "Protect Brand →",
                isActive: true,
                priority: 2
            ),
            OfferResponse(
                idVal: "offer_3",
                title: "GST Monthly Return & ITC Reconciliation Suite",
                subtitle: "GSTR-1, GSTR-3B, Vendor Reconciliation & Tally Voucher Export",
                badgeTag: "FLAT 40% OFF",
                badgeColor: "#059669",
                targetServiceKey: "gst_filing",
                discountAmount: 4000,
                originalPrice: 10000,
                discountedPrice: 6000,
                eligibilityText: "Annual upfront subscription plan",
                ctaText: "Subscribe Now →",
                isActive: true,
                priority: 3
            )
        ]
    }
    
    @Published var ticketCategory = "Service"
    
    func createSupportTicket(category: String? = nil, subject: String? = nil, description: String? = nil, priority: String? = nil) async -> Bool {
        let cat = category ?? ticketCategory
        let sub = subject ?? ticketSubject
        let desc = description ?? ticketDescription
        let prio = priority ?? ticketPriority
        
        guard !sub.isEmpty && !desc.isEmpty else {
            toastMessage = "Please enter subject and description"
            return false
        }
        
        do {
            let newTicket = try await NetworkManager.shared.createTicket(
                category: cat,
                subject: sub,
                description: desc,
                priority: prio
            )
            tickets.insert(newTicket, at: 0)
            ticketSubject = ""
            ticketDescription = ""
            ticketPriority = "Medium"
            toastMessage = "Support ticket raised successfully!"
            ticketCreatedEvent = true
            return true
        } catch {
            toastMessage = "Failed to create ticket: \(error.localizedDescription)"
            return false
        }
    }
    
    func createSupportTicket() {
        Task {
            _ = await createSupportTicket(category: ticketCategory, subject: ticketSubject, description: ticketDescription, priority: ticketPriority)
        }
    }
    
    func replyToTicket(ticketId: String, message: String? = nil) async -> TicketResponse? {
        let msg = message ?? ticketReplyMessage
        guard !msg.isEmpty else { return nil }
        
        do {
            let updatedTicket = try await NetworkManager.shared.addTicketMessage(ticketId: ticketId, message: msg)
            if let index = tickets.firstIndex(where: { $0.id == ticketId }) {
                tickets[index] = updatedTicket
            }
            if message == nil {
                ticketReplyMessage = ""
            }
            toastMessage = "Reply sent!"
            return updatedTicket
        } catch {
            toastMessage = "Failed to reply: \(error.localizedDescription)"
            return nil
        }
    }
    
    func replyToTicket(ticketId: String) {
        Task {
            _ = await replyToTicket(ticketId: ticketId, message: nil)
        }
    }
    
    func markNotificationAsRead(id: String) {
        Task {
            do {
                _ = try await NetworkManager.shared.markNotificationAsRead(id: id)
                if let index = notifications.firstIndex(where: { $0.id == id }) {
                    let n = notifications[index]
                    // Create updated notification copy since struct properties are read-only let.
                    notifications[index] = NotificationResponse(
                        idVal: n.idVal,
                        title: n.title,
                        message: n.message,
                        type: n.type,
                        isRead: true,
                        createdAt: n.createdAt
                    )
                }
            } catch {
                print("Failed to mark notification \(id) as read: \(error)")
            }
        }
    }
}
