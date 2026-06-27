# Architectural Strategy Proposal

This document outlines the solutions for cross-platform service synchronization and dynamic city-specific SEO page scaling.

---

## Strategy 1: Cross-Platform Service Sync (Server-Driven UI) - Detailed Breakdown

### 1. What is Server-Driven UI (SDUI)?
Traditionally, you code a screen's UI layout and data separately inside the React Web code, Android Kotlin XML/Compose code, and iOS Swift/SwiftUI code. Any time a service page changes (e.g., a price changes, a feature is added, or a checklist changes), you have to modify three different codebases, deploy updates, and wait for Apple/Google App Store approvals.

**Server-Driven UI** shifts the layout and data ownership to the server. The server sends a structural JSON response (the schema) that doesn't just specify *data*, but also specifies *how the layout should look and behave*. The clients (Web, Android, iOS) act as "dumb" rendering engines that parse this JSON and build native widgets on the fly.

### 2. Architectural Blueprint

```
 ┌────────────────────────────────────────────────────────┐
 │                   Admin Panel / DB                     │
 │  (Configure service title, pricing, checklists, CTAs)  │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │                      Backend API                       │
 │         (Serves unified JSON Page Config Schema)        │
 └─────────────┬─────────────┼──────────────┬─────────────┘
               │             │              │
               ▼             ▼              ▼
         ┌───────────┐ ┌───────────┐  ┌───────────┐
         │ React Web │ │  Android  │  │    iOS    │
         │ Renderer  │ │  Compose  │  │  SwiftUI  │
         │  (Web)    │ │ Renderer  │  │ Renderer  │
         └─────┬─────┘ └─────┬─────┘  └─────┬─────┘
               │             │              │
               ▼             ▼              ▼
         ┌───────────┐ ┌───────────┐  ┌───────────┐
         │ Razorpay  │ │ Razorpay  │  │ Razorpay  │
         │  Web JS   │ │Android SDK│  │  iOS SDK  │
         └───────────┘ └───────────┘  └───────────┘
```

### 3. Concrete Example: Service Page Schema JSON
A single API endpoint like `/api/services/config/income-tax-return` serves the following schema:

```json
{
  "serviceId": "income-tax-return",
  "metadata": {
    "title": "Income Tax Return (ITR) Filing",
    "subTitle": "File accurately with expert Chartered Accountants.",
    "theme": "indigo"
  },
  "sections": [
    {
      "type": "packages",
      "title": "Select Your Return Filing Package",
      "items": [
        {
          "planId": "itr1",
          "name": "ITR-1 (Sahaj)",
          "price": 999,
          "features": ["Salary & Form 16", "House Property", "FD/Savings Interest"],
          "action": {
            "type": "checkout",
            "productId": "prod_itr_1",
            "price": 999
          }
        },
        {
          "planId": "itr2",
          "name": "ITR-2 (Premium)",
          "price": 1699,
          "features": ["Capital Gains / Shares", "Multiple House Properties", "Foreign Income"],
          "action": {
            "type": "checkout",
            "productId": "prod_itr_2",
            "price": 1699
          }
        }
      ]
    },
    {
      "type": "checklist",
      "title": "Documents Required",
      "categories": [
        {
          "name": "General Documents",
          "items": ["PAN Card", "Aadhaar Card", "Bank Statements"]
        }
      ]
    }
  ]
}
```

### 4. Client-Side Rendering Implementation (Mapping Schema to UI)

Each app reads the JSON `sections` array and maps elements to native UI elements:

#### Web (React + Vanilla CSS)
```jsx
// Iterate sections in React render
{serviceSchema.sections.map((section, idx) => {
  if (section.type === 'packages') {
    return <PackagesSection key={idx} data={section} onSelectPlan={handleCheckoutTrigger} />;
  }
  if (section.type === 'checklist') {
    return <ChecklistSection key={idx} data={section} />;
  }
})}
```

#### Android (Jetpack Compose)
```kotlin
// Iterate sections in Kotlin
@Composable
fun ServiceScreen(sections: List<SectionData>) {
    LazyColumn {
        items(sections) { section ->
            when (section.type) {
                "packages" -> PackagesSectionView(section, onSelectPlan = { initiateNativeRazorpay(it) })
                "checklist" -> ChecklistSectionView(section)
            }
        }
    }
}
```

#### iOS (SwiftUI)
```swift
// Iterate sections in SwiftUI
struct ServiceScreen: View {
    let sections: [SectionData]
    
    var body: some View {
        ScrollView {
            VStack {
                ForEach(sections) { section in
                    switch section.type {
                    case "packages":
                        PackagesSectionView(data: section, onSelect: { initiateNativeRazorpay($0) })
                    case "checklist":
                        ChecklistSectionView(data: section)
                    default:
                        EmptyView()
                    }
                }
            }
        }
    }
}
```

### 5. Native Checkout & Payments Hook (Razorpay Integration)
To prevent webview redirection and keep the UX premium, payments are handled using native platform SDK wrappers configured to fire the same action configurations.
- **Web**: React receives the checkout click, loads Razorpay standard web checkout via JS, completes checkout, and updates backend.
- **Android**: Compose handles the click natively, triggers the **Razorpay Android SDK (Checkout)** Activity wrapper, receives success/fail callbacks natively in Kotlin, and communicates success to the backend API.
- **iOS**: SwiftUI triggers the **Razorpay iOS SDK** framework wrapper natively via UIKit integration, presents the payment sheet, and processes verification callbacks.

---

## Strategy 2: Scalable City-Specific SEO Pages (200+ Cities)

To support 200+ city-specific pages (e.g., `/income-tax-return-tirupati`, `/income-tax-return-hyderabad`) without codebase bloat or manual file creation, we use **Dynamic Wildcard Routing** coupled with **Server-Side Meta Injection** for search crawlers.

### 1. Frontend Wildcard Routing
Define a single dynamic wildcard route in `frontend.jsx`:
```jsx
<Route path="/income-tax-return-:city" element={<IncomeTaxPage />} />
```
Inside the component:
- Grab the `city` param using the React Router `useParams()` hook.
- Format the city name dynamically (e.g., `tirupati` becomes `"Tirupati"`).
- Interpolate the city name dynamically into headings, tags, descriptions, and checklists.

### 2. Express Server-Side Meta Injection
Search engines (Googlebot) need to read `<title>` and `<meta>` tags directly from the initial server-side HTML response to index pages and backlinks properly.
In `backend/server.js`:
```javascript
app.get('/income-tax-return-:city', async (req, res) => {
  const rawCity = req.params.city;
  const cityName = rawCity.charAt(0).toUpperCase() + rawCity.slice(1);
  
  // Read target build file
  let html = fs.readFileSync(path.join(__dirname, '../dist/index.html'), 'utf8');
  
  // Dynamically replace title and SEO meta tags server-side
  html = html.replace(/<title>.*?<\/title>/g, `<title>Income Tax Return Filing Online in ${cityName} - AY 2026-27</title>`);
  html = html.replace(/<meta name="description" content=".*?"/g, `<meta name="description" content="File your ITR online in ${cityName} easily. Get CA-assisted e-filing for salaries, capital gains, and business tax in ${cityName}."`);

  res.send(html);
});
```

### 3. Dynamic Sitemap Generation
Construct a script/endpoint on the server to dynamically generate a `sitemap.xml` mapping all valid city permutations, ensuring search engine bots index every location-based URL.
