# Architectural Strategy Proposal

This document outlines the solutions for cross-platform service synchronization and dynamic city-specific SEO page scaling.

---

## Strategy 1: Cross-Platform Service Sync (Server-Driven UI)

To eliminate manual code duplication across React Web, Android (Kotlin), and iOS (SwiftUI) while keeping native design specifications and native checkout (Razorpay), we recommend a **Server-Driven UI (SDUI)** architecture.

### SDUI Workflow Architecture
1. **Admin Panel / DB**: Saves the Service configuration JSON schema to the database.
2. **Backend API**: Serves the JSON schema request to all clients.
3. **React Web, Android (Compose), and iOS (SwiftUI)**: Each client implements native rendering layers to read the JSON schema and map standard visual elements (e.g., packages grid, checklists, text blocks) dynamically using native platform components.
4. **Native Payments**:
   - Web launches Razorpay Web Checkout JS interface.
   - Android and iOS use the Razorpay Mobile SDK sheets directly in-app passing pricing parameters fetched from the backend.

### Sample Unified Service Schema (JSON)
```json
{
  "serviceId": "income-tax-return",
  "title": "Income Tax Return (ITR) Filing",
  "basePrice": 499,
  "plans": [
    {"id": "itr1", "name": "ITR-1 (Sahaj)", "price": 999},
    {"id": "itr2", "name": "ITR-2 (Premium)", "price": 1699}
  ],
  "documentsChecklist": [
    "PAN & Aadhaar Card",
    "Form 16"
  ]
}
```

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
