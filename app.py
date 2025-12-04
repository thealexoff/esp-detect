"""
ESP Detector - Scalable Email Service Provider Detection
=========================================================
Detects ESPs via DNS analysis (MX, SPF, DKIM)
Handles 1 to 100k+ domains with concurrent processing
"""

import streamlit as st
import pandas as pd
import dns.resolver
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import io

# ============================================================================
# ESP SIGNATURE DATABASE - 70+ ESPs
# ============================================================================

ESP_SIGNATURES = {
    # ECOMMERCE / DTC (Your target market)
    "Klaviyo": {
        "spf": ["spf.klaviyo.com", "klaviyo.com"],
        "mx": ["klaviyo-mail.com"],
        "dkim_selectors": ["klaviyo", "k1"],
        "dkim_cname": ["klaviyo.com"],
        "category": "ecommerce", "tier": "premium"
    },
    "Omnisend": {
        "spf": ["spf.omnisend.com", "omnisend.com"],
        "mx": ["omnisend.com"],
        "dkim_selectors": ["omnisend"],
        "dkim_cname": ["omnisend.com"],
        "category": "ecommerce", "tier": "premium"
    },
    "Drip": {
        "spf": ["drip.com", "getdrip.com"],
        "mx": ["drip.com"],
        "dkim_selectors": ["drip"],
        "dkim_cname": ["drip.com"],
        "category": "ecommerce", "tier": "premium"
    },
    "Privy": {
        "spf": ["privy.com"],
        "mx": ["privy.com"],
        "dkim_selectors": ["privy"],
        "dkim_cname": ["privy.com"],
        "category": "ecommerce", "tier": "mid"
    },
    "Yotpo": {
        "spf": ["yotpo.com"],
        "mx": ["yotpo.com"],
        "dkim_selectors": ["yotpo"],
        "dkim_cname": ["yotpo.com"],
        "category": "ecommerce", "tier": "premium"
    },
    "Attentive": {
        "spf": ["attentivemobile.com"],
        "mx": ["attentivemobile.com"],
        "dkim_selectors": ["attentive"],
        "dkim_cname": ["attentivemobile.com"],
        "category": "ecommerce", "tier": "premium"
    },
    "Listrak": {
        "spf": ["listrak.com"],
        "mx": ["listrak.com"],
        "dkim_selectors": ["listrak"],
        "dkim_cname": ["listrak.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    "Sailthru": {
        "spf": ["sailthru.com"],
        "mx": ["sailthru.com"],
        "dkim_selectors": ["sailthru"],
        "dkim_cname": ["sailthru.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    "Bluecore": {
        "spf": ["bluecore.com"],
        "mx": ["bluecore.com"],
        "dkim_selectors": ["bluecore"],
        "dkim_cname": ["bluecore.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    "Cordial": {
        "spf": ["cordial.com"],
        "mx": ["cordial.com"],
        "dkim_selectors": ["cordial"],
        "dkim_cname": ["cordial.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    "Emarsys": {
        "spf": ["emarsys.com", "emarsys.net"],
        "mx": ["emarsys.com"],
        "dkim_selectors": ["emarsys"],
        "dkim_cname": ["emarsys.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    "Dotdigital": {
        "spf": ["dotdigital.com", "dotmailer.com"],
        "mx": ["dotdigital.com"],
        "dkim_selectors": ["dotdigital"],
        "dkim_cname": ["dotdigital.com"],
        "category": "ecommerce", "tier": "enterprise"
    },
    
    # MARKETING AUTOMATION
    "Mailchimp": {
        "spf": ["servers.mcsv.net", "mcsv.net", "mailchimp.com"],
        "mx": ["mcsv.net", "mailchimp.com"],
        "dkim_selectors": ["k1", "k2", "mc"],
        "dkim_cname": ["mcsv.net", "dkim.mcsv.net"],
        "category": "marketing", "tier": "mid"
    },
    "ActiveCampaign": {
        "spf": ["activecampaign.com", "acems1.com"],
        "mx": ["activecampaign.com"],
        "dkim_selectors": ["ac", "activecampaign"],
        "dkim_cname": ["activecampaign.com"],
        "category": "marketing", "tier": "mid"
    },
    "HubSpot": {
        "spf": ["hubspot.com", "hubspotemail.net"],
        "mx": ["hubspot.com", "hubspotemail.net"],
        "dkim_selectors": ["hs1", "hs2", "hubspot"],
        "dkim_cname": ["hubspot.com"],
        "category": "marketing", "tier": "premium"
    },
    "Brevo (Sendinblue)": {
        "spf": ["sendinblue.com", "brevo.com"],
        "mx": ["sendinblue.com"],
        "dkim_selectors": ["mail", "sendinblue"],
        "dkim_cname": ["sendinblue.com"],
        "category": "marketing", "tier": "mid"
    },
    "GetResponse": {
        "spf": ["getresponse.com", "gr-mail.com"],
        "mx": ["getresponse.com"],
        "dkim_selectors": ["getresponse"],
        "dkim_cname": ["getresponse.com"],
        "category": "marketing", "tier": "mid"
    },
    "ConvertKit": {
        "spf": ["convertkit.com", "ckmail.link"],
        "mx": ["convertkit.com"],
        "dkim_selectors": ["ck", "convertkit"],
        "dkim_cname": ["convertkit.com"],
        "category": "marketing", "tier": "mid"
    },
    "AWeber": {
        "spf": ["aweber.com"],
        "mx": ["aweber.com"],
        "dkim_selectors": ["aweber"],
        "dkim_cname": ["aweber.com"],
        "category": "marketing", "tier": "mid"
    },
    "MailerLite": {
        "spf": ["mailerlite.com", "mlsend.com"],
        "mx": ["mailerlite.com"],
        "dkim_selectors": ["ml", "mailerlite"],
        "dkim_cname": ["mailerlite.com"],
        "category": "marketing", "tier": "budget"
    },
    "Constant Contact": {
        "spf": ["constantcontact.com", "rsys3.net"],
        "mx": ["constantcontact.com"],
        "dkim_selectors": ["ctct"],
        "dkim_cname": ["constantcontact.com"],
        "category": "marketing", "tier": "mid"
    },
    "Campaign Monitor": {
        "spf": ["createsend.com", "cmail19.com", "cmail20.com"],
        "mx": ["createsend.com"],
        "dkim_selectors": ["cm"],
        "dkim_cname": ["createsend.com"],
        "category": "marketing", "tier": "mid"
    },
    "Moosend": {
        "spf": ["moosend.com"],
        "mx": ["moosend.com"],
        "dkim_selectors": ["moosend"],
        "dkim_cname": ["moosend.com"],
        "category": "marketing", "tier": "budget"
    },
    "Emma": {
        "spf": ["e2ma.net", "emma.com"],
        "mx": ["e2ma.net"],
        "dkim_selectors": ["emma"],
        "dkim_cname": ["e2ma.net"],
        "category": "marketing", "tier": "mid"
    },

    # TRANSACTIONAL / INFRASTRUCTURE
    "SendGrid": {
        "spf": ["sendgrid.net", "sendgrid.com"],
        "mx": ["sendgrid.net", "mx.sendgrid.net"],
        "dkim_selectors": ["s1", "s2", "smtpapi"],
        "dkim_cname": ["sendgrid.net"],
        "category": "transactional", "tier": "premium"
    },
    "Mailgun": {
        "spf": ["mailgun.org", "mailgun.com"],
        "mx": ["mailgun.org", "mxa.mailgun.org"],
        "dkim_selectors": ["smtp", "mg", "k1"],
        "dkim_cname": ["mailgun.org"],
        "category": "transactional", "tier": "mid"
    },
    "Amazon SES": {
        "spf": ["amazonses.com"],
        "mx": ["amazonses.com", "inbound-smtp"],
        "dkim_selectors": ["ses"],
        "dkim_cname": ["amazonses.com"],
        "category": "transactional", "tier": "budget"
    },
    "Postmark": {
        "spf": ["postmarkapp.com", "mtasv.net"],
        "mx": ["postmarkapp.com"],
        "dkim_selectors": ["pm", "postmark"],
        "dkim_cname": ["postmarkapp.com"],
        "category": "transactional", "tier": "premium"
    },
    "SparkPost": {
        "spf": ["sparkpostmail.com"],
        "mx": ["sparkpostmail.com"],
        "dkim_selectors": ["sparkpost"],
        "dkim_cname": ["sparkpostmail.com"],
        "category": "transactional", "tier": "mid"
    },
    "Mandrill": {
        "spf": ["mandrillapp.com"],
        "mx": ["mandrillapp.com"],
        "dkim_selectors": ["mandrill"],
        "dkim_cname": ["mandrillapp.com"],
        "category": "transactional", "tier": "mid"
    },
    "Mailjet": {
        "spf": ["mailjet.com"],
        "mx": ["mailjet.com"],
        "dkim_selectors": ["mailjet"],
        "dkim_cname": ["mailjet.com"],
        "category": "transactional", "tier": "mid"
    },
    "Resend": {
        "spf": ["resend.com"],
        "mx": ["resend.com"],
        "dkim_selectors": ["resend"],
        "dkim_cname": ["resend.com"],
        "category": "transactional", "tier": "mid"
    },
    "Customer.io": {
        "spf": ["customer.io", "customeriomail.com"],
        "mx": ["customer.io"],
        "dkim_selectors": ["cio"],
        "dkim_cname": ["customer.io"],
        "category": "transactional", "tier": "premium"
    },
    "Loops": {
        "spf": ["loops.so"],
        "mx": ["loops.so"],
        "dkim_selectors": ["loops"],
        "dkim_cname": ["loops.so"],
        "category": "transactional", "tier": "mid"
    },
    "Mailersend": {
        "spf": ["mailersend.net"],
        "mx": ["mailersend.net"],
        "dkim_selectors": ["mailersend"],
        "dkim_cname": ["mailersend.net"],
        "category": "transactional", "tier": "mid"
    },

    # ENTERPRISE
    "Salesforce Marketing Cloud": {
        "spf": ["exacttarget.com", "cust-spf.exacttarget.com"],
        "mx": ["exacttarget.com"],
        "dkim_selectors": ["sf", "sf1", "sfmc"],
        "dkim_cname": ["exacttarget.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Pardot": {
        "spf": ["pardot.com"],
        "mx": ["pardot.com"],
        "dkim_selectors": ["pardot"],
        "dkim_cname": ["pardot.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Marketo": {
        "spf": ["mktomail.com", "marketo.com"],
        "mx": ["mktomail.com"],
        "dkim_selectors": ["m1", "mkto"],
        "dkim_cname": ["mktomail.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Eloqua": {
        "spf": ["eloqua.com"],
        "mx": ["eloqua.com"],
        "dkim_selectors": ["eloqua"],
        "dkim_cname": ["eloqua.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Oracle Responsys": {
        "spf": ["responsys.net"],
        "mx": ["responsys.net"],
        "dkim_selectors": ["responsys"],
        "dkim_cname": ["responsys.net"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Braze": {
        "spf": ["braze.com", "braze.eu"],
        "mx": ["braze.com"],
        "dkim_selectors": ["braze"],
        "dkim_cname": ["braze.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Iterable": {
        "spf": ["iterable.com"],
        "mx": ["iterable.com"],
        "dkim_selectors": ["iterable"],
        "dkim_cname": ["iterable.com"],
        "category": "enterprise", "tier": "enterprise"
    },
    "Acoustic (IBM)": {
        "spf": ["acoustic.com", "silverpop.com"],
        "mx": ["acoustic.com"],
        "dkim_selectors": ["acoustic"],
        "dkim_cname": ["acoustic.com"],
        "category": "enterprise", "tier": "enterprise"
    },

    # CRM WITH EMAIL
    "Keap (Infusionsoft)": {
        "spf": ["infusionmail.com", "keap.com"],
        "mx": ["infusionmail.com"],
        "dkim_selectors": ["infusion"],
        "dkim_cname": ["infusionmail.com"],
        "category": "crm", "tier": "mid"
    },
    "Ontraport": {
        "spf": ["ontraport.com"],
        "mx": ["ontraport.com"],
        "dkim_selectors": ["ontraport"],
        "dkim_cname": ["ontraport.com"],
        "category": "crm", "tier": "mid"
    },
    "Zoho Campaigns": {
        "spf": ["zoho.com", "zcsend.net"],
        "mx": ["zoho.com"],
        "dkim_selectors": ["zoho"],
        "dkim_cname": ["zoho.com"],
        "category": "crm", "tier": "mid"
    },

    # NEWSLETTER PLATFORMS
    "Substack": {
        "spf": ["substack.com"],
        "mx": ["substack.com"],
        "dkim_selectors": ["substack"],
        "dkim_cname": ["substack.com"],
        "category": "newsletter", "tier": "mid"
    },
    "Beehiiv": {
        "spf": ["beehiiv.com"],
        "mx": ["beehiiv.com"],
        "dkim_selectors": ["beehiiv"],
        "dkim_cname": ["beehiiv.com"],
        "category": "newsletter", "tier": "mid"
    },
    "Ghost": {
        "spf": ["ghost.io"],
        "mx": ["ghost.io"],
        "dkim_selectors": ["ghost"],
        "dkim_cname": ["ghost.io"],
        "category": "newsletter", "tier": "mid"
    },
    "Buttondown": {
        "spf": ["buttondown.email"],
        "mx": ["buttondown.email"],
        "dkim_selectors": ["buttondown"],
        "dkim_cname": ["buttondown.email"],
        "category": "newsletter", "tier": "budget"
    },

    # WORKSPACE (for context - not marketing ESPs)
    "Google Workspace": {
        "spf": ["google.com", "_spf.google.com"],
        "mx": ["google.com", "aspmx.l.google.com", "googlemail.com"],
        "dkim_selectors": ["google"],
        "dkim_cname": ["google.com"],
        "category": "workspace", "tier": "standard"
    },
    "Microsoft 365": {
        "spf": ["protection.outlook.com", "outlook.com"],
        "mx": ["mail.protection.outlook.com"],
        "dkim_selectors": ["selector1", "selector2"],
        "dkim_cname": ["onmicrosoft.com"],
        "category": "workspace", "tier": "standard"
    },
    "Zoho Mail": {
        "spf": ["zoho.com", "zohomail.com"],
        "mx": ["zoho.com", "zohomail.com"],
        "dkim_selectors": ["zoho"],
        "dkim_cname": ["zoho.com"],
        "category": "workspace", "tier": "standard"
    },
    "Fastmail": {
        "spf": ["fastmail.com", "messagingengine.com"],
        "mx": ["fastmail.com"],
        "dkim_selectors": ["fm1", "fm2"],
        "dkim_cname": ["fastmail.com"],
        "category": "workspace", "tier": "standard"
    },
    "ProtonMail": {
        "spf": ["protonmail.ch"],
        "mx": ["protonmail.ch"],
        "dkim_selectors": ["protonmail"],
        "dkim_cname": ["protonmail.ch"],
        "category": "workspace", "tier": "standard"
    },
    "GoDaddy Email": {
        "spf": ["secureserver.net"],
        "mx": ["secureserver.net"],
        "dkim_selectors": ["default"],
        "dkim_cname": ["secureserver.net"],
        "category": "workspace", "tier": "budget"
    },
}


# ============================================================================
# DOMAIN UTILITIES
# ============================================================================

def normalize_domain(input_str: str) -> Optional[str]:
    """Extract and normalize domain from URL, email, or raw domain."""
    if not input_str or not isinstance(input_str, str):
        return None
    
    input_str = input_str.strip().lower()
    if not input_str:
        return None
    
    # Handle emails
    if '@' in input_str and '/' not in input_str:
        input_str = input_str.split('@')[-1]
    
    # Add scheme for parsing
    if not input_str.startswith(('http://', 'https://')):
        input_str = 'http://' + input_str
    
    try:
        parsed = urlparse(input_str)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        domain = domain.split(':')[0]  # Remove port
        
        if '.' not in domain or len(domain) < 3:
            return None
        
        return domain
    except:
        return None


def find_domain_column(df: pd.DataFrame) -> Optional[str]:
    """Auto-detect domain column in DataFrame."""
    keywords = ['domain', 'website', 'url', 'site', 'web', 'link']
    
    for col in df.columns:
        for kw in keywords:
            if kw in col.lower():
                return col
    
    # Check content
    for col in df.columns:
        sample = df[col].dropna().head(10).astype(str)
        if sum(1 for v in sample if normalize_domain(v)) >= 5:
            return col
    
    return df.columns[0] if len(df.columns) > 0 else None


# ============================================================================
# ESP DETECTOR ENGINE
# ============================================================================

@dataclass
class ESPResult:
    domain: str
    esps: list = field(default_factory=list)
    confidence: str = "none"
    evidence: dict = field(default_factory=dict)
    raw_dns: dict = field(default_factory=dict)
    error: str = ""
    
    def to_dict(self):
        return {
            "domain": self.domain,
            "esps_detected": ", ".join(self.esps) or "Unknown",
            "esp_count": len(self.esps),
            "confidence": self.confidence,
            "primary_esp": self.esps[0] if self.esps else "Unknown",
            "has_klaviyo": "Klaviyo" in self.esps,
            "has_omnisend": "Omnisend" in self.esps,
            "has_mailchimp": "Mailchimp" in self.esps,
            "category": ESP_SIGNATURES.get(self.esps[0], {}).get("category", "") if self.esps else "",
            "tier": ESP_SIGNATURES.get(self.esps[0], {}).get("tier", "") if self.esps else "",
            "evidence": str(self.evidence),
            "error": self.error,
        }


class ESPDetector:
    def __init__(self, timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    
    def _query(self, domain: str, rtype: str) -> list:
        try:
            return [str(r) for r in self.resolver.resolve(domain, rtype)]
        except:
            return []
    
    def _check_dkim(self, domain: str, selectors: list) -> dict:
        found = {}
        for sel in selectors[:2]:  # Limit to avoid slowdown
            dkim_domain = f"{sel}._domainkey.{domain}"
            for rtype in ['CNAME', 'TXT']:
                records = self._query(dkim_domain, rtype)
                if records:
                    found[sel] = records
                    break
        return found
    
    def detect(self, domain: str) -> ESPResult:
        result = ESPResult(domain=domain)
        
        if not domain:
            result.error = "Invalid domain"
            return result
        
        try:
            # Get DNS records
            mx = self._query(domain, 'MX')
            txt = self._query(domain, 'TXT')
            
            result.raw_dns = {'MX': mx, 'TXT': txt}
            spf = [r for r in txt if 'v=spf1' in r.lower()]
            
            matches = {}
            
            for esp, sigs in ESP_SIGNATURES.items():
                evidence = []
                
                # SPF check
                for spf_rec in spf:
                    for sig in sigs.get('spf', []):
                        if sig.lower() in spf_rec.lower():
                            evidence.append(f"SPF: {sig}")
                
                # MX check
                mx_str = ' '.join(mx).lower()
                for sig in sigs.get('mx', []):
                    if sig.lower() in mx_str:
                        evidence.append(f"MX: {sig}")
                
                # DKIM for key ESPs (avoid too many queries)
                if evidence or esp in ["Klaviyo", "Omnisend", "Mailchimp", "SendGrid", "HubSpot"]:
                    dkim = self._check_dkim(domain, sigs.get('dkim_selectors', []))
                    for sel, recs in dkim.items():
                        for cname in sigs.get('dkim_cname', []):
                            if any(cname.lower() in r.lower() for r in recs):
                                evidence.append(f"DKIM: {sel}")
                
                if evidence:
                    matches[esp] = evidence
            
            if matches:
                sorted_matches = sorted(matches.items(), key=lambda x: len(x[1]), reverse=True)
                result.esps = [e for e, _ in sorted_matches]
                result.evidence = dict(sorted_matches)
                
                max_ev = len(sorted_matches[0][1])
                result.confidence = "high" if max_ev >= 3 else "medium" if max_ev >= 2 else "low"
            
        except Exception as e:
            result.error = str(e)
        
        return result


def process_batch(domains: list, progress_cb=None, workers: int = 20) -> list:
    """Process domains concurrently."""
    detector = ESPDetector()
    results = []
    
    # Dedupe
    seen = set()
    unique = [normalize_domain(d) for d in domains if normalize_domain(d) and normalize_domain(d) not in seen and not seen.add(normalize_domain(d))]
    
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(detector.detect, d): d for d in unique}
        
        for i, future in enumerate(as_completed(futures)):
            try:
                results.append(future.result(timeout=10))
            except Exception as e:
                results.append(ESPResult(domain=futures[future], error=str(e)))
            
            if progress_cb:
                progress_cb((i + 1) / len(unique))
    
    return results


# ============================================================================
# STREAMLIT UI
# ============================================================================

def main():
    st.set_page_config(page_title="ESP Detector", page_icon="📧", layout="wide")
    
    st.title("📧 ESP Detector")
    st.caption("Detect Email Service Providers via DNS analysis • Supports 1-100k+ domains")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        workers = st.slider("Concurrent lookups", 5, 50, 20)
        
        st.markdown("---")
        st.metric("ESPs in Database", len(ESP_SIGNATURES))
        
        cats = {}
        for e, d in ESP_SIGNATURES.items():
            c = d.get('category', 'other')
            cats[c] = cats.get(c, 0) + 1
        for c, n in sorted(cats.items()):
            st.caption(f"{c.title()}: {n}")
    
    # Input
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Single Domain")
        single = st.text_input("Domain or URL", placeholder="pinklily.com")
        if st.button("🔍 Check", type="primary") and single:
            norm = normalize_domain(single)
            if norm:
                with st.spinner(f"Analyzing {norm}..."):
                    r = ESPDetector().detect(norm)
                
                if r.esps:
                    st.success(f"**Found:** {', '.join(r.esps)}")
                    st.info(f"**Confidence:** {r.confidence}")
                    
                    if "Klaviyo" in r.esps:
                        st.warning("⭐ Klaviyo user - good prospect!")
                    
                    with st.expander("Evidence"):
                        st.json(r.evidence)
                else:
                    st.warning("No ESP detected")
                    with st.expander("Raw DNS"):
                        st.json(r.raw_dns)
            else:
                st.error("Invalid domain")
    
    with col2:
        st.subheader("Bulk Upload")
        file = st.file_uploader("CSV file", type=['csv'])
    
    # Bulk processing
    if file:
        df = pd.read_csv(file)
        st.success(f"Loaded {len(df)} rows")
        
        col = find_domain_column(df)
        col = st.selectbox("Domain column", df.columns.tolist(), 
                          index=df.columns.tolist().index(col) if col else 0)
        
        st.dataframe(df.head())
        
        if st.button("🚀 Process All", type="primary"):
            domains = df[col].dropna().astype(str).tolist()
            
            progress = st.progress(0)
            status = st.empty()
            
            start = time.time()
            results = process_batch(domains, 
                                   progress_cb=lambda p: (progress.progress(p), status.text(f"{int(p*100)}%")),
                                   workers=workers)
            elapsed = time.time() - start
            
            rdf = pd.DataFrame([r.to_dict() for r in results])
            
            # Stats
            st.markdown("---")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Processed", len(rdf))
            detected = len(rdf[rdf['esp_count'] > 0])
            c2.metric("Detected", f"{detected} ({detected/len(rdf)*100:.0f}%)")
            c3.metric("Klaviyo Users", len(rdf[rdf['has_klaviyo']]))
            c4.metric("Time", f"{elapsed:.1f}s")
            
            # Distribution
            esp_counts = {}
            for esps in rdf['esps_detected']:
                for e in str(esps).split(', '):
                    if e and e != 'Unknown':
                        esp_counts[e] = esp_counts.get(e, 0) + 1
            
            if esp_counts:
                st.bar_chart(pd.DataFrame(
                    sorted(esp_counts.items(), key=lambda x: x[1], reverse=True)[:15],
                    columns=['ESP', 'Count']
                ).set_index('ESP'))
            
            # Results table
            st.dataframe(rdf[['domain', 'esps_detected', 'confidence', 'has_klaviyo', 'category', 'tier']])
            
            # Downloads
            buf = io.StringIO()
            rdf.to_csv(buf, index=False)
            st.download_button("📥 Download All Results", buf.getvalue(), 
                             f"esp_results_{int(time.time())}.csv", "text/csv")
            
            klaviyo_df = rdf[rdf['has_klaviyo']]
            if len(klaviyo_df) > 0:
                kbuf = io.StringIO()
                klaviyo_df.to_csv(kbuf, index=False)
                st.download_button("⭐ Download Klaviyo Users", kbuf.getvalue(),
                                 f"klaviyo_prospects_{int(time.time())}.csv", "text/csv")


if __name__ == "__main__":
    main()
