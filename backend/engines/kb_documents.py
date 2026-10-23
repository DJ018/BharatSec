"""Reference notes for BharatSec AI's knowledge base (stored and searched in MongoDB Atlas).

Each note is plain text that the assistant can quote and cite. Keep notes factual, dated where the
law or guidance may change, and free of em dashes (house style).
"""
from typing import Dict, List

NOTES: List[Dict[str, str]] = [
    # ── CERT-In ───────────────────────────────────────────────────────────────
    {
        "id": "india:cert-in-directions-2022",
        "title": "CERT-In Directions of 28 April 2022 (Section 70B(6), IT Act)",
        "source": "CERT-In",
        "url": "https://www.cert-in.org.in/Directions70B.jsp",
        "text": (
            "CERT-In issued directions under Section 70B(6) of the IT Act on 28 April 2022; they came into force in June 2022. "
            "They apply to service providers, intermediaries, data centres, body corporates and government organisations. Key duties: "
            "(1) report the listed cyber incidents to CERT-In within 6 hours of noticing them or being told about them; "
            "(2) enable logs of all ICT systems and keep them securely for a rolling 180 days within Indian jurisdiction, and share them with CERT-In when asked; "
            "(3) synchronise ICT system clocks with the NTP servers of the National Informatics Centre (NIC) or the National Physical Laboratory (NPL), or with sources traceable to them; "
            "(4) designate a Point of Contact to interface with CERT-In; "
            "(5) data centres, VPS providers, cloud service providers and VPN service providers must keep validated subscriber details (names, addresses, contact numbers, purpose, IP addresses allotted) for 5 years after cancellation; "
            "(6) virtual asset service providers, exchanges and custodian wallet providers must keep KYC and transaction records for 5 years. "
            "Not complying can be punished under Section 70B(7): imprisonment up to one year, a fine up to ₹1 lakh, or both."
        ),
    },
    {
        "id": "india:cert-in-reportable-incidents",
        "title": "Which incidents must be reported to CERT-In within 6 hours",
        "source": "CERT-In",
        "url": "https://www.cert-in.org.in/Directions70B.jsp",
        "text": (
            "Annexure I of the CERT-In directions lists the reportable incident types. They include: targeted scanning or probing of critical networks; "
            "compromise of critical systems or information; unauthorised access to IT systems or data; defacement of websites or intrusion into a website and unauthorised changes "
            "such as inserting malicious code or links to external sites; malicious code attacks such as viruses, worms, Trojans, bots, spyware and ransomware; attacks on servers "
            "(database, mail, DNS) and network devices (routers); identity theft, spoofing and phishing attacks; denial of service and distributed denial of service attacks; "
            "attacks on critical infrastructure, SCADA, operational technology and wireless networks; attacks on applications such as e-governance, e-commerce and digital payments; "
            "data breach; data leak; attacks on Internet of Things devices; attacks or incidents affecting digital payment systems; attacks through malicious mobile apps; "
            "fake mobile apps; unauthorised access to social media accounts; attacks on cloud systems; and attacks on Big Data, blockchain, virtual assets, robotics, drones, "
            "3D printing, artificial intelligence and machine learning systems. "
            "Report by email to incident@cert-in.org.in or through the incident reporting form on cert-in.org.in. A first report within 6 hours can be brief; send details as the investigation continues."
        ),
    },
    # ── DPDP ──────────────────────────────────────────────────────────────────
    {
        "id": "india:dpdp-act-overview",
        "title": "Digital Personal Data Protection Act, 2023: key ideas",
        "source": "MeitY",
        "url": "https://www.meity.gov.in",
        "text": (
            "The DPDP Act, 2023 (assented on 11 August 2023) governs digital personal data processed in India, and processing outside India when it is for offering goods or services to people in India. "
            "Roles: the Data Principal is the person the data is about; the Data Fiduciary decides why and how data is processed; a Data Processor processes on a fiduciary's behalf; "
            "the government can notify Significant Data Fiduciaries with extra duties (Data Protection Officer based in India, independent data audits, periodic impact assessments). "
            "Processing needs free, specific, informed and unambiguous consent through clear notice, or a listed legitimate use. Fiduciaries must use reasonable security safeguards, "
            "notify personal data breaches, erase data when the purpose is served or consent is withdrawn, and offer grievance redressal. Children's data (under 18) needs verifiable parental consent "
            "and no tracking, behavioural monitoring or targeted advertising aimed at children. Consent Managers help people manage consents. The Data Protection Board of India enforces the Act."
        ),
    },
    {
        "id": "india:dpdp-penalties",
        "title": "DPDP Act penalties (Schedule)",
        "source": "DPDP Act, 2023",
        "url": "https://www.meity.gov.in",
        "text": (
            "The Schedule to the DPDP Act sets maximum penalties per instance: up to ₹250 crore for failing to take reasonable security safeguards to prevent a personal data breach; "
            "up to ₹200 crore for failing to notify the Data Protection Board and affected Data Principals of a breach; up to ₹200 crore for breaching the additional obligations for children; "
            "up to ₹150 crore for breaching the additional obligations of Significant Data Fiduciaries; up to ₹10,000 for a Data Principal who breaches their own duties (for example filing false complaints); "
            "and up to ₹50 crore for breaching any other provision or the Rules. The Board considers the nature, gravity and duration of the breach, mitigation and repetition when deciding the amount."
        ),
    },
    {
        "id": "india:dpdp-rules-2025",
        "title": "DPDP Rules, 2025: breach notification and timelines",
        "source": "MeitY",
        "url": "https://www.meity.gov.in",
        "text": (
            "The Digital Personal Data Protection Rules were notified in November 2025 with a phased start: Data Protection Board provisions applied at once, the Consent Manager framework "
            "after about 12 months, and most fiduciary obligations (notice, security safeguards, breach intimation, retention and erasure) after about 18 months. "
            "On a personal data breach a Data Fiduciary must inform each affected Data Principal without delay, in plain language, describing the breach, likely consequences, mitigation steps "
            "and a contact; and inform the Data Protection Board without delay, followed by a detailed report (facts, cause, mitigation, the person responsible if known, and the notices sent) within 72 hours "
            "unless the Board allows more time. Reasonable security safeguards in the Rules include encryption, obfuscation or masking, access control, logging and monitoring of access, "
            "backups for continuity, and keeping logs and related data for at least one year to detect and investigate unauthorised access. "
            "Check the latest MeitY notifications for exact commencement dates because timelines can be amended."
        ),
    },
    # ── IT Act and rules ──────────────────────────────────────────────────────
    {
        "id": "india:it-act-sections",
        "title": "IT Act, 2000: sections security teams meet most often",
        "source": "IT Act, 2000",
        "url": "https://www.indiacode.nic.in",
        "text": (
            "Section 43: penalty and compensation for unauthorised access, downloading, introducing viruses, damage or disruption. "
            "Section 43A: compensation when a body corporate negligently fails to protect sensitive personal data (the DPDP Act omits 43A once its provisions are in force). "
            "Section 66: computer-related offences (acts in Section 43 done dishonestly or fraudulently). Section 66B: receiving stolen computer resources. Section 66C: identity theft, "
            "such as using someone's password or electronic signature. Section 66D: cheating by personation using a computer resource (common in phishing and fake customer-care fraud). "
            "Section 66E: violation of privacy through images. Section 66F: cyber terrorism. Section 67 and 67A: obscene and sexually explicit material. "
            "Section 69: interception, monitoring and decryption by government. Section 70: protected systems (critical information infrastructure). Section 70A: NCIIPC as the national nodal agency for CII protection. "
            "Section 70B: CERT-In as the national agency for incident response. Section 72A: disclosure of personal information in breach of a lawful contract. Section 79: intermediary safe harbour subject to due diligence."
        ),
    },
    {
        "id": "india:spdi-rules-2011",
        "title": "SPDI Rules 2011 and 'reasonable security practices'",
        "source": "IT Rules, 2011",
        "url": "https://www.meity.gov.in",
        "text": (
            "The Information Technology (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules, 2011 define sensitive personal data "
            "(passwords, financial information, health data, biometrics, sexual orientation) and require a documented information security programme. ISO/IEC 27001 is named as one "
            "standard that satisfies 'reasonable security practices', with periodic audits. These rules sit under Section 43A, so they are being replaced by the DPDP framework as it comes into force."
        ),
    },
    # ── Sector regulators ─────────────────────────────────────────────────────
    {
        "id": "india:sebi-cscrf",
        "title": "SEBI Cybersecurity and Cyber Resilience Framework (CSCRF)",
        "source": "SEBI",
        "url": "https://www.sebi.gov.in",
        "text": (
            "SEBI issued the Cybersecurity and Cyber Resilience Framework (CSCRF) in August 2024 for its regulated entities (stock brokers, depositories, mutual funds, portfolio managers, "
            "investment advisers and others), replacing earlier separate circulars. It is graded by entity category and is built around governance, identify, protect, detect, respond and recover. "
            "Expectations include an approved cybersecurity policy, asset inventory, vulnerability assessment and penetration testing (VAPT), 24x7 security monitoring through an own or market SOC, "
            "log retention, incident reporting to SEBI and CERT-In within 6 hours, cyber audits, and data localisation for specified data. Compliance was phased in through 2025; check SEBI circulars for the current dates for your category."
        ),
    },
    {
        "id": "india:rbi-cyber",
        "title": "RBI cybersecurity expectations for banks, NBFCs and payment players",
        "source": "RBI",
        "url": "https://www.rbi.org.in",
        "text": (
            "RBI requires regulated entities to run a board-approved cyber security policy and crisis management plan, separate from the broader IT policy (Cyber Security Framework for banks, June 2016). "
            "The Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices (November 2023, effective April 2024) covers IT governance, risk management, "
            "business continuity, IS audit and vendor risk for banks, NBFCs and other entities. Separate directions cover digital payment security controls and payment aggregators. "
            "Common expectations: a security operations centre or monitoring capability, regular VAPT, multi-factor authentication for privileged and customer access, fraud monitoring, "
            "and prompt reporting of cyber incidents to RBI within tight timelines, in addition to CERT-In's 6-hour rule."
        ),
    },
    {
        "id": "india:nciipc-cii",
        "title": "Critical information infrastructure and NCIIPC",
        "source": "NCIIPC",
        "url": "https://nciipc.gov.in",
        "text": (
            "Critical information infrastructure (CII) is a computer resource whose incapacitation would seriously affect national security, the economy, public health or safety. "
            "The government can declare such systems 'protected systems' under Section 70 of the IT Act; unauthorised access to a protected system can lead to imprisonment up to 10 years. "
            "The National Critical Information Infrastructure Protection Centre (NCIIPC), under Section 70A, is the nodal agency for CII sectors such as power and energy, banking and finance, "
            "telecom, transport, government and strategic enterprises. Incidents affecting CII are also reported to NCIIPC."
        ),
    },
    # ── Help for victims ──────────────────────────────────────────────────────
    {
        "id": "india:cybercrime-help",
        "title": "Reporting cybercrime and fraud in India (1930, cybercrime.gov.in, Sanchar Saathi)",
        "source": "I4C, Ministry of Home Affairs",
        "url": "https://cybercrime.gov.in",
        "text": (
            "For financial fraud call the national cybercrime helpline 1930 as soon as possible; quick reporting lets banks freeze the money trail. "
            "File a complaint on the National Cyber Crime Reporting Portal, cybercrime.gov.in, run by the Indian Cyber Crime Coordination Centre (I4C) of the Ministry of Home Affairs. "
            "Report suspected fraud calls, SMS and WhatsApp messages on the Chakshu facility of the Department of Telecommunications' Sanchar Saathi portal (sancharsaathi.gov.in), "
            "which also lets people check mobile connections registered in their name and block lost phones. Tell your bank immediately, block cards and UPI, and keep screenshots, "
            "transaction IDs, phone numbers and URLs as evidence. Organisations should also check whether the incident must be reported to CERT-In within 6 hours."
        ),
    },
    # ── Practical guidance ────────────────────────────────────────────────────
    {
        "id": "guide:startup-security-baseline",
        "title": "Security baseline for an Indian startup or SME",
        "source": "BharatSec guide",
        "url": "https://bharatsec.vercel.app",
        "text": (
            "A practical first-90-days baseline: (1) turn on phishing-resistant MFA (passkeys or authenticator apps) for email, cloud, code hosting, domain registrar and banking; "
            "(2) use a password manager and remove shared logins; (3) publish SPF, DKIM and DMARC for every domain, starting DMARC at p=none and moving to p=reject; "
            "(4) serve every site over HTTPS with HSTS and modern TLS (1.2 and 1.3 only), and add security headers such as Content-Security-Policy; "
            "(5) keep an inventory of domains, subdomains, cloud accounts and SaaS apps, and remove what is unused; (6) patch internet-facing software first, prioritising anything on the CISA KEV list; "
            "(7) block public access on cloud storage, avoid long-lived access keys, and enable cloud audit logs; (8) back up critical data with an offline or immutable copy and test restores; "
            "(9) keep logs for 180 days in India and sync clocks to NIC or NPL NTP to meet CERT-In directions; (10) write a one-page incident plan naming who reports to CERT-In within 6 hours "
            "and who informs customers under the DPDP Act. BharatSec's scanner, SOC and cloud checks cover items 3 to 7."
        ),
    },
    {
        "id": "guide:ransomware-response-india",
        "title": "First hours of a ransomware incident (Indian organisation)",
        "source": "BharatSec guide",
        "url": "https://bharatsec.vercel.app",
        "text": (
            "1. Isolate affected machines from the network (unplug or disable Wi-Fi) but do not power them off, so memory evidence survives. "
            "2. Disable compromised accounts, reset privileged and service credentials, and revoke active sessions and access keys. "
            "3. Protect backups: disconnect them and confirm they are clean before restoring. "
            "4. Report to CERT-In within 6 hours (incident@cert-in.org.in) and, for regulated sectors, to RBI, SEBI or IRDAI as required; if personal data may be affected, prepare DPDP breach notices to the Data Protection Board and affected people. "
            "5. Preserve evidence: logs, ransom notes, file samples and timelines. 6. File a police complaint through cybercrime.gov.in. "
            "7. Do not contact or pay attackers without legal advice; payment does not guarantee recovery and may breach sanctions. "
            "8. Restore from known-good backups, patch the entry point (often exposed RDP or VPN, phishing, or a KEV-listed vulnerability), and monitor for re-entry."
        ),
    },
    {
        "id": "guide:email-sender-rules",
        "title": "Email authentication requirements of Gmail, Yahoo and Microsoft",
        "source": "BharatSec guide",
        "url": "https://bharatsec.vercel.app",
        "text": (
            "Since February 2024 Gmail and Yahoo require all senders to have SPF or DKIM and valid forward and reverse DNS, and bulk senders (around 5,000 or more messages a day to Gmail) "
            "to have SPF, DKIM and a DMARC policy (p=none at minimum) with alignment, plus one-click unsubscribe and low spam rates. Microsoft announced similar rules for Outlook.com consumer "
            "addresses in 2025. Domains without these records see mail rejected or sent to spam, and are easier to spoof in phishing. BharatSec's domain scan checks SPF, DKIM and DMARC."
        ),
    },
    # ── BharatSec itself ──────────────────────────────────────────────────────
    {
        "id": "bharatsec:platform",
        "title": "What BharatSec does",
        "source": "BharatSec",
        "url": "https://bharatsec.vercel.app",
        "text": (
            "BharatSec is an India-built cyber risk intelligence platform. Domain Scanner: passive checks of DNS, WHOIS, email authentication (SPF, DKIM, DMARC), SSL/TLS, HTTP security headers "
            "and subdomains, producing a 0 to 100 score, severity-rated findings, a prioritised fix list and attack-path explanations. BharatSec AI and the scan Copilot explain results and answer "
            "security questions. SOC: website and asset monitoring, alerts and incident tracking. Threat Intel: CISA Known Exploited Vulnerabilities and other feeds mapped to MITRE ATT&CK, plus breach watch. "
            "Cloud: read-only posture checks for AWS, Azure and Google Cloud. Risk: turns findings into expected annual loss in rupees. Scans are passive; only scan domains you own or are authorised to assess."
        ),
    },
    {
        "id": "bharatsec:risk-method",
        "title": "How BharatSec estimates risk in rupees",
        "source": "BharatSec",
        "url": "https://bharatsec.vercel.app",
        "text": (
            "BharatSec Risk follows the idea behind the FAIR model: annualised loss expectancy equals how often a loss event is likely per year multiplied by the expected cost of one event. "
            "Findings from scans and cloud checks raise or lower the likelihood of scenarios such as email spoofing, website compromise, data breach or downtime, and impact estimates use the "
            "organisation's size and sector. The output is an expected annual loss in rupees with the scenarios that drive it, so leadership can compare the cost of fixes with the risk they remove. "
            "Treat the figures as estimates for prioritisation, not actuarial quotes."
        ),
    },
]
