// Academy curriculum data (static, trusted, authored content; may contain simple HTML markup).
/* =========================================================================
   VAINQUEURES ACADEMY DATA (12 CURRICULAR CATEGORIES FULL + QUIZ ENGINE)
   ========================================================================= */

const ul = a => '<ul class="list-disc pl-5 space-y-2 text-xs sm:text-sm text-neutral-700 mt-2">' + a.map(x => '<li>' + x + '</li>').join('') + '</ul>';

export const curriculumData = [
  {
    id: "cat-1",
    name: "1. Cybersecurity Fundamentals",
    lessons: [
      {
        title: "CIA Triad & Threat Modeling",
        level: "Beginner",
        time: "5 min",
        objectives: "Understand Confidentiality, Integrity, and Availability; distinguish threats, vulnerabilities, and business risks.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            The CIA Triad forms the bedrock of information security:
          </p>
          <ul class="list-disc pl-5 space-y-2 text-xs sm:text-sm text-neutral-700 mt-2">
            <li><strong>Confidentiality:</strong> Preventing unauthorized information disclosure through AES encryption, access controls, and least-privilege tokens.</li>
            <li><strong>Integrity:</strong> Protecting data accuracy against unauthorized modification via cryptographic hashing (SHA-256) and digital signatures.</li>
            <li><strong>Availability:</strong> Ensuring authorized personnel have timely access via high-availability clustering, DDoS mitigation, and tested backups.</li>
          </ul>
          <div class="mt-4 p-4 rounded-xl bg-apple-surface border border-apple-border text-xs">
            <strong>Equation:</strong> Risk = Likelihood (Threat executing against Vulnerability) &times; Business Impact.
          </div>
        `,
        quiz: {
          q: "Which element of the CIA Triad is compromised during a successful Ransomware data-encryption attack?",
          opts: ["Availability & Confidentiality", "Confidentiality only", "Physical wiring only"],
          correct: 0,
          exp: "Ransomware denies access to data (Availability) and frequently exfiltrates secrets for double-extortion (Confidentiality)."
        }
      }
    ]
  },
  {
    id: "cat-2",
    name: "2. Networking Fundamentals",
    lessons: [
      {
        title: "TCP 3-Way Handshake & SYN Floods",
        level: "Intermediate",
        time: "7 min",
        objectives: "Analyze TCP transmission states, packet header flags, and DoS mitigation strategies.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            TCP initiates stateful sessions through SYN &rarr; SYN-ACK &rarr; ACK handshakes.
          </p>
          <div class="my-4 p-4 rounded-2xl bg-apple-surface border border-apple-border">
            <svg viewBox="0 0 600 130" class="w-full font-mono text-xs">
              <text x="50" y="20" fill="#1D1D1F" font-weight="bold">Client Host</text>
              <text x="450" y="20" fill="#1D1D1F" font-weight="bold">Server Port 443</text>
              <line x1="80" y1="30" x2="80" y2="120" stroke="#CBD5E1" stroke-dasharray="3" />
              <line x1="490" y1="30" x2="490" y2="120" stroke="#CBD5E1" stroke-dasharray="3" />
              <line x1="80" y1="50" x2="490" y2="65" stroke="#2563EB" stroke-width="2" />
              <text x="210" y="55" fill="#2563EB">1. SYN (seq=100)</text>
              <line x1="490" y1="75" x2="80" y2="90" stroke="#059669" stroke-width="2" />
              <text x="200" y="80" fill="#059669">2. SYN-ACK (ack=101)</text>
              <line x1="80" y1="100" x2="490" y2="115" stroke="#1D1D1F" stroke-width="2" />
              <text x="210" y="105" fill="#1D1D1F">3. ACK (ack=301)</text>
            </svg>
          </div>
          <p class="text-xs text-neutral-600">During a SYN Flood attack, attackers deliberately withhold the final ACK packet, exhausting server kernel connection backlogs. Enable <code>SYN Cookies</code> to mitigate this vulnerability.</p>
        `,
        quiz: {
          q: "What Linux kernel defense technique mitigates TCP SYN flood backlog exhaustion without allocating state memory?",
          opts: ["SYN Cookies", "Disabling Port 443", "Rebooting the server"],
          correct: 0,
          exp: "SYN Cookies encode connection state into the initial sequence number, requiring zero half-open memory allocation on the server."
        }
      }
    ]
  },
  {
    id: "cat-3",
    name: "3. Linux & Command Line Security",
    lessons: [
      {
        title: "Auditing SUID Permissions & Least Privilege",
        level: "Intermediate",
        time: "6 min",
        objectives: "Locate dangerous setuid binaries and understand Linux permission bits.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            The SUID (Set User ID) bit allows a regular user to execute a binary with the permissions of the file owner (frequently <code>root</code>).
          </p>
          <div class="my-3 p-3 rounded-xl bg-apple-surface border border-apple-border font-mono text-xs">
            <code>find / -perm -4000 -type f 2>/dev/null</code>
          </div>
          <p class="text-xs text-neutral-600">If utilities such as <code>find</code>, <code>vim</code>, or <code>nmap</code> have SUID flags set, local users can break out into an unrestricted root shell (GTFOBins).</p>
        `,
        quiz: {
          q: "What permission bit octal represents SUID in Linux chmod commands?",
          opts: ["4000", "2000", "1000"],
          correct: 0,
          exp: "4000 represents SUID, 2000 is SGID (Set Group ID), and 1000 is the Sticky Bit."
        }
      }
    ]
  },
  {
    id: "cat-4",
    name: "4. Web Application Security (OWASP Top 10)",
    lessons: [
      {
        title: "Broken Access Control (A01:2021) & IDOR",
        level: "Advanced",
        time: "8 min",
        objectives: "Understand Insecure Direct Object References and enforce server-side authorization matrices.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            Broken Access Control remains the #1 vulnerability on the OWASP Top 10. IDOR occurs when an application exposes a database key in the URL:
          </p>
          <div class="p-3 bg-apple-surface rounded-xl font-mono text-xs my-2">
            GET /api/v1/invoices/9021 &rarr; Attacker modifies to: /api/v1/invoices/9022
          </div>
          <p class="text-xs text-neutral-600">If the server fails to verify that user 9021 owns invoice 9022, private customer records are leaked. Enforce role-based access checks at every API endpoint handler.</p>
        `,
        quiz: {
          q: "Where must access control verification take place to prevent IDOR vulnerabilities?",
          opts: ["Server-side API handlers", "Client-side JavaScript only", "HTML button disable attributes"],
          correct: 0,
          exp: "Client-side restrictions can be bypassed using tools like Burp Suite. Authorization must be enforced strictly on the server."
        }
      }
    ]
  },
  {
    id: "cat-5",
    name: "5. Phishing & Online Scams",
    lessons: [
      {
        title: "Synthetic Domain Infrastructure & Typo Lures",
        level: "Beginner",
        time: "6 min",
        objectives: "Recognize how modern phishing syndicates deploy multi-layered regional lures.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            Many campaigns avoid crude, easily spotted domains. Instead, threat actors combine regional acronyms (<code>ap-my1.com</code>), sub-path typos (<code>/aplly</code>), and abuse-tolerant ("bulletproof") hosting to slow down takedowns and blocklists.
          </p>
          <div class="p-4 rounded-xl bg-apple-surface border border-apple-border text-xs space-y-1">
            <strong>Anatomy of a Scam:</strong>
            <p>1. SMS broadcast announcing an unclaimed financial aid or bonus.</p>
            <p>2. Link redirects to synthetic lookalike portal with banking icons.</p>
            <p>3. Dynamic credential harvester captures username, password, and triggers an instantaneous OTP request to the victim's phone.</p>
          </div>
        `,
        quiz: {
          q: "Why do attackers use URLs like ap-my1.com/aplly instead of official domains?",
          opts: ["To impersonate regional authority while avoiding exact keyword blocks", "Because it is faster to register", "To improve Google ranking"],
          correct: 0,
          exp: "Synthetic domains combine brand familiarity with slight spelling alterations to bypass basic string checks."
        }
      }
    ]
  },
  {
    id: "cat-6",
    name: "6. Ethical Hacking & Pentesting",
    lessons: [
      {
        title: "Reconnaissance & Responsible Disclosure",
        level: "Intermediate",
        time: "7 min",
        objectives: "Master active/passive recon methodologies within clear legal frameworks.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            Ethical hacking requires explicit written authorization (Rules of Engagement). Passive recon collects intelligence without sending packets to target systems (WHOIS, crt.sh, Shodan). Active recon sends probes (Nmap port scanning).
          </p>
        `,
        quiz: {
          q: "What differentiates ethical penetration testing from illegal unauthorized access?",
          opts: ["Explicit written authorization and defined Rules of Engagement", "Using Kali Linux", "Publishing bugs on social media"],
          correct: 0,
          exp: "Written permission and strict legal boundaries separate authorized penetration testing from criminal activity."
        }
      }
    ]
  },
  {
    id: "cat-7",
    name: "7. Cryptography & PKI",
    lessons: [
      {
        title: "Symmetric vs Asymmetric Encryption & TLS",
        level: "Intermediate",
        time: "7 min",
        objectives: "Differentiate AES from RSA/ECC and explain how HTTPS secures browser sessions.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            HTTPS uses asymmetric encryption (RSA/ECDSA) to exchange ephemeral session keys, followed by high-speed symmetric encryption (AES-256-GCM) for bulk data transmission.
          </p>
        `,
        quiz: {
          q: "Which cipher type is utilized for bulk web session traffic after the TLS handshake concludes?",
          opts: ["Symmetric Encryption (e.g. AES-256)", "Asymmetric RSA only", "Plaintext MD5"],
          correct: 0,
          exp: "Symmetric ciphers like AES are thousands of times faster than asymmetric ciphers, making them ideal for bulk payload encryption."
        }
      }
    ]
  },
  {
    id: "cat-8",
    name: "8. Digital Forensics & Incident Response",
    lessons: [
      {
        title: "Evidence Preservation & Order of Volatility",
        level: "Advanced",
        time: "8 min",
        objectives: "Preserve forensic evidence following RFC 3227 standards.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            RFC 3227 Order of Volatility: CPU registers/cache &rarr; Routing tables / ARP / RAM &rarr; Temporary file systems &rarr; Hard disks &rarr; Archival media.
          </p>
          <div class="p-3 rounded-xl bg-apple-surface border border-apple-border text-xs font-semibold text-rose-700">
            Crucial Rule: Do NOT reboot an infected workstation. Live malware injection, process tokens, and decrypted keys disappear when power is lost.
          </div>
        `,
        quiz: {
          q: "What is the most volatile tier of memory during an incident response investigation?",
          opts: ["CPU Registers & Cache / RAM", "Hard disk drives", "Printed server logs"],
          correct: 0,
          exp: "CPU registers, cache, and system RAM are immediately wiped upon machine reboot or power loss."
        }
      }
    ]
  },
  {
    id: "cat-9",
    name: "9. CTF & Practical Challenges",
    lessons: [
      {
        title: "Binary Analysis, Strings & Header Magic Bytes",
        level: "Intermediate",
        time: "6 min",
        objectives: "Inspect binary files and identify signatures using file headers.",
        content: `
          <p class="text-sm text-apple-textSecondary leading-relaxed">
            File extensions can be easily faked. Forensic analysts rely on magic bytes (the first few bytes of a file) to determine authentic formats:
          </p>
          <div class="p-3 bg-apple-surface rounded-xl font-mono text-xs space-y-1 my-2">
            <p>• PNG: <code>89 50 4E 47 0D 0A 1A 0A</code></p>
            <p>• PDF: <code>25 50 44 46</code> (%PDF)</p>
            <p>• ELF Linux: <code>7F 45 4C 46</code></p>
          </div>
        `,
        quiz: {
          q: "What tool allows a security analyst to extract human-readable text sequences from an unknown binary?",
          opts: ["strings", "rm -rf", "ping"],
          correct: 0,
          exp: "The 'strings' command prints sequences of printable characters from binary files."
        }
      }
    ]
  }
];

// Pelajaran Tambahan (Category 1 - 9 Extended)
const LS = [
  [0,'Defense in Depth & Security Controls','Beginner','5 min','Explain layered defence and the three control types.',['<strong>Layers:</strong> people, process and technology so one failure is not a breach.','<strong>Types:</strong> preventive (firewall), detective (SIEM alert), corrective (backup restore).','<strong>Least privilege + segmentation</strong> shrink the blast radius.'],'Which is a DETECTIVE control?',['SIEM alert rule','Door lock','Backup restore'],0,'A SIEM alert detects events after they happen.'],
  [1,'DNS, HTTP & TLS: How a Page Really Loads','Beginner','6 min','Trace a page load and see where attackers hide.',['<strong>DNS</strong> turns a name into an IP; spoofed or lookalike domains abuse this step.','<strong>TLS</strong> encrypts transport but does not prove the site is honest.','Always read the registrable domain, not the padlock.'],'Which DNS record maps a hostname to an IPv4 address?',['A','MX','TXT'],0,'The A record maps names to IPv4 addresses.'],
  [2,'SSH Hardening & Log Auditing','Intermediate','7 min','Lock down SSH and spot brute-force attempts.',['Use key-based auth and set <code>PermitRootLogin no</code>.','Add fail2ban to ban repeated failures.','Review <code>/var/log/auth.log</code> for bursts of failed logins from one IP.'],'Which setting disables direct root SSH login?',['PermitRootLogin no','PasswordAuthentication yes','X11Forwarding yes'],0,'PermitRootLogin no blocks direct root logins.'],
  [3,'XSS, CSRF & Secure Headers','Intermediate','7 min','Prevent script injection and forged requests.',['<strong>XSS:</strong> output encoding + Content-Security-Policy.','<strong>CSRF:</strong> SameSite cookies and anti-CSRF tokens.','Headers: HSTS, X-Content-Type-Options, HttpOnly + Secure cookies.'],'Best primary defence against stored XSS?',['Output encoding + CSP','Longer passwords','Disabling ping'],0,'Encoding output and a strict CSP neutralise injected scripts.'],
  [4,'Smishing, Vishing & Malaysian Scam Patterns','Beginner','6 min','Recognise common local scam scripts.',['Parcel, LHDN refund and "account frozen" SMS lures push you to a fake link.','Fake officer calls (Macau scam) demand transfers to a "safe account".','Real organisations never ask for TAC/OTP. If money is lost, call NSRC 997 at once.'],'A caller says you are under investigation and asks you to move money to a safe account. This is...',['A Macau-scam pattern','Normal police procedure','A bank audit'],0,'Legitimate agencies never ask you to transfer money to a safe account.'],
  [5,'Rules of Engagement & Scoping','Beginner','5 min','Know what must exist before any test begins.',['Written authorisation, scope, test window and data-handling rules.','Unauthorised access is a crime (e.g., Malaysia Computer Crimes Act 1997).','Deliver a report with severity and remediation advice.'],'What must exist before a pentest starts?',['Signed authorisation and scope','A fast laptop','A public announcement'],0,'Authorisation and scope make the work legal and bounded.'],
  [6,'Hashing, Salting & Password Storage','Intermediate','7 min','Choose safe password storage.',['A hash is one-way; encryption is reversible.','A unique salt defeats rainbow tables.','Use Argon2id/bcrypt, never MD5 or SHA-1.'],'Best choice to store passwords?',['Argon2/bcrypt with salt','Plain MD5','Base64'],0,'Slow salted hashes resist offline cracking.'],
  [7,'Incident Response Lifecycle (NIST)','Intermediate','6 min','Follow the four-phase response model.',['Preparation > Detection & Analysis > Containment/Eradication/Recovery > Post-incident review.','Keep chain of custody and a written timeline.','Contain first, then eradicate.'],'What comes right after detection and analysis?',['Containment','Lessons learned','Preparation'],0,'Containment limits damage before eradication.'],
  [8,'Classic Ciphers, Encodings & Stego Basics','Beginner','6 min','Tell encodings from encryption in CTFs.',['Base64, hex and ROT13 are encodings, not encryption.','Frequency analysis breaks Caesar-style ciphers.','Check metadata and appended data (exiftool, binwalk).'],'ROT13 is...',['A reversible substitution cipher','Strong encryption','A hash'],0,'ROT13 shifts letters by 13 and is trivially reversed.']
];

// Kategori Baru (Category 10, 11, 12)
const NEWC = [
  ['10. Cloud & Container Security',[
    ['Shared Responsibility & IAM Basics','Beginner','6 min','Know who secures what in the cloud.',['The provider secures the infrastructure; you secure configuration, identities and data.','Enforce least-privilege IAM and MFA on the root account.','Never commit access keys to code.'],'Who secures customer data in IaaS?',['The customer','Only the provider','Nobody'],0,'Customers are responsible for their data and configuration.'],
    ['Misconfiguration: Public Buckets & Container Hygiene','Intermediate','7 min','Avoid the most common cloud breach causes.',['Public storage buckets leak data; scan IaC before deploy.','Use minimal, non-root images and scan them for CVEs.','Keep secrets in a vault, not environment files.'],'Top cause of cloud breaches?',['Misconfiguration','Zero-days only','Cable cuts'],0,'Misconfiguration dominates real-world cloud incidents.']]],
  ['11. Malware Analysis Basics',[
    ['Static Analysis: Hashes, Strings & Headers','Intermediate','7 min','Triage an unknown sample safely.',['Hash it and check reputation before anything else.','Strings and imports hint at capability.','Only analyse inside an isolated VM.'],'First safe step on an unknown sample?',['Hash it and check reputation','Double-click it','Email it to a friend'],0,'Hashing is passive and safe.'],
    ['Behavioural Analysis & IOCs','Advanced','8 min','Extract and share indicators responsibly.',['Sandboxes record file, registry and network activity.','IOCs: hashes, domains, mutexes. Map behaviour to MITRE ATT&CK.','Defang IOCs (hxxp, [.]) when sharing.'],'Why defang IOCs?',['Prevent accidental clicks','Make them faster','Encrypt them'],0,'Defanging stops links from being clickable by mistake.']]],
  ['12. Governance, Risk & Compliance',[
    ['Risk Assessment: Likelihood x Impact','Beginner','6 min','Score and treat risks.',['Identify assets, threats and vulnerabilities.','Risk = likelihood x impact.','Treatments: mitigate, transfer, accept, avoid.'],'Buying cyber insurance is...',['Risk transfer','Risk avoidance','Risk acceptance'],0,'Insurance transfers financial impact to a third party.'],
    ['PDPA 2010, ISO 27001 & NIST CSF','Intermediate','7 min','Match frameworks to goals.',['PDPA 2010 governs personal data in commercial transactions in Malaysia.','ISO 27001 is a certifiable ISMS standard.','NIST CSF: Identify, Protect, Detect, Respond, Recover (+Govern in 2.0).'],'Which is a certifiable standard?',['ISO 27001','NIST CSF','OWASP Top 10'],0,'Organisations can be audited and certified against ISO 27001.']]]
];

const mk = a => ({ title: a[0], level: a[1], time: a[2], objectives: a[3], content: ul(a[4]), quiz: { q: a[5], opts: a[6], correct: a[7], exp: a[8] } });

LS.forEach(a => curriculumData[a[0]].lessons.push(mk(a.slice(1))));
NEWC.forEach((c, i) => curriculumData.push({ id: 'cat-' + (10 + i), name: c[0], lessons: c[1].map(mk) }));
