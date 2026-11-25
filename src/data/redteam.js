// RT learning-roadmap data (static, trusted content). Educational; authorized testing only.
/* =========================================================================
   VAINQUEURES RT ROADMAP (STAGE 01 - STAGE 05 PURPLE TEAM FULL)
   ========================================================================= */

export const rtRoadmapData = {
  1: {
    stage: "STAGE 01 • FOUNDATIONAL RECON",
    title: "OSINT, Attack Surface Mapping & Web VAPT",
    desc: "Master external footprinting, passive and active DNS mapping, and OWASP Top 10 vulnerabilities.",
    tools: "Nmap, Burp Suite Pro, Amass, Gobuster, SQLmap",
    benchmarks: ["Certified Ethical Hacker (CEH) syllabus equivalency", "Comprehensive external attack surface mapping", "Authenticated business-logic flaw identification"]
  },
  2: {
    stage: "STAGE 02 • LOCAL EXPLOITATION",
    title: "Privilege Escalation & Credential Extraction",
    desc: "Escalate foothold access to root/SYSTEM across heterogeneous Linux and Windows servers.",
    tools: "LinPEAS, WinPEAS, Mimikatz, BloodHound, Chisel",
    benchmarks: ["Offensive Security Certified Professional (OSCP)", "UAC constraint bypassing", "Extraction of LSASS process secrets and hash dumping"]
  },
  3: {
    stage: "STAGE 03 • DOMAIN ADVERSARY",
    title: "Active Directory Abuse & C2 Orchestration",
    desc: "Lateral movement, Kerberos ticket forgery (Golden/Silver Tickets), and resilient C2 channels.",
    tools: "Cobalt Strike, Havoc, Rubeus, Impacket, Certipy",
    benchmarks: ["Certified Red Team Operator (CRTO)", "Execution of Kerberoasting and DCSync operations", "Deployment of multi-tier redirectors using CDN domain fronting"]
  },
  4: {
    stage: "STAGE 04 • LEAD OPERATOR",
    title: "EDR Evasion & Full Adversary Emulation",
    desc: "Author custom shellcode loaders in C/Rust, defeat modern EDR hooks with direct syscalls, and conduct full adversary campaigns.",
    tools: "Custom C/Rust loaders, Syswhispers3, Donut, Sliver",
    benchmarks: ["Certified V-RT Lead Operator credential", "Bypass in-memory API hooks and ETW telemetry", "Lead enterprise multi-week adversary simulations"]
  },
  5: {
    stage: "STAGE 05 • PURPLE TEAM",
    title: "Detection Engineering, Reporting & Leadership",
    desc: "Turn offensive findings into detections, measure coverage against MITRE ATT&CK and brief executives.",
    tools: "Sigma, Atomic Red Team, MITRE ATT&CK Navigator, Velociraptor, Elastic/Splunk",
    benchmarks: ["Write and validate Sigma rules for emulated techniques", "Produce an ATT&CK coverage heatmap", "Deliver executive and technical reports with remediation tracking"]
  }
};

export const ENR = {
  1: { dur: '6-8 weeks', pre: 'Networking, Linux, HTTP basics', cap: 'Scoped external assessment report on a lab target', det: 'WAF and web-log anomaly alerts, rate limits', role: 'Junior Pentester' },
  2: { dur: '8-10 weeks', pre: 'Stage 01 + Windows/Linux internals', cap: 'Lab host privilege-escalation write-up with fixes', det: 'Sysmon/auditd alerts, LSASS access monitoring', role: 'Pentester' },
  3: { dur: '10-12 weeks', pre: 'Stage 02 + Active Directory fundamentals', cap: 'AD lab compromise path with attack graph and mitigations', det: 'Kerberos anomaly detection, tiered admin model', role: 'Red Team Operator' },
  4: { dur: '12+ weeks', pre: 'Stage 03 + C/Rust or Go basics', cap: 'Authorised multi-week emulation plan and debrief', det: 'EDR telemetry tuning, ETW and call-stack analytics', role: 'Lead Operator' },
  5: { dur: '6-8 weeks', pre: 'Any offensive stage + SIEM basics', cap: 'Detection pack plus ATT&CK coverage report', det: 'Purple-team exercises with measurable coverage', role: 'Detection Engineer / Purple Team Lead' }
};
