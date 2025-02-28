# Device Accidentally Exposed to the Internet

**Author:** [Your Name]  
**Date:** [Date]  
**Category:** Threat Hunting  

---

## 🛠️ Scenario Overview
During routine security maintenance, the security team was tasked with investigating any VMs in the shared services cluster that might have been mistakenly exposed to the public internet. The focus was on identifying misconfigured VMs and checking for potential brute-force login attempts from external sources.

## 🔍 Hypothesis
- If a VM was exposed to the internet, there is a possibility that attackers attempted brute-force login attempts.
- Older devices lacking account lockout policies might be at higher risk of a successful attack.

---

## 📊 Data Collection

### 📝 Query 1: Identify Internet-Facing Devices
```kql
DeviceInfo
| where DeviceName == "rich-mde-test"
| where IsInternetFacing == true
| order by Timestamp desc
```

**Findings:**
- The `rich-mde-test` VM was **not directly internet-facing** at the time of the investigation.

---

## 🚀 Data Analysis

### 📝 Query 2: Identify Failed Login Attempts from Remote IPs
```kql
DeviceLogonEvents
| where DeviceName == "rich-mde-test"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

**Findings:**
- Multiple failed login attempts were detected from **various remote IP addresses**.
- The top 3 most common attacking IPs were:
  - `185.243.96.107`
  - `31.43.185.40`
  - `31.43.185.42`

### 📝 Query 3: Check for Successful Logins from Malicious IPs
```kql
let RemoteIPsInQuestion = dynamic(["185.243.96.107","31.43.185.40", "31.43.185.42"]);
DeviceLogonEvents
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**Findings:**
- No successful logins from the identified malicious IPs.

### 📝 Query 4: Identify All Successful Logins to the VM
```kql
DeviceLogonEvents
| where DeviceName == "rich-mde-test"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize Count = count() by Account
```

**Findings:**
- The only successful remote/network logins in the last 30 days were from the `labuserich` account (6 times).
- **No failed login attempts for this account**, meaning no brute force attacks were attempted against it.

---

## ⚡ Investigation Insights
Although the `rich-mde-test` VM was not explicitly internet-facing, attackers **still attempted brute force logins** due to automated Azure IP range scanning.

### 🔎 How did attackers find the VM?
- Attackers use **automated scanners** to probe Azure’s public IP ranges.
- Even without a direct public IP, authentication logs recorded these attempts at **Azure’s authentication layer** before reaching the VM.

### 🔎 **Relevant MITRE ATT&CK TTPs**
| **TTP ID** | **Technique** | **Description** |
|------------|--------------|----------------|
| **T1595**  | **Active Scanning** | Attackers scanned Azure’s public IP ranges looking for exposed services. |
| **T1110**  | **Brute Force** | Multiple failed login attempts indicate systematic credential guessing. |

---

## 🛡️ Response & Mitigation

### ✅ **Recommended Mitigation Strategies**

#### 🔹 **To Prevent Exposure to Active Scanning (T1595)**
✔️ Restrict network exposure with **firewalls, VPNs, or load balancers**.  
✔️ Configure **Network Security Groups (NSGs)** to **allow RDP only from trusted sources**.  
✔️ Implement **intrusion detection systems (IDS/IPS)** to detect and block scanning traffic.  
✔️ Minimize exposed services by placing **critical systems behind private networks**.  

#### 🔹 **To Mitigate Brute Force Attacks (T1110)**
✔️ Enforce **Multi-Factor Authentication (MFA)** on all accounts.  
✔️ Configure **account lockout policies** to prevent repeated failed login attempts.  
✔️ Implement **Just-In-Time (JIT) access** to restrict open management ports.  
✔️ Continuously monitor authentication logs for unusual login activity.  

---

## 📚 Areas for Improvement

### 🔹 **Security Enhancements**
- Implement **proactive network segmentation** to reduce attack surfaces.
- Enhance **Azure NSG policies** to block unwanted traffic more effectively.

### 🔹 **Threat Hunting Improvements**
- Improve **KQL proficiency** for more efficient detection of attack patterns.
- Automate security monitoring with **custom alerts and SIEM integrations**.

---

## 📖 Final Summary
✅ The `rich-mde-test` VM was **targeted by automated brute-force attacks**, but no successful intrusions occurred.  
✅ Attackers leveraged **T1595 (Active Scanning)** to detect Azure VMs and **T1110 (Brute Force)** to attempt logins.  
✅ **No malicious actors successfully logged in**, but the event highlights the importance of **proactive cloud security**.  

🔐 **Next Steps:** Strengthen **network security controls**, **MFA enforcement**, and **log monitoring** to prevent future incidents.  

---

### 📌 **Repository Information**

💡 This project is designed for **educational & security research purposes**. If you're interested in **Azure security**, **threat hunting**, or **KQL**, feel free to explore and contribute!  

📁 _Repo: [GitHub Link]_  
📬 _Contact: [Your Contact]_
