<div align="center">

# 🛡️ Java-Based Secure Network Monitoring Dashboard

[![Java](https://img.shields.io/badge/Java-11-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-2.7.18-6DB33F?style=for-the-badge&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring_Security-JWT-6DB33F?style=for-the-badge&logo=springsecurity&logoColor=white)](https://spring.io/projects/spring-security)
[![H2 Database](https://img.shields.io/badge/H2-Database-0000BB?style=for-the-badge&logo=databricks&logoColor=white)](https://www.h2database.com/)
[![Maven](https://img.shields.io/badge/Maven-3.6+-C71A36?style=for-the-badge&logo=apachemaven&logoColor=white)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

**A production-ready enterprise network monitoring application that combines PCAP file analysis, real-time threat intelligence, and a secure web dashboard — all built on Spring Boot.**

[🚀 Quick Start](#-quick-start) •
[✨ Features](#-features) •
[🏗️ Architecture](#️-architecture) •
[📡 API Reference](#-api-reference) •
[🔒 Security](#-security) •
[🤝 Contributing](#-contributing)

---

</div>

## 📋 Table of Contents

- [Overview](#overview)
- [🚀 Quick Start](#-quick-start)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🛠️ Tech Stack](#️-tech-stack)
- [⚙️ Configuration](#️-configuration)
- [📡 API Reference](#-api-reference)
- [🔒 Security](#-security)
- [📂 Project Structure](#-project-structure)
- [🗄️ Database Schema](#️-database-schema)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## Overview

The **Secure Network Monitoring Dashboard** is a Spring Boot web application that captures and analyzes network traffic from PCAP files, identifies suspicious or malicious IPs using the [AbuseIPDB](https://www.abuseipdb.com/) threat intelligence API, and visualizes the data through an interactive web dashboard with Chart.js.

### What It Does

| Capability | Description |
|:--|:--|
| 🔍 **Packet Analysis** | Upload and parse PCAP files to extract network packet metadata |
| 🌐 **Threat Intelligence** | Check IPs against AbuseIPDB for real-time reputation scoring |
| 📊 **Visual Dashboard** | Protocol distribution charts, top traffic sources, threat analysis |
| 🔐 **Secure Access** | JWT-based authentication with account lockout protection |
| 🔔 **Alerting** | Automatic email notifications for suspicious activity |
| 🗄️ **Persistent Storage** | Encrypted packet data stored in H2 (or PostgreSQL) database |

---

## 🚀 Quick Start

<details>
<summary><b>📦 Prerequisites</b></summary>

| Requirement | Version |
|:--|:--|
| Java JDK | 11 or higher |
| Maven | 3.6+ (or use the included `mvnw` wrapper) |
| Git | Latest |

</details>

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/codesburners/Java-Based-Secure-Network-Monitoring-Dashboard.git
cd Java-Based-Secure-Network-Monitoring-Dashboard/secure-network-monitor
```

### 2️⃣ Build the Project

```bash
# Using Maven wrapper (Linux/Mac)
./mvnw clean package -DskipTests

# Using Maven wrapper (Windows)
mvnw.cmd clean package -DskipTests

# Or using system Maven
mvn clean package -DskipTests
```

### 3️⃣ Run the Application

```bash
# Option A: Maven
./mvnw spring-boot:run

# Option B: JAR
java -jar target/secure-network-monitor-1.0.0.jar
```

### 4️⃣ Access the Dashboard

| Page | URL |
|:--|:--|
| 🏠 Home | [`http://localhost:8080`](http://localhost:8080) |
| 🔑 Login | [`http://localhost:8080/login`](http://localhost:8080/login) |
| 📊 Dashboard | [`http://localhost:8080/dashboard`](http://localhost:8080/dashboard) |
| 🗄️ H2 Console | [`http://localhost:8080/h2-console`](http://localhost:8080/h2-console) |

<details>
<summary>🔑 <b>Default Credentials</b> (click to reveal)</summary>

> ⚠️ **Change these before deploying to production!** See [Security Configuration](#️-configuration).
>
> Username: `vitvellore` / Password: `hellovit`
>
> These are configured in `application.properties` via `admin.username` and `admin.password`.

</details>

---

## ✨ Features

<details>
<summary><b>🔍 Network Packet Analysis</b></summary>

- Upload `.pcap` files through the REST API or dashboard
- Extract source/destination IPs, ports, protocols (TCP/UDP), packet length, and timestamps
- Full support for IPv4 and IPv6 packets
- Parse TCP and UDP port information from packet headers

</details>

<details>
<summary><b>🌐 Threat Intelligence Integration</b></summary>

- Real-time IP reputation scoring via [AbuseIPDB API](https://www.abuseipdb.com/)
- Reputation categories:
  - 🔴 **Known Attacker** — High confidence abuse score
  - 🟡 **Suspicious** — Moderate abuse score
  - 🟢 **Benign** — Clean IP
  - ⚪ **Private** — RFC 1918 private address
  - ❓ **Check Error** — API unavailable
- Built-in IP reputation caching to avoid API rate limiting

</details>

<details>
<summary><b>📊 Interactive Dashboard</b></summary>

- **Statistics Cards** — Total packets, average packet size, threat count
- **Protocol Distribution** — Pie chart of TCP vs UDP traffic
- **Top Traffic Sources** — Bar chart of most active source IPs
- **Threat Analysis** — Visual breakdown of known attackers and suspicious IPs
- **Recent Packets Table** — View the 100 most recent captured packets
- Responsive grid layout that works on desktop and mobile

</details>

<details>
<summary><b>🔐 Enterprise Security</b></summary>

- **JWT Authentication** — Stateless token-based auth with 24-hour validity
- **BCrypt Password Hashing** — Industry-standard password storage
- **Role-Based Access Control** — `USER` and `ADMIN` roles with method-level security
- **Account Lockout** — Automatic 5-minute lockout after 3 failed login attempts
- **AES-256-GCM Encryption** — Encrypted packet data storage with KeyStore management
- **Automated Alerts** — Email notifications for suspicious IPs and lockout events

</details>

<details>
<summary><b>🔔 Alerting System</b></summary>

- Email alerts triggered on:
  - Suspicious IP detection during PCAP analysis
  - Account lockout after repeated failed logins
  - Insecure protocol usage (e.g., Telnet on port 23)
- Async/non-blocking email delivery via Spring Mail
- Configurable SMTP settings (supports Ethereal for testing)

</details>

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CLIENT (Browser)                        │
│          Login Page ◄──► Dashboard (Chart.js + Axios)       │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/HTTPS
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   SPRING BOOT APPLICATION                   │
│                                                             │
│  ┌──────────────┐  ┌─────────────────┐  ┌───────────────┐  │
│  │ Auth          │  │ Dashboard Web   │  │ Network       │  │
│  │ Controller    │  │ Controller      │  │ Monitor       │  │
│  │ (JWT Login)   │  │ (Thymeleaf)     │  │ Controller    │  │
│  └──────┬───────┘  └────────┬────────┘  └──────┬────────┘  │
│         │                   │                   │           │
│  ┌──────▼───────────────────▼───────────────────▼────────┐  │
│  │              SERVICE LAYER                            │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │  │
│  │  │ Dashboard    │ │ PCAP         │ │ Threat Intel │  │  │
│  │  │ Service      │ │ Processing   │ │ Service      │  │  │
│  │  └──────────────┘ └──────────────┘ └──────┬───────┘  │  │
│  │  ┌──────────────┐ ┌──────────────┐        │          │  │
│  │  │ Login        │ │ Alerting     │        │          │  │
│  │  │ Attempt Svc  │ │ Service      │        │          │  │
│  │  └──────────────┘ └──────────────┘        │          │  │
│  └───────────────────────┬───────────────────┤          │  │
│                          │                   │          │  │
│  ┌───────────────────────▼────────┐   ┌──────▼───────┐  │  │
│  │   SECURITY LAYER              │   │  AbuseIPDB   │  │  │
│  │  JWT Filter + Provider        │   │  REST API    │  │  │
│  │  Spring Security Config       │   └──────────────┘  │  │
│  │  Encryption Service (AES-GCM) │                     │  │
│  └───────────────────────┬───────┘                     │  │
│                          │                              │  │
│  ┌───────────────────────▼───────────────────────────┐  │  │
│  │         DATA LAYER (Spring Data JPA)              │  │  │
│  │  PacketRepository  ◄──►  H2 / PostgreSQL          │  │  │
│  └───────────────────────────────────────────────────┘  │  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

<details open>
<summary><b>Click to expand/collapse</b></summary>

| Category | Technology | Version |
|:--|:--|:--|
| **Language** | Java | 11 |
| **Framework** | Spring Boot | 2.7.18 |
| **Security** | Spring Security + JWT (JJWT) | 0.9.1 |
| **Database** | H2 (default) / PostgreSQL (optional) | — |
| **ORM** | Spring Data JPA + Hibernate | — |
| **Network Analysis** | PCAP4J | 1.8.2 |
| **Encryption** | BouncyCastle (AES-256-GCM) | 1.70 |
| **Template Engine** | Thymeleaf | — |
| **Charts** | Chart.js | Latest |
| **HTTP Client** | Axios | Latest |
| **Email** | Spring Mail | — |
| **Build Tool** | Maven | 3.6+ |
| **Testing** | Spring Boot Test + Spring Security Test | — |

</details>

---

## ⚙️ Configuration

The application is configured via `secure-network-monitor/src/main/resources/application.properties`.

<details>
<summary><b>🗄️ Database Configuration</b></summary>

```properties
# H2 (Default - file-based)
spring.datasource.url=jdbc:h2:file:./target/h2-database/mydb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=
spring.h2.console.enabled=true

# PostgreSQL (Optional - uncomment to switch)
# spring.datasource.url=jdbc:postgresql://localhost:5432/network_monitor
# spring.datasource.username=your_username
# spring.datasource.password=your_password
```

</details>

<details>
<summary><b>🔑 Security & Encryption</b></summary>

```properties
# Admin credentials (change before production!)
admin.username=<your-admin-username>
admin.password=<your-admin-password>

# KeyStore for AES-256-GCM encryption
keystore.path=/path/to/keystore.p12
keystore.password=your-keystore-password
encryption.password=your-super-secret-password-123!
```

> ⚠️ **Important:** Replace default credentials and secrets before deploying to production.

</details>

<details>
<summary><b>🌐 Threat Intelligence</b></summary>

```properties
# AbuseIPDB API (get your key at https://www.abuseipdb.com/account/api)
abuseipdb.api.key=YOUR_API_KEY_HERE
abuseipdb.api.url=https://api.abuseipdb.com/api/v2/check
```

</details>

<details>
<summary><b>📧 Email Alerts</b></summary>

```properties
# SMTP settings (example: Ethereal for testing)
spring.mail.host=smtp.ethereal.email
spring.mail.port=587
spring.mail.username=your-email@ethereal.email
spring.mail.password=your-email-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true

alert.admin.email=alerts@my-dashboard.com
```

</details>

---

## 📡 API Reference

<details>
<summary><b>🔑 Authentication</b></summary>

#### `POST /api/auth/login`

Authenticate and receive a JWT token.

**Request Body:**
```json
{
  "username": "vitvellore",
  "password": "hellovit"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Usage:** Include the token in subsequent requests:
```
Authorization: Bearer <token>
```

</details>

<details>
<summary><b>📤 PCAP Upload</b></summary>

#### `POST /api/monitor/upload`

Upload a PCAP file for analysis. **Requires `ADMIN` role.**

**Request:**
```bash
curl -X POST http://localhost:8080/api/monitor/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@capture.pcap"
```

**Response:**
```json
{
  "message": "Successfully processed 150 packets."
}
```

</details>

<details>
<summary><b>📊 Dashboard Stats</b></summary>

#### `GET /api/monitor/stats`

Retrieve aggregated dashboard statistics.

**Response:**
```json
{
  "totalPackets": 1500,
  "averagePacketSize": 512.3,
  "protocolDistribution": { "TCP": 1200, "UDP": 300 },
  "topSourceIps": [ ... ],
  "threatIps": [ ... ]
}
```

#### `GET /api/monitor/recent`

Retrieve the 100 most recent captured packets.

</details>

---

## 🔒 Security

<details open>
<summary><b>Security Features Overview</b></summary>

| Feature | Implementation |
|:--|:--|
| 🔑 **Authentication** | JWT tokens with 24-hour validity |
| 🔐 **Password Hashing** | BCrypt encoder |
| 👥 **Authorization** | Role-based (`USER`, `ADMIN`) with `@PreAuthorize` |
| 🚫 **Account Lockout** | 5-minute lockout after 3 failed login attempts |
| 🛡️ **Data Encryption** | AES-256-GCM with PKCS12 KeyStore |
| 📧 **Security Alerts** | Email notifications on lockout and threat detection |
| 🔒 **Stateless Sessions** | No server-side sessions — fully JWT-based |

</details>

<details>
<summary><b>🛡️ Security Best Practices for Production</b></summary>

- [ ] Change all default credentials (`admin.username`, `admin.password`)
- [ ] Replace the AbuseIPDB API key with your own
- [ ] Configure HTTPS/TLS termination
- [ ] Restrict H2 console access or switch to PostgreSQL
- [ ] Enable CSRF protection if serving browser-based forms
- [ ] Store secrets in environment variables or a vault (not in properties files)
- [ ] Set up proper CORS configuration for your domain
- [ ] Review and tighten Spring Security filter chains for production

</details>

---

## 📂 Project Structure

<details open>
<summary><b>Click to expand/collapse</b></summary>

```
secure-network-monitor/
├── pom.xml                          # Maven build configuration
├── mvnw / mvnw.cmd                  # Maven wrapper scripts
├── src/main/java/com/networkmonitor/secure_network_monitor/
│   ├── SecureNetworkMonitorApplication.java   # 🚀 Entry point
│   ├── config/
│   │   └── SecurityConfig.java                # Spring Security configuration
│   ├── controller/
│   │   ├── AuthController.java                # JWT login endpoint
│   │   ├── DashboardWebController.java        # Web pages (login, dashboard)
│   │   ├── NetworkMonitorController.java      # PCAP upload & stats API
│   │   └── dto/
│   │       └── AuthRequest.java               # Login request DTO
│   ├── encryption/
│   │   └── EncryptionService.java             # AES-256-GCM encryption
│   ├── entity/
│   │   └── NetworkPacket.java                 # JPA entity
│   ├── pcap/
│   │   └── PcapProcessingService.java         # PCAP file parsing
│   ├── repository/
│   │   └── PacketRepository.java              # Spring Data JPA repository
│   ├── security/
│   │   ├── AuthenticationListener.java        # Login event listener
│   │   ├── JwtTokenFilter.java                # JWT request filter
│   │   └── JwtTokenProvider.java              # JWT token utilities
│   └── service/
│       ├── AlertingService.java               # Async email alerts
│       ├── DashboardService.java              # Dashboard data aggregation
│       ├── LoginAttemptService.java           # Failed login tracking
│       └── ThreatIntelService.java            # AbuseIPDB integration
├── src/main/resources/
│   ├── application.properties                 # App configuration
│   └── templates/
│       ├── dashboard.html                     # Dashboard UI (Thymeleaf)
│       └── login.html                         # Login page
└── logs/                                      # Application logs
```

</details>

---

## 🗄️ Database Schema

<details>
<summary><b>NetworkPacket Entity</b></summary>

| Column | Type | Description |
|:--|:--|:--|
| `id` | `BIGINT` (PK) | Auto-generated primary key |
| `sourceIp` | `VARCHAR` | Source IP address |
| `destinationIp` | `VARCHAR` | Destination IP address |
| `sourcePort` | `INTEGER` | Source port number |
| `destinationPort` | `INTEGER` | Destination port number |
| `protocol` | `VARCHAR` | Protocol (TCP / UDP) |
| `length` | `INTEGER` | Packet length in bytes |
| `timestamp` | `TIMESTAMP` | Packet capture timestamp |
| `reputation` | `VARCHAR` | IP threat reputation score |
| `rawData` | `TEXT` | Encrypted raw packet data |
| `captureDate` | `TIMESTAMP` | Date of capture processing |

**Custom Queries:**
- Protocol distribution aggregation
- Top source IPs by packet count
- Top threat IPs (Known Attacker / Suspicious)
- Average packet size calculation

</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Commit** your changes
   ```bash
   git commit -m "Add amazing feature"
   ```
4. **Push** to the branch
   ```bash
   git push origin feature/amazing-feature
   ```
5. **Open** a Pull Request

<details>
<summary><b>💡 Ideas for Contribution</b></summary>

- [ ] Add unit and integration tests
- [ ] Live packet capture from network interfaces
- [ ] WebSocket-based real-time packet streaming
- [ ] Docker / Docker Compose support
- [ ] Grafana / Prometheus metrics integration
- [ ] Dark mode for the dashboard
- [ ] Export packet data as CSV/JSON
- [ ] Additional threat intelligence providers (VirusTotal, Shodan)

</details>

---



<div align="center">

**⭐ Star this repo if you find it useful!**

Built with ❤️ using Java and Spring Boot

</div>
