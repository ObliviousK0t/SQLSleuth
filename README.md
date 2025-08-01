# 🔥 **SQLSleuth** – Advanced SQL Injection Scanner

```
                                       ____   ___  _     ____  _            _   _     
                                      / ___| / _ \| |   / ___|| | ___ _   _| |_| |__  
                                      \___ \| | | | |   \___ \| |/ _ \ | | | __| '_ \ 
                                       ___) | |_| | |___ ___) | |  __/ |_| | |_| | | |
                                      |____/ \__\_\_____|____/|_|\___|\__,_|\__|_| |_|
                                                 
                                    🔍  SQL Sleuth - Advanced SQL Injection Scanner  🔍
```

---

## 🕵️‍♂️ **What is SQLSleuth?**

SQLSleuth is a **next-gen SQL Injection detection tool** built in Python for **penetration testers, bug bounty hunters, and security researchers**.
It combines **stealth techniques** with **multi-threaded scanning** to uncover vulnerabilities quickly.

💡 **Think of it as your lightweight, customizable version of a SQLi framework.**

---

## 🚀 **Features**

* ✅ **Error-Based SQL Injection Detection**
* ✅ **Boolean-Based Blind SQL Injection Detection**
* ✅ **Multi-Threaded Payload Testing**
* ✅ **User-Agent Randomization**
* ✅ **Custom Payload Support**
* ✅ **Header & Cookie Injection**
* ✅ **Logging to scan\_results.txt**
* ✅ **Experimental DB Extraction Mode**
* ✅ **Stylish ASCII Banner UI**

---

## ⚠️ **Disclaimer**

> This tool is for **educational purposes** and **authorized testing** only.
> The author takes **no responsibility** for misuse.
> Use it **only** on targets you have permission to test.

---

## 🛠️ **Installation**

```bash
git clone https://github.com/YourUsername/SQLSleuth.git
cd SQLSleuth
pip install -r requirements.txt
```

---

## ▶️ **Usage Examples**

### 🔹 **Basic Scan**

```bash
python3 sqli_sleuth.py -u "http://target.com/page.php?id=1"
```

### 🔹 **Using Custom Payloads**

```bash
python3 sqli_sleuth.py -u "http://target.com/page.php?id=1" -p "custom_payloads.txt"
```

### 🔹 **Testing POST Parameters**

```bash
python3 sqli_sleuth.py -u "http://target.com/login.php" -d "username=admin&password=INJECT"
```

### 🔹 **With Cookies**

```bash
python3 sqli_sleuth.py -u "http://target.com/page.php?id=1" -c "PHPSESSID=abc123; security=low"
```

### 🔹 **Custom Headers**

```bash
python3 sqli_sleuth.py -u "http://target.com/page.php?id=1" --header "User-Agent: CustomAgent"
```

### 🔹 **Dump Mode (Experimental)**

```bash
python3 sqli_sleuth.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --dump
```

---

## 📂 **Project Structure**

```
SQLSleuth/
├── sqli_sleuth.py       # Main Scanner Script
├── payloads.txt         # Default Payloads
├── requirements.txt     # Dependencies
├── README.md            # This Legendary Readme
└── .gitignore           # Ignores logs and local files
```

---

## 🧩 **How It Works**

1. Loads payloads from `payloads.txt`
2. Sends crafted requests to the target
3. Detects anomalies:

   * Error-based SQLi
   * Boolean-based blind SQLi
4. If `--dump` is enabled, attempts database name extraction
5. Logs results in `scan_results.txt`

---

## 📌 **Example Output**

```
[i] Testing http://target.com/page.php?id=1 for SQL errors (GET)...
[+] Vulnerable! SQL error triggered with payload: '
[*] Dump mode enabled! Attempting to extract DB name...
[DUMP] Database Name: acuart
```

---

## ✅ **Future Roadmap**

* [ ] DBMS Fingerprinting (MySQL, MSSQL, Oracle, PostgreSQL)
* [ ] Table & Column Enumeration
* [ ] Proxy & Tor Support
* [ ] Interactive Exploitation Console
* [ ] Full Data Extraction Module

---

## 📜 **License**

Released under the **MIT License** – free to use, modify, and share (with attribution).

---

## ⭐ **Support the Project**

* Star ⭐ the repository if you like it
* Share with other security researchers
* Contribute payloads or new features via pull requests

---

## 👨‍💻 **Author**

**ObliviousK0t** – Security Researcher & Pentester
Follow for more open-source security tools.

---

## 🎯 **Hack Responsibly. Scan Smart. Stay Sleuthy.**
