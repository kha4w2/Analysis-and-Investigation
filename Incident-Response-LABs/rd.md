# Malware Containment via AppLocker Path-Based Policy Report (File System-Level Containment Implementation)

## Introduction
This report documents a practical containment procedure implemented during a simulated incident response exercise. The focus was on utilizing Windows native security controls—specifically AppLocker—to isolate and prevent execution of potentially malicious files from a suspicious directory. This approach demonstrates a targeted containment strategy that balances security with operational continuity.

## Objective
To implement and validate a path-based application containment mechanism using AppLocker, effectively preventing execution of unauthorized executables from a designated suspicious folder while maintaining normal system functionality elsewhere.

<img width="1068" height="793" alt="1" src="https://github.com/user-attachments/assets/f2c3f38c-b350-4fb6-8d84-0c32ae39ce52" />


## Containment Implementation Procedure

### **Step 1 — Creating a Suspicious Folder for Malware Containment Testing**
A new directory named **`C:\Test`** was created to simulate a malicious payload location. An executable file was placed inside the folder to serve as a test artifact representing the suspected malware.

**Path Used:** `C:\Test`
**Test Artifact:** `SuspiciousExecutable.exe`

### **Step 2 — Launching the Local Group Policy Editor to Configure AppLocker Policies**
The **Local Group Policy Editor** was opened using `gpedit.msc` to begin configuring Application Control Policies (AppLocker) required for blocking executable files within the suspicious directory.

<img width="1031" height="772" alt="2" src="https://github.com/user-attachments/assets/7b452850-1e2b-4a5b-99a5-4626b4ab22d9" />


**Command Used:** `gpedit.msc`

### **Step 3 — Navigating to AppLocker Policy Configuration**


<img width="951" height="462" alt="3" src="https://github.com/user-attachments/assets/1ebe95d3-914a-459a-b496-dc52f94543f4" />


Navigated through the Local Group Policy Editor to access **Application Control Policies → AppLocker**, where executable restrictions were created to block malicious file execution.

**Navigation Path:**
```
Computer Configuration
 → Windows Settings
   → Security Settings
     → Application Control Policies
       → AppLocker
```

### **Step 4 — Opening Services Console to Enable Application Identity Service**


<img width="1052" height="770" alt="4" src="https://github.com/user-attachments/assets/96a4f52f-a101-4dce-89f1-31d9bcac3f9a" />

<img width="1062" height="767" alt="5" src="https://github.com/user-attachments/assets/a53b9cb1-4470-4aad-9b83-74c7d2d26364" />



The **Services Management Console** was opened using `services.msc` to start the *Application Identity* service, which is required for AppLocker enforcement.

**Command Used:** `services.msc`

### **Step 5 — Enable and Start Application Identity Service (AppIDSvc)**

<img width="1022" height="417" alt="6" src="https://github.com/user-attachments/assets/24e01b10-5c1b-478a-82bf-544becbb3b29" />

The *Application Identity* service was enabled and set to start automatically. AppLocker cannot enforce any rules unless AppIDSvc is running.

**Commands Used:**
```powershell
sc.exe stop AppIDSvc
sc.exe config AppIDSvc start= auto
sc.exe start AppIDSvc
```

### **Step 6 — Configure Rule Permissions**

<img width="948" height="790" alt="7" src="https://github.com/user-attachments/assets/831117fb-c8c7-4282-8ead-02edad734204" />

Defined the action (Allow) and specified the user or group (Everyone) the AppLocker rule would apply to, establishing the baseline control before defining the matching condition.

### **Step 7 — Selecting the Rule Condition Type**

<img width="773" height="648" alt="8" src="https://github.com/user-attachments/assets/24c671ec-5a2b-4e89-ad5b-e7a3dfe1fafc" />

<img width="772" height="657" alt="9" src="https://github.com/user-attachments/assets/54b1290b-2681-4543-8276-b46935f77266" />



Determined how AppLocker would identify the executable to control—by publisher, file path, or file hash—to accurately target the intended application. Path condition was selected.

### **Step 8 — Reviewing Executable Rules Overview**

<img width="1032" height="772" alt="10" src="https://github.com/user-attachments/assets/bc8f40ca-452a-467b-9942-eff9570afd05" />

Verified that the new AppLocker rule targeting `C:\Test` appeared alongside default rules to ensure proper enforcement without affecting system files.



### **Step 9 — Enabling AppLocker Rule Enforcement**


<img width="1048" height="737" alt="11" src="https://github.com/user-attachments/assets/587250cc-8ff6-4f82-9d40-56e4ebc81bb7" />



<img width="1061" height="778" alt="12" src="https://github.com/user-attachments/assets/0463e3b3-a3b1-460a-a761-af71935159af" />

Ensured all AppLocker rules, including the new rule for `C:\Test`, were actively enforced so that unauthorized executables would be blocked.



### **Step 10 — Testing AppLocker Enforcement on Target Folder**

<img width="1068" height="793" alt="13" src="https://github.com/user-attachments/assets/13887061-663e-4e45-9fb3-5095335c30e8" />

Validated that the AppLocker rule for `C:\Test` successfully blocked execution of executables, confirming containment of potential malicious files.


**Test Executed:** Attempted to run `test.exe` via File Explorer — successfully blocked by AppLocker.

