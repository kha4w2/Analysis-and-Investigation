<h1 align="center">🛡️ Windows Malware Eradication & DFIR Investigation Lab</h1>

---

## 🔎 Introduction

This repository documents a **hands-on Digital Forensics & Incident Response (DFIR) lab** focused on analyzing, containing, and eradicating a malicious Windows executable.
The lab simulates a realistic endpoint compromise scenario where a user executes an unknown binary that exhibits disruptive behavior, establishes persistence, and performs data theft activities.

The investigation emphasizes **native Windows telemetry**, leveraging built-in auditing mechanisms and security event logs to reconstruct attacker behavior and validate eradication efforts without relying on third-party EDR solutions.

---

## 🎯 Lab Objective

The primary objectives of this lab are to:

* Prepare a Windows system for forensic visibility using advanced audit policies.
* Observe and contain malicious executable behavior in a controlled environment.
* Identify and remove user-level persistence mechanisms.
* Reconstruct post-execution activity using Windows Security Event Logs.
* Confirm data access, staging, and packaging behavior.
* Fully eradicate the malware and validate system recovery.

This lab demonstrates an **end-to-end DFIR workflow**, from pre-incident preparation to post-eradication validation.

---

## 🧪 Scenario Overview

An analyst is provided with a suspicious executable suspected of malicious behavior.
Upon execution, the binary causes noticeable system disruption, launches multiple processes, and persists across system reboots without user interaction.

The executable is believed to:

* Achieve persistence using a registry-based mechanism.
* Access sensitive user data from Google Chrome.
* Stage and compress stolen data locally.
* Continuously re-execute to maintain presence and disrupt the system.

The analyst’s task is to **investigate, contain, analyze, and fully eradicate** the threat using Windows-native tools and event logs, ensuring no residual malicious artifacts remain on the system.

To Prepare the Malicious files of this lab:
1. download this files:

2. Extract the file 
<img width="1923" height="677" alt="Screenshot 2026-03-25 183333" src="https://github.com/user-attachments/assets/e6814973-87fa-4487-af97-60de135aae1e" />

3. Open this file



---




# Phase 1: Pre Task Preparation – Audit Policy Configuration

Before executing the lab task and analyzing any malicious activity, the system audit policies were configured to ensure full visibility into process and file system actions performed by the executable.

## Objective

Enable detailed Windows auditing to accurately capture:

* Process creation and termination events.
* File system access, creation, modification, and deletion events.

These logs are critical for tracing the executable’s behavior and supporting the investigation and eradication process.

---

## Step 1: Open Local Group Policy Editor

The Local Group Policy Editor was accessed using:


<img width="1916" height="1075" alt="image" src="https://github.com/user-attachments/assets/a8e45692-08d5-4ba3-bda5-a0ece88b116a" />


```
gpedit.msc
```

<img width="1918" height="1078" alt="image" src="https://github.com/user-attachments/assets/b98ddbb7-1e41-4867-a110-ddff37644f75" />

Navigation path:

Computer Configuration
→ Windows Settings
→ Security Settings
→ Advanced Audit Policy Configuration
→ System Audit Policies – Local Group Policy Object




---

## Step 2: Configure Detailed Tracking Auditing

Under Detailed Tracking, the following subcategories were configured:

* Audit Process Creation → Success and Failure
* Audit Process Termination → Success and Failure


<img width="377" height="153" alt="image" src="https://github.com/user-attachments/assets/0b81a426-aa01-45c1-9bf3-6f0e72bcde65" />


This ensures that all processes launched or terminated by the executable are logged for analysis.

---

## Step 3: Configure Object Access – File System Auditing

Navigation path:

Object Access
→ Audit File System

Configuration applied:

* Audit File System → Success and Failure


<img width="1918" height="1078" alt="image" src="https://github.com/user-attachments/assets/7641ba85-c0e3-4d78-9e2b-b632f8135d01" />


This enables logging of file level interactions such as file creation, modification, and deletion.

---

## Step 4: Enable Global Object Access Auditing

To capture file system activity system wide, Global Object Access Auditing was configured.

Navigation path:

Global Object Access Auditing
→ File System


<img width="1912" height="1073" alt="image" src="https://github.com/user-attachments/assets/1ac94350-8361-45f9-bf9f-d4440775d0b7" />


---

## Step 5: Configure Global File SACL

The Global File SACL was configured to audit file system access by all users.

Actions performed:

* Opened File System Properties
* Selected Configure
* Added a new auditing entry
* Set Principal to:
* Everyone
* Enabled Success auditing
* Granted Full Control permissions (all access types)

<img width="1918" height="1078" alt="image" src="https://github.com/user-attachments/assets/6c2e9d21-6f02-4064-a874-ef9a15210676" />


<img width="1906" height="1065" alt="image" src="https://github.com/user-attachments/assets/4d536ef7-2359-4864-88b5-0596d52b38a0" />


<img width="917" height="591" alt="image" src="https://github.com/user-attachments/assets/511ef1d0-3510-40cc-8564-acb792d0a98d" />


This ensures comprehensive logging of all file system activities across the system.

---

## Result

At this stage, the audit environment was fully prepared. The system is now capable of recording:

* All process execution activities.
* All file system interactions performed by the malicious executable.

These configurations provide the necessary telemetry to accurately investigate, trace, and reverse the actions performed by the executable in the next phases of the lab.

---

# Phase 2: Malware Execution, Persistence Identification, and Eradication

After preparing the audit environment, the malicious executable was executed to observe its behavior, identify its persistence mechanism, and perform eradication.

---

## Step 1: Execute the Malicious File

The provided executable was manually executed. Immediately after execution, multiple abnormal behaviors were observed, including:

* Repeated pop-up windows displaying messages such as "RUN please RUN".
* Multiple application windows opening simultaneously (e.g., browsers, FileZilla, Wireshark).
* Noticeable system resource consumption and user disruption.


<img width="975" height="507" alt="image" src="https://github.com/user-attachments/assets/8a2ca451-4a0b-4802-9553-7c8bbe60872e" />

<img width="975" height="502" alt="image" src="https://github.com/user-attachments/assets/3019a6f8-62e5-49b4-bee1-412873a645c4" />



This confirmed that the executable was actively running and intentionally designed to be disruptive.

---

## Step 2: Initial Containment – Process Termination

To contain the activity, Task Manager was opened and the malicious process was identified.

Observed process:

* what_have_i_become.exe

Action taken:

* The process was manually terminated using End Task.

<img width="975" height="505" alt="image" src="https://github.com/user-attachments/assets/77478f69-a54e-45b3-a3b5-7b36194efcd8" />


The process was successfully killed, confirming user-level control over the running instance.

---

## Step 3: Persistence Verification via System Restart

After terminating the process, the system was restarted to determine whether the malware would:

* Remain inactive, or
* Automatically re-execute without user interaction.

Result:

* The malicious process restarted automatically after boot, confirming the presence of a persistence mechanism.


  <img width="975" height="732" alt="image" src="https://github.com/user-attachments/assets/e5543a1d-112a-458b-b8ce-f68f2137fa15" />


This behavior strongly indicated registry-based persistence.

---

## Step 4: Persistence Investigation Strategy

Before immediately deleting the file, several eradication approaches were considered, including:

* Blocking execution using AppLocker.
* Hash-based execution control.
* File-based containment rather than deletion.

However, since the executable continued to run after deletion and reboot, the focus shifted to identifying the persistence artifact.

---

## Step 5: Registry Persistence Analysis (Run Keys)

The investigation focused on Registry Run Keys, a common persistence technique.

Using RegSeek and the native Registry Editor, the following registry locations were reviewed:
URL: https://regseek.github.io/
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```
<img width="1918" height="1077" alt="image" src="https://github.com/user-attachments/assets/8b6f33a8-9688-49b2-b82a-bbd747a70176" />

```
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

```
<img width="1910" height="1067" alt="image" src="https://github.com/user-attachments/assets/46a222e5-474f-42c0-8f5e-02c095be8835" />

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

<img width="1918" height="1078" alt="Screenshot 2026-03-25 173037" src="https://github.com/user-attachments/assets/d30cf696-c9bb-4bda-995a-174fc102b245" />


Initial analysis of HKLM Run and RunOnce keys showed only legitimate entries.

---

## Step 6: Identification of Malicious Registry Key

The investigation then shifted to the current user context:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

A suspicious registry value was identified:

* Value Name: RunMe
* Value Type: REG_SZ
* Value Data:
* C:\Users\Khaled\AppData\Roaming\runme.exe


<img width="975" height="728" alt="image" src="https://github.com/user-attachments/assets/d263c915-44a6-47d3-acbd-0cd50c04c0b2" />

This entry directly matched the executable that was repeatedly launching after system startup.

---

## Step 7: Correlation with Runtime Evidence

The registry value was correlated with:

* The process name observed in Task Manager.
* Automatic execution behavior after reboot.


<img width="975" height="548" alt="image" src="https://github.com/user-attachments/assets/057c2764-e529-45ee-87d9-11d7b4ea3ef9" />


This confirmed that HKCU Run key persistence was the mechanism used by the malware.

---

## Step 8: Eradication of Persistence Mechanism

Action taken:

* The RunMeBro registry value was deleted from:
* HKCU\Software\Microsoft\Windows\CurrentVersion\Run


<img width="1917" height="1077" alt="image" src="https://github.com/user-attachments/assets/1636b37a-1116-4b0c-af52-c4898f34f8f2" />

---

## Step 9: Validation

After removing the registry key, the system was restarted.

<img width="975" height="435" alt="image" src="https://github.com/user-attachments/assets/810429f8-a3bf-4082-bb03-c356f94a5575" />

Result:

* No malicious processes executed on startup.
* The system returned to normal operational state.

<img width="1918" height="1013" alt="image" src="https://github.com/user-attachments/assets/ff81540f-94b8-4744-9fc6-ca3831f7f64f" />


---

## Outcome

At this stage:

* The malware persistence mechanism was successfully identified.
* Registry-based persistence was fully eradicated.
* The malicious executable no longer executed automatically after reboot.

This concludes the eradication phase and prepares the environment for further forensic analysis to determine the full impact of the malware on the system.

---

# Phase 3 – Event Log Investigation & Post-Execution Analysis

## Objective

The goal of this phase was to identify and reconstruct the malicious activities performed by the executable after execution, specifically:

* Process execution behavior
* File system interaction
* Evidence of Chrome data access and data staging
* Identification of directories and files created by the malware

This phase relies heavily on Windows Security Event Logs to build a reliable attack timeline and confirm malware intent.

---

## 1. Audit Policy Validation (Pre-Investigation)

Before analyzing event logs, audit policies were verified to ensure full visibility of process and file system activity.

### 1.1 Process Creation & Termination Auditing

```
auditpol /get /subcategory:"Process Creation"
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /get /category:"Detailed Tracking"
```

Result:

* Process Creation: Success & Failure
* Process Termination: Success & Failure

<img width="635" height="253" alt="image" src="https://github.com/user-attachments/assets/85308c82-eec7-43cf-b962-7115a18985c5" />


This guarantees visibility for Event ID 4688 (process creation) and termination-related artifacts.

---

### 1.2 File System (Object Access) Auditing

```
auditpol /get /subcategory:"File System"
```

Result:

* Object Access (File System): Success & Failure

<img width="635" height="134" alt="image" src="https://github.com/user-attachments/assets/d35708ec-8b75-4389-ad57-0382f655fc8a" />


This confirms the system is capable of logging Event ID 4663, which is critical for tracking file read/write/delete operations.

---

## 2. Event Log Scope Definition

The investigation focused on:

* Log Source: Windows Security Log

<img width="1920" height="1078" alt="image" src="https://github.com/user-attachments/assets/6b1515c0-d5fd-4c2a-88d6-446124f582c6" />

* Primary Event IDs:

  * 4688 – Process Creation
<img width="975" height="462" alt="image" src="https://github.com/user-attachments/assets/9f446073-00e7-4c4e-9e18-f696be5bd396" />

  * 4663 – File System Object Access

<img width="975" height="471" alt="image" src="https://github.com/user-attachments/assets/3e618373-99f9-4283-9b29-93c0f0ba342f" />


---

## 3. Process Creation Analysis (Event ID 4688)

### 3.1 Initial Malware Execution


<img width="1918" height="1003" alt="image" src="https://github.com/user-attachments/assets/625e02fd-63c7-4566-9b49-e80594d47df3" />


<img width="1917" height="1078" alt="Screenshot 2026-03-25 185239" src="https://github.com/user-attachments/assets/363ad136-7e0c-489c-b987-dd70df6c2296" />


By filtering for Event ID 4688 and searching for the unique executable name:

```
eradication_lab.exe
```

The following was confirmed:

* Executable Path:

  * C:\Users\Khaled\Desktop\eradication_lab.exe
* Execution Method:

  * Manual execution via double-click
* Parent Process:

  * C:\Windows\explorer.exe
* Execution Context:

  * Standard user privileges
  * No administrative elevation

This confirms the executable acted as the Initial Dropper / Loader and represents the start of the attack timeline.

---

### 3.2 Persistence Confirmation via Execution Context

<img width="1912" height="1073" alt="image" src="https://github.com/user-attachments/assets/edb6f445-c0d8-4215-aad5-4a5c446e9524" />


The parent process being explorer.exe and execution under a standard user account strongly supports the earlier finding that persistence was achieved via:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

This validates that persistence was user-based, not system-wide.

---

### 3.3 Self-Spawning Behavior (Forking)

Multiple Event ID 4688 entries showed the executable spawning child instances of itself.

Key Indicators:

* PPID (Parent Process ID): 0x2980
* Child processes were created by the original eradication_lab.exe instance
* No evidence of:

  * Process injection
  * LOLBins abuse
  * Privilege escalation

Conclusion:

The malware exhibited self-spawning behavior, creating additional instances from the original process. This increased runtime persistence and disruption without escalating privileges.

---

## 4. File System Activity Analysis (Event ID 4663)

<img width="1918" height="1075" alt="image" src="https://github.com/user-attachments/assets/f4731426-654e-4335-844e-1c9bb504a61d" />




### 4.1 Identification of Relevant Object Access Events


<img width="1918" height="1077" alt="image" src="https://github.com/user-attachments/assets/81f6bd95-29cf-45d0-b5a3-0fcd595c5232" />


<img width="1903" height="1017" alt="image" src="https://github.com/user-attachments/assets/bde905db-0f5a-4679-9b6b-9418f59a4abd" />

<img width="1917" height="962" alt="image" src="https://github.com/user-attachments/assets/8602cf12-cded-4051-993d-214388129082" />



Event ID 4663 logs were used to track file system interaction, including:

* ReadData
* ListDirectory
* Delete

Filtering was narrowed using the unique Process ID (PPID = 0x2980) to avoid false positives.

---

### 4.2 System File Access Observation


### Evidence:

<img width="1917" height="996" alt="image" src="https://github.com/user-attachments/assets/b5996945-0532-41e9-93fc-f4101d14f3dc" />

* Object Name:

  ```
  C:\Windows\System32\kernel.appcore.dll
  ```
* Process:

  ```
  what_have_i_become.exe
  ```

---

### Analysis:

The executable performed read access on a core Windows system DLL (`kernel.appcore.dll`), indicating normal dependency loading behavior during execution.

---

## 🔹 4.3 Temporary Directory Access & Staging Behavior

### Evidence:

<img width="1915" height="1075" alt="image" src="https://github.com/user-attachments/assets/27be6932-81c7-46a1-b68e-5079bb068177" />

* Object Name:

  ```
  C:\Users\Khaled\AppData\Local\Temp\_MEI96202
  ```
* Process:

  ```
  what_have_i_become.exe
  ```

<img width="903" height="702" alt="image" src="https://github.com/user-attachments/assets/ad2a6fdf-e3ad-4ac2-9e35-95cfa4cfcd93" />

---

### Analysis:

The executable accessed a temporary directory with the `_MEI` naming pattern, which is commonly associated with PyInstaller-packed executables.

Further inspection of the directory revealed multiple runtime components, including:

* Python runtime (`python313.dll`)
* Standard library archive (`base_library.zip`)
* Cryptographic library (`libcrypto-3.dll`)
* Network-related modules (`_socket.pyd`)

This indicates that the executable unpacked its runtime environment into the Temp directory during execution.

---

### Conclusion:

This behavior confirms that the malware is a PyInstaller-packed executable that dynamically extracts its components at runtime. The presence of networking and cryptographic modules suggests potential capabilities for data processing or communication.


## 5. Final Findings Summary

Malware Capabilities Confirmed

Manual execution via user interaction
User-level persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run key
Self-spawning process behavior (child processes created by original executable)
No privilege escalation or process injection detected
Reads critical system DLLs (e.g., kernel.appcore.dll) during execution
Stages runtime components in Temp directory (_MEI*)
PyInstaller-packed executable dynamically extracts Python runtime & libraries
Includes cryptographic (libcrypto-3.dll) and networking (_socket.pyd) modules
High resource consumption and user disruption (pop-ups, multiple apps opened)
Full eradication achieved via registry key removal and Temp cleanup
---

## 6. Eradication Status

At the conclusion of the investigation:

* Persistence registry key removed
* Malicious executable deleted
* Temporary staging directories identified and removed
* No residual malicious activity observed

---

## 7. Conclusion

This phase successfully reconstructed the post-execution behavior of the malware using native Windows auditing and event logs. The findings confirm the executable’s intent to steal browser data, stage it locally, and maintain persistence at the user level.

The investigation demonstrates a complete DFIR workflow, from execution tracing to data theft confirmation and eradication validation.
