

# ✅ **Task 1 — Brute Force Investigation (ELK Stack)**

**Goal:** Identify *when* the brute-force attack happened and extract the *Account Name* and *Workstation Name* involved.

---

## **1. Filtering Logs from the Target Device**

**I opened Kibana Discover and filtered logs using `agent.name` to view only events coming from the targeted machine.**

<img width="975" height="469" alt="image" src="https://github.com/user-attachments/assets/51124abe-c37e-4bef-8de5-b90c88debe3b" />



## **2. Identifying the Failed Logon Event ID**

**I searched Ultimate Windows Security for "Failed to log on" and confirmed the event ID for failed logins is `4625`.**

<img width="975" height="464" alt="image" src="https://github.com/user-attachments/assets/199d06b0-b3d1-4687-b573-3adbba1f368c" />



<img width="975" height="491" alt="image" src="https://github.com/user-attachments/assets/823276d2-4049-4112-9932-e1f6903fcd17" />


## **3. Querying All Failed Login Attempts**

**I searched in Kibana using `event.code: "4625"` to display all failed logon events collected by Winlogbeat.**


<img width="975" height="466" alt="image" src="https://github.com/user-attachments/assets/c3d04c13-4655-4bc4-81ad-fe4b32a9b88d" />



## **4. Detecting Suspicious Login Activity (Brute Force Indicator)**

**From the visualization, I noticed an abnormal spike—130 failed logons on December 6th around 15:00, indicating a potential brute-force attack.**

<img width="975" height="469" alt="image" src="https://github.com/user-attachments/assets/30742437-2c0a-4d97-a23a-d7d19623ae20" />



## **5. Narrowing Down the Exact Attack Time Window**

**I filtered the time range further and identified 82 failed logons within less than two minutes — the exact brute-force activity window (16:33:33 → 16:34:13).**


<img width="975" height="469" alt="image" src="https://github.com/user-attachments/assets/13f7e68a-7c54-4dc1-a183-f5af1053046b" />

<img width="975" height="453" alt="image" src="https://github.com/user-attachments/assets/93fb02b2-320f-4adb-8f41-82c0b2800d38" />


## **6. Extracting Account Name and Workstation Name**

**I opened one of the failed-logon logs and retrieved the required fields:**

* **Account Name:** *Administrator*


<img width="975" height="468" alt="image" src="https://github.com/user-attachments/assets/fd2fe730-c5a9-4286-80ec-1301ccf26b65" />


* **Workstation Name:** *IS-SOC-AR*



<img width="975" height="466" alt="image" src="https://github.com/user-attachments/assets/13c7734f-d370-442b-af10-7a077165fcbd" />


---

# ✅ **Task 2 — Detecting Suspicious `.vbs` File Creation (Sysmon Event ID 11)**

**Goal:** Identify when a `.vbs` file was created and determine the process and path responsible.

---

## **1. Identifying the Relevant Sysmon Event ID**

**I searched Ultimate Windows Security and confirmed that “File Creation” events are logged under Sysmon Event ID `11`.**

<img width="975" height="484" alt="image" src="https://github.com/user-attachments/assets/f17bd4af-493a-4a58-830a-110981a5ab34" />


## **2. Querying All File-Creation Events**

**I filtered Kibana logs using `event.code: "11"` to retrieve all Sysmon file-creation events.**


<img width="975" height="466" alt="image" src="https://github.com/user-attachments/assets/477276b9-2c0f-4e45-a806-4eb291428f16" />



## **3. Narrowing the Scope to `.vbs` Files Only**

**To reduce noise, I filtered further using `file.extension: "vbs"` to return only logs related to VBS file creation.**


<img width="975" height="474" alt="image" src="https://github.com/user-attachments/assets/fe6effcf-a2b8-4de1-9ac9-7243f235d051" />


## **4. Locating the Exact Suspicious File Event**

**Only one result appeared, indicating a `.vbs` file created on December 6th — confirming it as the suspicious file.**


<img width="975" height="472" alt="image" src="https://github.com/user-attachments/assets/67cbd0ab-0aff-475d-9db9-c5465808d1de" />


## **5. Extracting the File Path and Process Details**

**From the event details, I retrieved the file’s full path and the process responsible for creating it:**

* **File Path:**
  `C:\Users\Administrator\Downloads\Iloveturkey\rootdir\x123456.vbs`

* **Creating Process:**
  `C:\Windows\explorer.exe`

* **User:**
  `Administrator`

---


