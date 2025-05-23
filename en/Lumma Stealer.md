# Lumma Stealer

Lumma Stealer is an info stealer malware that has been active since 2022. According to research, the use of malware belonging to the Lumma family has increased in recent years. Lumma adopts the MaaS (Malware as a Service) model, offering its services for sale. With this model, even individuals without technical knowledge can easily access such malware and contribute to its spread.

![Malware Trend of the Last Year (ANY.RUN)](/img/1.png)


_Lumma Stealer_ intends to steal the web browsing data, cryptocurrency wallet information, and system data of targeted systems. The data that has been stolen is sent to C&C servers. 

Due to its nature as a malware service, its methods of spreading vary. One of the most common methods nowadays is creating **fake CAPTCHA** pages. In addition, threat actors distribute Lumma Stealer through platforms such as **Discord CDNs** or **cracked software**. 

Research indicates that the first quarter of 2025 saw almost twice as many Lumma-related attacks detected as all attacks reported throughout 2024.

![Number of Incident Related to Lumma Stealer (Ontinue)](/img/2.png)

The Lumma family develops the Lumma Stealer malware and releases new versions. In this way, they develop new methods to bypass current security measures. A new and advanced version of Lumma Stealer has been detected recently.

![An Interview with Lumma Gang](/img/3.png)

# Lumma Stealer Family

**LummaC2** is a member of the Lumma malware family, which has been active since December 2022. It is developed using the C/C++ programming language. This malware family is believed to be of Russian origin and developed by a threat actor known as “Shamel.” LummaC2 appeared as an improved version of LummaC, which has been sold on underground forums since August 2022 and was also developed by the same threat actor. Detection is made more challenging by the use of extensive obfuscation and anti-analysis techniques.

Lumma Stealer is sold on dark web forums, its own Telegram channel, and a dedicated website (lumma [.] shop). Lumma, which uses the MaaS (Malware as a Service) model, is spreading rapidly because it's relatively easy to access and doesn't require any technical skill for usage. Additionally, the most comprehensive sales package allows buyers to access the source code of Lumma Stealer. This enables them to customize and either sell or use the software themselves.

![Pricing in Lumma Web Sites](/img/4.png)

Lumma Stealer steals sensitive information from the target system, such as cryptocurrency wallets, browser data, and system information. It sends the stolen data by communicating with a command and control (C2) server. First, it reaches a server it can connect to. Then, it sends a **POST** request with the **User-Agent** information and the **“act=life”** parameter to register itself.

After that, another **POST** request is sent with the **Lumma ID** and the **“act=receive-message”** parameter. The stolen data is kept in a compressed file, and this compressed file is sent to a C2 server with the **“/api”** path. However, due to the constantly evolving and changing structure of Lumma Stealer, it has recently been observed using the HTTPS protocol. This makes it harder to detect in network traffic.

![POST Request is Sent with Lumma ID](/img/5.png)

## Common Distribution Methods

Lumma Stealer aims to steal sensitive information from the target system, especially browser data, cryptocurrency wallets, and two-factor authentication (2FA) data. To achieve this goal, it uses various distribution methods, primarily phishing emails.

In October 2024, a method emerged in which attackers installed the Lumma malware on the target system through fake CAPTCHA pages. Another observed method is the distribution of cracked versions of popular applications such as ChatGPT or VegasPro.

Another method used to distribute the Lumma Stealer malware is Content Delivery Networks (CDN). Some of the CDNs used by Lumma Stealer include Cloudflare CDN and Discord CDN. In addition, Discord APIs are used to create bots to control the malware remotely. Some of these bots are developed to transmit the stolen data to private Discord servers or channels.

### Fake CAPTCHA

![ Attack Chain for Fake CAPTCHA](/img/6.png)

Attackers create fake **CAPTCHA** verification pages to distribute the Lumma Stealer malware. Through these pages, a PowerShell command is executed to initiate the download of Lumma Stealer onto the target system. Victims are usually directed to these verification pages through phishing techniques.

When the verification page loads, the user is shown a “verify you are human” screen. There is a fake **“I’m not a robot”** button. When this button is clicked, the verification steps are displayed. When the **Run** command (Windows+R) is executed and the given code is pasted, a PowerShell command runs, and the malicious file is downloaded to the system.

![Fake CAPTCHA Page](/img/7.png)

When the source code of the fake CAPTCHA page is examined, a **“verify”** function is found that executes the **“document.execCommand("copy")”** command and contains a PowerShell script encoded in Base64. With this command, when the “I’m not a robot” button is clicked, the Base64-encoded PowerShell command is automatically copied to the clipboard.

![PowerShell Command Base64-Encoded](/img/8.png)

When the Base64-encoded part is decoded, it is revealed to be a **mshta.exe** command. **Mshta.exe** is a legitimate Windows tool used to run HTML applications and embedded scripts. Using this tool, the payload located at the given URL is downloaded and saved to the “INetCache” directory.

![Decoded PowerShell Command](/img/9.png)

The downloaded **“2ndhsoru”** file with this command line is a Portable Executable (PE) prepared for the **dialer.exe** Windows tool and contains a script in the _overlay_ section. Upon inspection, this script is found to be an _obfuscated_ JavaScript file.

In this payload, the **polyglot technique** is used. A valid HTA content is embedded into files that can be executed by mshta. This script is triggered by an **‘eval’** function to run the JavaScript code.

Inside the JavaScript code, there is a PowerShell command encrypted with AES. This command downloads and extracts the **K1.zip** file containing DLLs and the **K2.zip** file containing **Victirfree.exe** (Lumma Stealer) into the **“C:\Users%username%\AppData\Local\Temp”** directory.

![K1.zip and K2.zip Files](/img/10.png)

The **Victirfree.exe** file, a variant of Lumma Stealer, uses the legitimate **BitLockerToGo.exe** for the **process hollowing** technique.

The **BitLockerToGo.exe** process, into which the malware is injected, saves certain files to the **Temp** directory. One of these files, named **72RC2SM21DDZ2OAH3P30V1XPT5AE7YN.exe**, copies the **Killing.bat** and **Voyuer.pif** files into the same directory. The **Killing.bat** file is an _obfuscated_ script that uses **tasklist** and **findstr** commands to check for antivirus processes such as **wrsa.exe (Webroot Antivirus), opssvc.exe (Quick Heal Antivirus), bdservicehost.exe (Bitdefender)**.

![ BitLockerToGo.exe Process After Process Hollowing](/img/11.png)

Lumma Stealer targets specific file directories to capture cryptocurrency wallets, passwords, browser data, and other sensitive information. It searches for keywords such as **_seed_.txt, _pass_.txt, _.kbdx, ledger.txt, trezor.txt, metamask.txt, bitcoin_.txt, _word_**, and **_wallet_.txt** to locate and steal the desired data.

![Web Browser Data](/img/12.png)

It sends the stolen information to the Command and Control (C2) server. Lumma Stealer mostly uses domains with the **“.shop”** top-level domain (TLD) as its C2 servers.

### Discord CDN

**Discord** is a platform with a large and diverse user base. It appeals not only to gamers but also to content creators, streamers, and various online communities. For this reason, this popular platform becomes a hunting ground for cyber attackers. Moreover, attackers try to gain users' trust by offering rewards such as money or Discord Nitro. Lumma Stealer also uses the Discord platform in this way.

Attackers usually send messages to targeted users using randomly created or compromised accounts. They ask the targeted user to help with a project in exchange for rewards like money or a ‘nitro boost.’ The requested help is described as short and easy, convincing the targeted user. If the user agrees, they are asked to download the project file.

![Example of Help Message](/img/14.png)

This fake project is hosted on Discord’s **CDN** (cdn[.]discordapp[.]com/attachments/). When the link sent to download the file is clicked, multiple downloads start. The malicious file containing Lumma Stealer (4_iMagicInventory_1_2_s.exe) is downloaded onto the target system.

When the file is executed, it attempts to connect to a malicious domain like "**gapi-node[.]io**," allowing it to steal the user’s cryptocurrency wallets and browser data.

![Targeted Crypto Currency Wallets](/img/15.png)

### Cracked Software

 One of the oldest methods, cracked software, is also used for spreading the Lumma Stealer malware. Attackers embed their payloads in a loader and deliver them to the target system this way. During the installation of cracked software, users are often prompted to disable antivirus tools. This allows the user to unintentionally create an entry point for Lumma Stealer.

![Cracked Software Attack Chain](/img/16.png)

Lumma Stealer mostly uses YouTube videos to deliver itself to target systems through cracked software. On compromised YouTube channels that already offer cracked software content, it provides installation guides for the malware and often includes URLs shortened with **cuttly** and **tinyurl** services.

![YouTube Channels](/img/17.png)

Using open-source platforms like GitHub and MediaFire, it accesses a NET loader that downloads Lumma Stealer to bypass web filters.

It has been observed that the ZIP files in the links are updated periodically. In this way, the most recent version of Lumma Stealer continues to spread.

![Lumma Stealer Uploaded to MediaFire](/img/18.png)

The file named **“installer_Full_Version_V.1f2.zip”** seen in this example contains an **LNK** file that executes a PowerShell command. This PowerShell command downloads a .NET executable from the GitHub repository named **"New"** owned by the user **John1323456**.

![The GitHub Repo](/img/19.png)

The analysis **Installer-Install-2023_v0y.6.6.exe** file in the example is found to be _obfuscated_. The malware performs system checks to avoid running in isolated environments.

To ensure stealthy execution on the infected system, it uses certain properties of the **ProcessStartInfo** object. By using **RedirectStandardInput**, **CreateNoWindow**, and **UseShellExecute**, it runs commands and programs in the background, helping evade antivirus detection.

![processStartInfo Properties](/img/20.png)

This malware contains IP addresses of four different servers encoded in Base64. Depending on the current system date, it selects the appropriate IP address to fetch its binary data.

It communicates with one of these servers, **176[.]113[.]115[.]224:29983**, and downloads the requested data. The malware decrypts the AES-encrypted script obtained from the server and installs a DLL file on the system.

The downloaded **Agacantwhitey.dll** file in this example is encrypted to evade detection. Additionally, it performs multiple checks to provide anti-VM and anti-debug protections. Some of these checks are as follows:

* ****Active window check:** Using GetForegroundWindow, it verifies whether any of the following debuggers are running on the system:

	"x32dbg," "x64dbg," "windbg," "ollydbg," "dnspy," "immunity debugger," "hyperdbg," "debug," "debugger," "cheat engine," "cheatengine," "ida."

* **Antivirus and sandbox checks:**

	Detects DLLs such as SbieDll.dll (Sandboxie), cmdvrt64.dll (Comodo Antivirus), cuckoomon.dll (Cuckoo Sandbox), SxIn.dll (360 Total Security).
	
	Checks for usernames like Johnson, Miller, malware, maltest, CurrentUser, Sandbox, virus, John Doe, test user, sand box, and WDAGUtilityAccount.

* ***Virtual machine detection:** It queries the system via WMI to check the manufacturer and model names, such as:

	Manufacturer names like "innotek gmbh" (associated with VirtualBox), "microsoft corporation" (linked to Hyper-V) and model names like "VirtualBox," "vmware."
	
	Also checks for the existence of directories like “C:\Program Files\VMware” and “C:\Program Files\oracle\virtualbox guest additions.”

* **System services and process names checks:**

	Checks for the presence of services such as "vmbus," "VMBusHID," and "hyperkbd."
	
	Checks for processes like "vboxservice," "VGAuthService," "vmusrvc," and "qemu-ga."

# New Version of LummaC2

Recently, a new and advanced version of **Lumma Stealer** has been identified. In this new version, Lumma Stealer employs advanced techniques such as **code flow obfuscation**, **API hash resolving**, **Heaven’s Gate**, **disabling ETWTi callbacks**, and **anti-sandbox** methods to evade detection.

![New Version of LummaC2 Attack Chain](/img/21.png)

It has been identified that a threat actor using the new version of _Lumma Stealer_ distributes it via **obfuscated PowerShell scripts**. These scripts contain two components: a **Base64-encoded Lumma payload** and a **.NET-based loader** named **GOO.dll**.

The PowerShell script leverages the **Reflection API** to load the .NET executable GOO.dll, which is obfuscated using **Crypto Obfuscator**. This loader then injects the _Lumma payload_ into the legitimate **RegSvcs.exe** process. By doing so, the payload operates under the guise of a legitimate process, aiming to carry out malicious activities and steal sensitive data without detection.

Analysis of the encrypted **Lumma binary file** reveals that it avoids calling functions commonly flagged by behavioral detection systems, such as **LoadLibrary** and **GetProcAddress**, by using **Process Environment Block (PEB)** structures and custom API hash tables.

Logical connections between code blocks are computed dynamically at runtime, disrupting the code flow and making static analysis and reverse engineering tools struggle to interpret the logic. This computation varies at every step and is applied throughout the code, a technique known as **Code Flow Obfuscation**, which is designed to complicate reverse engineering by altering the program's control flow.

In this version, Lumma uses hashed values to conceal the APIs it intends to use, such as **RtlAllocateHeap**, **RtlReAllocateHeap**, **RtlFreeHeap**, and **RtlExpandEnvironmentStrings**. These hash values are resolved dynamically before the APIs are called, a method known as **API Hash Resolving**. The same technique is used to resolve APIs needed to communicate with **C&C servers**.

Although compiled as a **32-bit** executable, the new version of _Lumma Stealer_ also functions on **64-bit** systems by utilizing the **Heaven’s Gate** technique. It first checks the nature of the infected system and performs compatible calls accordingly.

Additionally, to reduce interference from modern Endpoint Detection and Response (EDR) tools, the latest version of Lumma remaps the **ntdll.dll** library to execute clean and unhooked system calls (syscalls).

![Remapping ntdll.dll](/img/22.png)

After checking whether the infected system is 32-bit or 64-bit, the appropriate DLL version is selected. To remap the appropriate ntdll.dll file, **syscall** invocations are used. Since these syscalls are represented as hash values, **API hash resolving** is performed to decode them. This technique is intended to complicate code analysis.

_Lumma Stealer_ disables **ETW (Event Tracing for Windows) callbacks** to prevent its system calls from being detected by security software. ETW callbacks are monitoring functions that Windows triggers to inform security systems early about processes and events. By disabling them, Lumma avoids detection.

Lumma also performs checks using **hardcoded hash values** against artifacts related to known **sandboxes**, **antivirus DLLs**, and **virtual machines**. If it detects a virtualized environment, it refrains from executing malicious activities.

Additionally, Lumma checks the system's language settings. If **Russian** is set as the **default user language**, it avoids executing malicious behavior.

_Lumma Stealer_ stores the **C2 server domains** in an encrypted format. It sequentially decrypts these domains and attempts to establish a connection via a **POST request**.

![Requests to C&C](/img/23.png)

If no valid response is received from the C2 servers, Lumma attempts to communicate with the C2 server using **Steam** user URLs. The Steam usernames are embedded in the URL in an encrypted format. Once decrypted, these usernames are used to initiate communication with the C2 server.

After successful communication, an encrypted **configuration file** is retrieved from the C2 address, which specifies the targets for data collection. This file includes **web browsers, cryptocurrency wallets, password managers, VPN clients, FTP applications**, and messaging platforms such as **Telegram** and **Discord**.

The **data exfiltration** process is carried out automatically. Around 90 applications and critical file paths on the infected system are targeted. The stealer also aims to collect data from cryptocurrency wallets and email applications.

### Conclusion

_Lumma Stealer_ is a sophisticated and continuously evolving **info-stealer** malware used by cyber threat actors. Through its advanced evasion techniques and constantly updated methods, it aims to bypass traditional security mechanisms. The ongoing development and deployment of stealer malware like Lumma pose a significant threat to organizations. To counter such advanced threats, organizations must adopt proactive defense strategies and implement stronger **endpoint protection** measures.