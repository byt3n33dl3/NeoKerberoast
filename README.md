[![banners](https://github.com/pxcs/BrazilianKarambit/assets/151133481/e23e52bd-60fe-4ca6-9797-ca56cad4a118)](https://github.com/pxcs/BrazilianKarambit/)

Create by [@pxcs.](https://github.com/pxcs/) This tool targeted to get information about the versions of software and services running on the network. This information can be used to identify known ```vulnerabilities``` and exploits specific to those versions. Mainly used for enumerate user accounts, group memberships, and roles within a target system. Knowing user privileges and access rights can help ***~Attackers~*** to identify potential targets for privilege escalation.

### Documentation

Documentation and report will be listed `here` or somewhere else.<br>

- **Testing**<br>
- **Report**<br>
<hr>

#### Ghost Hunter | Brazilian Karambit | Enumeration Tool

<a href="https://github.com/pxcs/BrazilianKarambit/"><img src="https://static.wikia.nocookie.net/infestationnewz_gamepedia_en/images/e/e4/Karambit.png/revision/latest?cb=20200124170225" align="right" width="70" alt="BrazilianKarambit"></a>

> [<img src="https://static.wikia.nocookie.net/infestationnewz_gamepedia_en/images/e/e4/Karambit.png/revision/latest?cb=20200124170225" width="20">]() Ghost Hunter | Enumeration Tool: <br>
These tools can help to uncover network policies, firewall rules, and routing tables. Understanding these configurations can help ***~Attackers~*** find ways to bypass security measures. Simple Network Management Protocol (SNMP) enumeration can reveal detailed device information, including system configurations, hardware details, and running processes, which can be leveraged for further attacks.<br><br>
#### Warning

The application is included in the standard of Enumeration tool package was not available yet.
<br />
You can also download the [release](https://github.com/pxcs/BrazilianKarambit/releases/latest) and unzip/untar, only after the test was completed on ```active``` directory scenario.
<br />
> [!WARNING]
>
> The application is not compatible `yet` with the official [HarpoonHound](https://github.com/pxcs/harpoonhound) project.
> Also, it has not been tested on any other Enumeration tool.

---

### Role for Kerberos attack

[![banners](https://github.com/pxcs/GhostHunterKerberos/assets/151133481/0dabcb6d-774d-4d16-a393-84788ec69b86)](https://github.com/pxcs/KerberossianCracker)
A senior penetration tester or advanced cyber criminal focusing on network enumeration and Kerberos attacks, having a comprehensive set of tools and features is crucial.

### Key Features and Strengths

#### Kerberos Interaction
Automated AS-REQ and TGS-REQ, for `automates` the sending of AS-REQ (Authentication Service Requests) and TGS-REQ (Ticket Granting Service Requests) messages to the Kerberos Key Distribution Center (KDC). This streamlines the process of obtaining TGTs and service tickets.

#### Capability
Extraction and Parsing: It includes functionality to parse and extract relevant information from the `tickets` received, which is essential for further analysis or attacks. The tool can request service tickets for various service accounts, which can then be extracted for offline password cracking. This is a critical component of the Kerberoasting attack. 

### YARA for Enumeration and Kerberoasting Protocol
The tool primarily used in malware research and detection. However, it can be adapted for various purposes in ~cyber-attacks~, including the detection of specific behaviors such as enumeration and Kerberoasting in a network. Kerberoasting is an attack method that targets the Kerberos authentication protocol used in Windows environments to extract hashed credentials for brute-force cracking. And for Detection enumeration activities often involve scanning for open ports, user accounts, and services. Detecting such activities can involve looking for specific strings or patterns associated with known enumeration tools or behaviors.

#### YARA to detect Kerberoasting activity:
```
rule KerberoastingDetection
{
    meta:
        description = "Detects Kerberoasting tools and activities"
        author = "Username"
        date = "2020-07-02"
        reference = "https://github.com/pxcs/KerberossianCracker"

    strings:
        $rubeus = "Rubeus"
        $JtR = "John-the-Ripper"
        $hashcat = "hashcat"
        $tgsrepcrack = "tgsrepcrack"
        $gettgssession = "Get-TGSSession"
        $invoke_kerberoast = "Invoke-Kerberoast"
        $request_spn = "Request-SPN"
        $spnrequest = "spnrequest"
        $kerberoast = "kerberoast"

    condition:
        any of ($rubeus, $Jtr, $hashcat, $tgsrepcrack, $gettgssession, $invoke_kerberoast, $request_spn, $spnrequest, $kerberoast)
}
```
#### Run YARA protocol:
```
yara -r /path/to/rules /path/to/scan
```
---

Note: for research and educational purposes only.

Thanks to SharpHound/AD repo and HarpoonHound.
