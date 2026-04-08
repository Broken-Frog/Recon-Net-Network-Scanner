/*
 * Recom-Net Network Forensics YARA Rules
 * Focused on PCAP-extracted payloads, C2, DDoS artifacts, and malware
 */

rule SYN_Flood_Pattern {
    meta:
        description = "High SYN packet patterns or reflection attack artifacts"
        author = "ATLAS"
        severity = "High"
    strings:
        $syn_flood = { 02 00 00 00 }  // Common in SYN packets (flags)
        $reflection = "SYNACK" nocase
    condition:
        any of them and filesize < 5MB
}

rule C2_Beaconing {
    meta:
        description = "Common C2 beacon patterns (Cobalt Strike, Empire, Sliver, etc.)"
        severity = "High"
    strings:
        $beacon1 = "beacon" nocase
        $beacon2 = "/api/" nocase
        $c2 = "c2" nocase
        $http_post = "POST /" nocase
        $sliver = "sliver" nocase
    condition:
        2 of them
}

rule Data_Exfiltration {
    meta:
        description = "Large base64 or encoded data exfiltration"
        severity = "Medium"
    strings:
        $base64_long = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $base64_long and filesize > 10KB

}

rule Malware_Downloader {
    meta:
        description = "Common malware downloader patterns"
        severity = "High"
    strings:
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $wget = "wget " nocase
        $curl = "curl " nocase
        $exe = ".exe" nocase
    condition:
        2 of them
}

rule Port_Scan_Pattern {
    meta:
        description = "Port scanning behavior in payloads"
        severity = "Medium"
    strings:
        $nmap = "nmap" nocase
        $scan = "scan" nocase
        $port = "port " nocase
    condition:
        any of them
}

rule UDP_Flood_Artifact {
    meta:
        description = "UDP amplification or flood related strings"
        severity = "High"
    strings:
        $udp_flood = "UDP" nocase
        $amplification = "amplification" nocase
        $dns = "DNS" nocase fullword
    condition:
        2 of them
}

/* Add more rules here as you find new IOCs */
rule PowerShell_Ransomware_Dropper
{
    strings:
        $a = "powershell" nocase
        $b = "DownloadString" nocase
        $c = "Invoke-Expression" nocase
        $d = "FromBase64String" nocase
    condition:
        2 of them
}

rule Suspicious_Download
{
    strings:
        $a = ".exe" nocase
        $b = ".dll" nocase
        $c = "application/octet-stream" nocase
        $d = "Content-Disposition" nocase
    condition:
        any of them
}

import "math"

rule Packed_or_Encrypted_Payload
{
    meta:
        description = "Detect packed or encrypted payloads"

    condition:
        filesize > 50KB and
        math.entropy(0, filesize) > 7.3
}

rule Ransomware_Binary_Behavior
{
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "bcdedit /set" nocase
        $c = "wbadmin delete catalog" nocase
        $d = "shadowcopy delete" nocase
        $e = "CryptEncrypt"
        $f = "CryptAcquireContext"
        $g = "CreateFileW"
        $h = "WriteFile"

    condition:
        3 of them
}

rule Ransomware_RansomNote_Generic
{
    meta:
        description = "Detect common ransomware ransom notes"
        category = "ransomware"

    strings:
        $a = "your files have been encrypted" nocase
        $b = "pay within" nocase
        $c = "bitcoin" nocase
        $d = "decrypt your files" nocase
        $e = "private key" nocase

    condition:
        2 of them
}

rule Ransomware_File_Extensions
{
    meta:
        description = "Detect ransomware file extensions"

    strings:
        $a = ".locked"
        $b = ".encrypted"
        $c = ".crypt"
        $d = ".wncry"
        $e = ".crypto"
        $f = ".pay"

    condition:
        any of them
}


rule Ransomware_Encryption_API
{
    meta:
        description = "Detect encryption API usage"

    strings:
        $a = "CryptEncrypt"
        $b = "CryptAcquireContext"
        $c = "CryptGenKey"
        $d = "AES"
        $e = "RSA"

    condition:
        3 of them
}

rule Ransomware_Bitcoin_Payment
{
    meta:
        description = "Detect bitcoin ransom payment indicators"

    strings:
        $btc1 = "bitcoin wallet" nocase
        $btc2 = "send bitcoin" nocase
        $btc3 = "btc address" nocase
        $btc4 = "payment id" nocase

    condition:
        any of them
}

rule Ransomware_Network_Delivery
{
    meta:
        description = "Detect ransomware delivery instructions"

    strings:
        $a = "download decryptor" nocase
        $b = "tor browser" nocase
        $c = ".onion" nocase
        $d = "decrypt instructions" nocase

    condition:
        any of them
}


rule Ransomware_HighConfidence
{
    meta:
        description = "High confidence ransomware detection"

    strings:
        $a = "your files have been encrypted" nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
        $d = "private key" nocase
        $e = ".locked"
        $f = ".encrypted"

    condition:
        (2 of ($a,$b,$c,$d)) or (1 of ($e,$f))
}


rule Ransomware_Delete_ShadowCopies
{
    meta:
        description = "Detect shadow copy deletion behavior"

    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "bcdedit /set" nocase

    condition:
        any of them
}


rule Ransomware_Stop_Services
{
    meta:
        description = "Detect stopping security services"

    strings:
        $a = "net stop" nocase
        $b = "taskkill /f" nocase
        $c = "disable recovery" nocase

    condition:
        2 of them
}

rule File_Write_Operation
{
    meta:
        description = "Detect file write operations"

    strings:
        $a = "WriteFile"
        $b = "CreateFile"
        $c = "fwrite"
        $d = "ofstream"
        $e = "SetEndOfFile"

    condition:
        2 of them
}

rule File_Read_Operation
{
    strings:
        $a = "ReadFile"
        $b = "fread"
        $c = "ifstream"
        $d = "CreateFile"
    condition:
        2 of them
}


rule File_Delete_Operation
{
    strings:
        $a = "DeleteFile"
        $b = "RemoveDirectory"
        $c = "unlink"
        $d = "del /f"
        $e = "rm -rf"

    condition:
        any of them
}

rule File_Update_Operation
{
    strings:
        $a = "MoveFile"
        $b = "RenameFile"
        $c = "MoveFileEx"
        $d = "rename("
    condition:
        any of them
}

rule Mass_File_Modification
{
    strings:
        $a = ".locked"
        $b = ".encrypted"
        $c = ".crypt"
        $d = "WriteFile"
        $e = "CreateFile"
    condition:
        3 of them
}


rule Network_File_Operations
{
    strings:
        $a = "SMB2 WRITE"
        $b = "SMB2 READ"
        $c = "SMB2 SET_INFO"
        $d = "PUT /"
        $e = "DELETE /"
        $f = "PATCH /"
    condition:
        any of them
}

rule Shadow_Copy_Delete
{
    strings:
        $a = "vssadmin delete shadows"
        $b = "wmic shadowcopy delete"
        $c = "bcdedit /set"
    condition:
        any of them
}


rule File_Tampering_HighConfidence
{
    strings:
        $a = "WriteFile"
        $b = "DeleteFile"
        $c = "MoveFile"
        $d = "CreateFile"
    condition:
        3 of them
}


rule Ransomware_File_Activity
{
    strings:
        $a = "CreateFile"
        $b = "WriteFile"
        $c = "CloseHandle"
        $d = ".locked"
        $e = ".encrypted"
    condition:
        3 of them
}

rule Linux_File_Operations
{
    meta:
        description = "Linux file read/write/delete operations"

    strings:
        $a = "open("
        $b = "write("
        $c = "read("
        $d = "unlink("
        $e = "chmod("
        $f = "chown("
        $g = "rename("

    condition:
        3 of them
}


rule Linux_File_Delete
{
    strings:
        $a = "rm -rf"
        $b = "unlink("
        $c = "remove("
        $d = "shred"

    condition:
        any of them
}


rule Windows_File_Modification_Events
{
    strings:
        $a = "EventID>4663"
        $b = "EventID>4656"
        $c = "EventID>4660"
        $d = "Object Name:"
        $e = "Accesses: WRITE_DAC"

    condition:
        any of them
}


rule Windows_ShadowCopy_Delete_Event
{
    strings:
        $a = "vssadmin delete shadows"
        $b = "wmic shadowcopy delete"
        $c = "EventID>4688"
    condition:
        any of them
}


rule SMB_File_Write
{
    strings:
        $a = "SMB2 WRITE"
        $b = "SMB Write AndX"
        $c = "SMB2 CREATE"
    condition:
        any of them
}


rule SMB_File_Delete
{
    strings:
        $a = "SMB2 SET_INFO"
        $b = "FileDispositionInformation"
        $c = "Delete: True"
    condition:
        any of them
}


rule SMB_File_Rename
{
    strings:
        $a = "SMB2 SET_INFO"
        $b = "FileRenameInformation"
    condition:
        all of them
}


import "math"

rule Mass_File_Encryption_Extensions
{
    strings:
        $a = ".locked"
        $b = ".encrypted"
        $c = ".crypt"
        $d = ".crypto"
        $e = ".enc"

    condition:
        2 of them
}


rule High_Entropy_Encrypted_File
{
    condition:
        filesize > 50KB and
        math.entropy(0, filesize) > 7.2
}


rule Ransomware_Mass_Write
{
    strings:
        $a = "WriteFile"
        $b = "CreateFile"
        $c = "CloseHandle"
        $d = ".locked"
        $e = ".encrypted"

    condition:
        3 of them
}


rule NFS_File_Write
{
    meta:
        description = "Detect NFS file write operations"

    strings:
        $a = "NFS WRITE"
        $b = "NFSv3 WRITE"
        $c = "NFSv4 COMPOUND"
        $d = "PUTFH"

    condition:
        any of them
}

rule NFS_File_Delete
{
    strings:
        $a = "NFS REMOVE"
        $b = "NFS RENAME"
        $c = "NFS SETATTR"
    condition:
        any of them
}

rule FTP_File_Upload
{
    meta:
        description = "Detect FTP upload activity"

    strings:
        $a = "STOR "
        $b = "APPE "
        $c = "PUT "
        $d = "ftp-data"
    condition:
        any of them
}

rule FTP_Binary_Upload
{
    strings:
        $a = "TYPE I"
        $b = "STOR"
        $c = "PASV"
    condition:
        all of them
}

rule HTTP_File_Upload
{
    meta:
        description = "Detect HTTP file upload"

    strings:
        $a = "POST /"
        $b = "multipart/form-data"
        $c = "Content-Disposition: form-data"
        $d = "filename="

    condition:
        2 of them
}

rule HTTP_PUT_Upload
{
    strings:
        $a = "PUT /"
        $b = "Content-Length"
        $c = "application/octet-stream"
    condition:
        2 of them
}

rule Lateral_Movement_File_Copy
{
    strings:
        $a = "psexec"
        $b = "wmic"
        $c = "copy \\\\"
        $d = "ADMIN$"
        $e = "C$\\"

    condition:
        any of them
}

rule SMB_Lateral_Copy
{
    strings:
        $a = "SMB2 WRITE"
        $b = "IPC$"
        $c = "ADMIN$"
    condition:
        2 of them
}

rule Bulk_Data_Exfiltration
{
    strings:
        $a = "zip "
        $b = "tar "
        $c = "7z "
        $d = "rar "

    condition:
        any of them
}

rule Suspicious_Data_Transfer
{
    strings:
        $a = "scp "
        $b = "rsync "
        $c = "sftp "
        $d = "curl -T"
        $e = "wget --post-file"
    condition:
        any of them
}

rule Data_Exfiltration_HighConfidence
{
    strings:
        $a = "zip"
        $b = "scp"
        $c = "rsync"
        $d = "multipart/form-data"
        $e = "STOR "

    condition:
        2 of them
}













