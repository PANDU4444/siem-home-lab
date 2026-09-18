/*
   siem-home-lab :: YARA ruleset

   Scanned by the Wazuh active-response hook (yara/active-response/yara.sh)
   whenever FIM reports a new or modified file in a write-heavy directory
   (/tmp, the agent home, /var/www). One file per invocation, so the scan stays
   cheap enough to run inline on every FIM event.

   A match is written to active-responses.log, decoded by local_decoder.xml,
   and alerted on by rule 100141 at level 12.
*/

rule SHL_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test string - proves the FIM to YARA to alert path works"
        author      = "siem-home-lab"
        severity    = "low"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule SHL_Linux_Reverse_Shell
{
    meta:
        description = "Common Linux reverse shell one-liners"
        author      = "siem-home-lab"
        severity    = "high"
        mitre       = "T1059.004"
    strings:
        $bash_tcp  = "/dev/tcp/" ascii
        $nc_e      = /nc\s+-[a-zA-Z]*e[a-zA-Z]*\s/ ascii
        $py_sock   = "socket.socket(socket.AF_INET" ascii
        $py_dup2   = "os.dup2(" ascii
        $pty_spawn = "pty.spawn(" ascii
        $perl_sock = "IO::Socket::INET" ascii
    condition:
        $bash_tcp or $nc_e or $perl_sock or 2 of ($py_sock, $py_dup2, $pty_spawn)
}

rule SHL_PHP_Webshell
{
    meta:
        description = "PHP webshell: dynamic execution driven by a request parameter"
        author      = "siem-home-lab"
        severity    = "critical"
        mitre       = "T1505.003"
    strings:
        $php   = "<?php"
        $req   = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/
        $exec1 = "shell_exec" ascii nocase
        $exec2 = "passthru" ascii nocase
        $exec3 = "proc_open" ascii nocase
        $exec4 = "system(" ascii nocase
        $exec5 = "eval(" ascii nocase
        $exec6 = "assert(" ascii nocase
        $b64   = "base64_decode" ascii nocase
    condition:
        $php and $req and (any of ($exec*) or $b64)
}

rule SHL_Obfuscated_Shell_Payload
{
    meta:
        description = "Encoded blob or remote download piped straight into an interpreter"
        author      = "siem-home-lab"
        severity    = "high"
        mitre       = "T1027"
    strings:
        $pipe_bash = /base64\s+(-d|--decode)[^\n]{0,40}\|\s*(ba)?sh/
        $pipe_py   = /echo\s+[A-Za-z0-9+\/=]{40,}[^\n]{0,20}\|\s*python/
        $curl_bash = /curl\s[^\n|]{4,200}\|\s*(ba)?sh/
        $wget_bash = /wget\s[^\n|]{4,200}\|\s*(ba)?sh/
    condition:
        any of them
}

rule SHL_Cryptominer_Config
{
    meta:
        description = "Cryptocurrency miner configuration or binary strings"
        author      = "siem-home-lab"
        severity    = "high"
        mitre       = "T1496"
    strings:
        $pool1  = "stratum+tcp://" ascii nocase
        $pool2  = "stratum+ssl://" ascii nocase
        $xmrig  = "xmrig" ascii nocase
        $algo   = "randomx" ascii nocase
        $donate = "donate-level" ascii nocase
    condition:
        $pool1 or $pool2 or ($xmrig and ($algo or $donate))
}

rule SHL_Cron_Persistence_Downloader
{
    meta:
        description = "Cron entry that fetches and executes remote code"
        author      = "siem-home-lab"
        severity    = "high"
        mitre       = "T1053.003"
    strings:
        $sched  = /[0-9\*\/,\-]{1,10}\s+[0-9\*\/,\-]{1,10}\s+[0-9\*\/,\-]{1,10}\s+[0-9\*\/,\-]{1,10}\s+[0-9\*\/,\-]{1,10}\s/
        $fetch1 = "curl" ascii
        $fetch2 = "wget" ascii
        $pipe   = /\|\s*(ba)?sh/
    condition:
        $sched and any of ($fetch*) and $pipe
}

rule SHL_Metasploit_Payload_Markers
{
    meta:
        description = "Strings commonly present in Meterpreter or msfvenom ELF payloads"
        author      = "siem-home-lab"
        severity    = "critical"
        mitre       = "T1059"
    strings:
        $mp1 = "meterpreter" ascii nocase
        $mp2 = "metsrv" ascii nocase
        $mp3 = "stdapi_" ascii
        $mp4 = "PayloadUUID" ascii
    condition:
        uint32(0) == 0x464c457f and any of them
}
