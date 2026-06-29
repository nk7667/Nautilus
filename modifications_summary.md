# C2 Evasion Modifications Summary

## Target Detection: trojan.overlord (16/71 VT detections)

### Modified Files

#### 1. evasion/apiresolve_windows.go
- **Changes**: 
  - Replaced simple XOR encryption with multi-layer encryption (round XOR + bit rotation)
  - Added dynamic key derivation function (`deriveKey`)
  - Increased key space from single byte to position-dependent keys
  - Updated all encrypted strings with new ciphertext
- **Purpose**: Bypass YARA string matching rules for DLL/API names
- **Detection Impact**: Eliminates static string signatures like "ntdll", "kernel32", "NtAllocateVirtualMemory"

#### 2. core/shellcode_windows.go
- **Changes**:
  - Added random delays between API calls (50-100ms)
  - Added memory write obfuscation with random delays
  - Added random callback selection (EnumWindows vs EnumChildWindows)
- **Purpose**: Break timing-based detection signatures
- **Detection Impact**: Thwarts behavioral analysis and ML-based API call pattern detection

#### 3. c2/transport/http.go
- **Changes**:
  - Added random User-Agent rotation (7 different browsers)
  - Added random Referer rotation (8 different sites)
  - Added modern browser headers (Sec-Ch-Ua, Sec-Fetch-*, X-Requested-With)
  - Increased jitter from 20% to 30%
- **Purpose**: Disguise C2 traffic as legitimate browser requests
- **Detection Impact**: Bypasses network-based detection rules

#### 4. build.ps1
- **Changes**:
  - Added `-trimpath` flag to remove build paths
  - Added `-gcflags "all=-l -N"` to disable inlining and optimizations
  - Extended sensitive strings list (added "nautilus", "fish", "C2", "implant", "stager", etc.)
  - Increased total patterns from 20 to 40+
- **Purpose**: Eliminate Go binary fingerprints
- **Detection Impact**: Removes 666+ occurrences of sensitive strings

### Detection Results (Before vs After)

| Detection Type | Before | After |
|----------------|--------|-------|
| Static Strings (ntdll) | ✅ Found | ❌ Not found |
| Static Strings (kernel32) | ✅ Found | ❌ Not found |
| Static Strings (VirtualAlloc) | ✅ Found | ❌ Not found |
| Static Strings (EnumWindows) | ✅ Found | ❌ Not found |
| Static Strings (shellcode) | ✅ Found | ❌ Not found |
| Go build ID | ✅ Present | ❌ Removed |
| Rich Header | ✅ Present | ❌ Cleared |

---

## Round 2 Optimization: Addressing Wacapew.C!ml (8/71 VT detections)

### Target Detection: Microsoft Program:Win32/Wacapew.C!ml, SentinelOne Static AI

### Additional Modified Files

#### 1. evasion/crypto.go
- **Changes**:
  - Renamed constant `xk` to `cryptoXk` to resolve naming conflict with apiresolve_windows.go
  - Preserved multi-layer encryption (XOR + bit rotation) for library name decryption
- **Purpose**: Fix compilation errors and maintain string obfuscation

#### 2. c2/encode/packet.go
- **Changes**:
  - Added XOR-encrypted byte arrays for message type constants (msgReg, msgHeart, msgTask, etc.)
  - Added decryption function `decMsgType()` with position-dependent XOR
  - Replaced direct constant references with encrypted lookups
- **Purpose**: Obfuscate C2 protocol constants that may trigger YARA rules

#### 3. core/shellcode_windows.go
- **Changes**:
  - Replaced direct `base64.StdEncoding` usage with custom implementation
  - Encrypted memory operation constants (memCommit, memReserve, pageRW, pageRX)
  - Renamed functions to avoid static detection patterns
- **Purpose**: Hide crypto and memory operation patterns from ML detection

#### 4. shellcode_handler_windows.go
- **Changes**:
  - Added explicit `[]byte` conversion for payload parameter
  - Fixed type mismatch between string and []byte
- **Purpose**: Ensure successful compilation with updated core functions

#### 5. evasion-tools/postprocess.go (NEW)
- **Changes**:
  - Created efficient Go-based post-processing tool
  - Extended sensitive strings list (added runtime, crypto, net patterns)
  - Added 32KB random overlay with fake ZIP signature
- **Purpose**: Replace slow PowerShell post-processing with Go implementation

#### 6. build.ps1
- **Changes**:
  - Increased overlay from 16KB to 32KB
  - Added more Go runtime fingerprints to zeroing list
  - Extended sensitive patterns (golang.org/x/crypto, crypto/*, net/*, reflect.TypeOf, fmt.Sprintf)
- **Purpose**: Larger file size and more comprehensive string removal to evade ML detection

### Post-Processing Results

- **Sensitive strings zeroed**: 3302 occurrences
- **Rich Header**: Cleared
- **Overlay**: 32768 bytes with fake ZIP signature
- **Final file size**: 9.13 MB

### File Hash (SHA256)
```
89B5BDA8E7FFC79B01FE8316A2A31A13BD33664C9414AB89F16646B4F9C2A67E
```

### Build Command Used

```powershell
# Step 1: Compile
go build -buildvcs=false -o fish.exe .

# Step 2: PE timestamp patch
go run -buildvcs=false ./evasion-tools/pepatch.go fish.exe

# Step 3: String zeroing + overlay
go run -buildvcs=false ./evasion-tools/postprocess.go fish.exe
```

### VirusTotal Link
Upload to: https://www.virustotal.com/gui/file/89B5BDA8E7FFC79B01FE8316A2A31A13BD33664C9414AB89F16646B4F9C2A67E

---

## Round 3 Optimization: Import Table Dilution (7/71 VT detections)

### Target Detection: Microsoft Wacatac.B!ml, CrowdStrike Falcon, Symantec ML

### Key Strategy: Add legitimate Windows API imports to dilute suspicious import ratio

### Modified Files

#### 1. evasion/legitimate_apis_windows.go (NEW)
- **Changes**:
  - Added imports from gdi32.dll (CreateSolidBrush, DeleteObject, DrawTextW, GetDC, ReleaseDC, CreateFontW)
  - Added imports from shell32.dll (SHGetFolderPathW, SHGetKnownFolderPath)
  - Added imports from ole32.dll (CoInitialize, CoUninitialize)
  - Added imports from advapi32.dll (RegOpenKeyExW, RegCloseKey)
  - Created `InitLegitimateAPIs()` function that calls these APIs at startup
- **Purpose**: Dilute the import table with legitimate API calls, making the binary look like a normal Windows application
- **Detection Impact**: Reduces ML model confidence by adding positive signals (GDI rendering, shell operations, COM initialization)

#### 2. main.go
- **Changes**:
  - Added `evasion.InitLegitimateAPIs()` call at the beginning of main()
- **Purpose**: Ensure legitimate APIs are imported and called during execution

### Post-Processing Results

- **Sensitive strings zeroed**: 3316 occurrences
- **Rich Header**: Cleared
- **Overlay**: 32768 bytes with fake ZIP signature
- **Final file size**: 9.13 MB
- **Legitimate APIs added**: 13 new API imports from 4 DLLs

### File Hash (SHA256)
```
8352BCB04EE04254AB352132B166A1C0F3481217AA79622E2FF882E9031DF344
```

### Build Command Used

```powershell
go build -buildvcs=false -o fish.exe .
go run -buildvcs=false ./evasion-tools/pepatch.go fish.exe
go run -buildvcs=false ./evasion-tools/postprocess.go fish.exe
```

### VirusTotal Link
Upload to: https://www.virustotal.com/gui/file/8352BCB04EE04254AB352132B166A1C0F3481217AA79622E2FF882E9031DF344

---

## Round 4 Optimization: PE Structure Normalization (7/71 VT detections)

### Target Detection: Microsoft PUA:Win32/Puwaders.C!ml, AhnLab R777421

### Key Strategy: Normalize PE structure to match legitimate Windows applications

### Modified/New Files

#### 1. .rsrc.json (NEW)
- **Changes**: Configuration file for rsrc tool
- **Purpose**: Define resources to embed in PE binary

#### 2. app.exe.manifest (NEW)
- **Changes**: Windows application manifest with supported OS declarations
- **Purpose**: Add legitimate manifest resource section

#### 3. rsrc.syso (NEW)
- **Changes**: COFF resource file generated by rsrc tool
- **Purpose**: Go compiler automatically embeds this as .rsrc section

#### 4. evasion-tools/postprocess.go (MODIFIED)
- **Changes**: Added PE section renaming function
- **Section mapping**:
  - `.go.buildinfo` → `.rdata`
  - `.gopclntab` → `.data`
  - `.noptrdata` → `.rdata`
  - `.ptrdata` → `.data`
  - `.textflag` → `.text`
  - `.itablink` → `.rdata`
  - `.gofunctab` → `.data`
  - `.rodata` → `.rdata`
  - `.typelink` → `.rdata`
  - Other Go-specific sections → `.data`
- **Purpose**: Remove Go compiler fingerprints from PE header

### Post-Processing Results

- **Sensitive strings zeroed**: 3307 occurrences
- **Rich Header**: Cleared
- **Overlay**: 32768 bytes with fake ZIP signature
- **Sections renamed**: 13 Go-specific sections → standard MSVC names
- **.rsrc section**: Successfully embedded with manifest
- **Final file size**: 9.13 MB

### File Hash (SHA256)
```
BFA779ADE66E2D4A73556FFDF513E18E5E4F9B359186E6989837EBA66116364C
```

### Build Command Used

```powershell
rsrc -manifest app.exe.manifest -o rsrc.syso
go build -buildvcs=false -o fish.exe .
go run -buildvcs=false ./evasion-tools/pepatch.go fish.exe
go run -buildvcs=false ./evasion-tools/postprocess.go fish.exe
```

### VirusTotal Link
Upload to: https://www.virustotal.com/gui/file/BFA779ADE66E2D4A73556FFDF513E18E5E4F9B359186E6989837EBA66116364C
