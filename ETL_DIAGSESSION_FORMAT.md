# ETL and diagsession File Format 

## Overview

This document describes the structure of ETL (Event Tracing for Windows) and diagsession (Visual Studio diagnostic session) files, based on analysis of the code from Visual Studio Performance Tools.

## Structure of VSP Files (Visual Studio Performance)

VSP files are binary files created by Visual Studio to store profiling data.

### File Header

* **Header size**: 19,752 bytes
* **Magic number**: `1162561869` (0x454C504D = `"ELPM"` in ASCII)
* **Check**: The first 4 bytes of the file must contain this value

### Header Structure (`_FILEHEADER`)

#### Main fields (offsets in bytes):

```text
Offset  Size  Field                    Description
------  ----  ------                   -----------
0       4     Magic Number             "ELPM" (1162561869)
4       4     HeaderSize               Header size
8       4     MajorFileVersion         File major version
12      4     MajorProductVersion      Product major version (low 2 bytes)
        2     MinorProductVersion      Product minor version (high 2 bytes)
16      4     BuildNumber              Build number
20     64     VersionString            Version string
84      4     MinorFileVersion         File minor version
88      6     CreationTime             Creation date/time (year, month, day, hour, minute, second)
104     4     ProcessHighWater         Maximum process ID
108     4     TotalProcesses           Total processes
112     4     NumberOfProcesses        Number of processes
116     4     ThreadHighWater          Maximum thread ID
120     4     TotalThreads             Total threads
124     4     NumberOfThreads          Number of threads
140     4     BufferSize               Buffer size
144     4     NumberOfBuffers          Number of buffers
148     4     MaxThreads               Maximum number of threads
152     4     MaxProcesses             Maximum number of processes
156     4     Flags                    Flags (bits):
                                        - Bit 3: IsAllocation
                                        - Bit 5: Is64Bit
                                        - Bit 6: IsLifetime
                                        - Bit 7: IsManaged
                                        - Bit 8: IsUnsupportedCLR
                                        - Bit 9: IsDhpHappened
                                        - Bit 10: IsTip
                                        - Bit 11: IsJScript
                                        - Bit 12: IsUmsAppTerminated
164     4     CollectionType           Collection type:
                                        1 = ResourceContention
                                        2 = Instrumentation
                                        4 = Sampling
                                        8 = Coverage
                                        16 = Concurrency
168     4     SamplingType             Sampling type:
                                        1 = CycleSampling
                                        3 = PageFaultSampling
                                        4 = SysCallSampling
                                        5 = PerfCounterSampling
172     4     SamplingInterval         Sampling interval
180     4     IsGracefulExit           Graceful exit flag
184     4     TotalSamples             Total samples
188     4     NumApplicationSamples    Application samples
192     4     NumOverheadSamples       Overhead samples
196     4     NumKernelSamples         Kernel samples
200     4     NumOtherAppSamples       Other application samples
204     4     NumCallbackSamples       Callback samples
208     4     NumStackWalks            Number of stacks
212     4     NumBrokenStacks          Broken stacks
216     4     NumAbortedSamples        Aborted samples
524     4     NumCounters              Number of counters
544     N*80  CounterNames            Counter names (80 bytes each)
2192    8     LastIndexBlockOffset     Offset of the last index block
2200    4     NumIndexBlocks           Number of index blocks
2204    8     LastSymbolBlockOffset    Offset of the last symbol block
2212    4     NumSymbolBlocks          Number of symbol blocks
2216    4     NumBlocks                Number of blocks
2220   32     MachineName              Machine name (UNICODE, 16 characters)
2252    4     NumCpus                  Number of CPUs
2256    4     CpuType                  CPU type:
                                        1 = Intel
                                        2 = UMC
                                        3 = AMD
                                        4 = Cyrix
                                        5 = Nexgen
                                        6 = Centaur
2260    4     CpuArchitecture          CPU architecture:
                                        0 = Intel
                                        1 = Mips
                                        2 = Alpha
                                        3 = Ppc
                                        4 = Hitachi
                                        5 = Arm
2264    4     CpuInfo                  CPU info (Family, Model, Stepping)
2268    4     CpuMhz                   CPU frequency in MHz
2276    4     OSMajorVersion           OS major version
2280    4     OSMinorVersion           OS minor version
2284    4     OSBuildNumber            OS build number
2548    4     NumMessages              Number of messages
18696  520    KernelEtlPath            Path to kernel ETL file (UNICODE, 260 characters)
19216  520    AppEtlPath               Path to application ETL file (UNICODE, 260 characters)
```

### Reading a VSP File

```csharp
// Header reading pseudocode
void ReadVspHeader(string fileName) {
    using (var file = File.OpenRead(fileName)) {
        // Read the first 4 bytes – the magic number
        var magic = ReadUInt32(file);
        if (magic != 1162561869) {
            throw new Exception("Invalid VSP file");
        }
        
        // Read the whole header (19,752 bytes)
        var header = new byte[19752];
        file.Read(header, 0, 19752);
        
        // Extract paths to ETL files
        var kernelEtlPath = ReadUnicodeString(header, 18696, 260);
        var appEtlPath = ReadUnicodeString(header, 19216, 260);
        
        // Extract other information
        var is64Bit = (header[156] & 0x20) != 0;
        var collectionType = BitConverter.ToUInt32(header, 164);
        // ...
    }
}
```

## Structure of ETL Files

ETL (Event Tracing for Windows) files contain Windows tracing events.

### Reading ETL Files

ETL files are read through the `EtwReader` class from VSPerfReader:

```csharp
public class EtwReader {
    public EtwReader(string etlFile, string vspFilePath, IFilter filter, 
                     MofDescriptionData mofDescriptionData, ProcessList processList);
    
    public bool Read();
    public event EventHandler<EtwEventArgs> OnNewEvent;
    public EtwCollection AllEvents { get; }
}
```

### Resolving Paths to ETL Files

`EtwReader.ResolveFileLocation()` searches for ETL files in the following order:

1. **Absolute path**: If the file exists at the specified path
2. **Current directory**: Searches for a file with the same name in the current directory
3. **Relative to the VSP file**: Searches for the file in the directory where the VSP file is located
4. **Empty path**: If the path is empty, it is considered valid

```csharp
private bool ResolveFileLocation() {
    if (File.Exists(this.m_etlFile)) {
        return true;
    }
    
    string fileName = Path.GetFileName(this.m_etlFile);
    if (File.Exists(fileName)) {
        this.m_etlFile = fileName;
        return true;
    }
    
    string path = Path.Combine(Path.GetDirectoryName(this.m_vspFilePath), fileName);
    if (File.Exists(path)) {
        this.m_etlFile = path;
        return true;
    }
    
    if (string.IsNullOrEmpty(this.m_etlFile)) {
        return true; // Empty path is allowed
    }
    
    return false;
}
```

### Event Decoding

ETL events are decoded via:

* **TdhDecoder**: If available (Windows 6.0+)
* **MofDecoder**: Fallback option

Events contain:

* `ProcessId`: Process ID
* `ThreadId`: Thread ID
* `Timestamp`: Timestamp
* `EventData`: Event data (depends on event type)

## Structure of diagsession Files

diagsession files are containers created by Visual Studio for diagnostic sessions.

### Contents of a diagsession

A diagsession file typically contains:

1. **VSP files** (if any): Main profiling files
2. **ETL files**:

   * `sc.user_aux.etl`: Auxiliary system events
   * `kernel.etl`: Kernel events (can be referenced in VSP as `KernelEtlPath`)
   * `app.etl`: Application events (can be referenced in VSP as `AppEtlPath`)
3. **Other files**: Metadata, configuration, etc.

### Relationship Between Files

```text
diagsession/
├── Report*.diagsession          # Main session file
├── *.vsp                        # VSP files (if any)
│   └── (contains paths to ETL in the header)
├── sc.user_aux.etl              # Auxiliary events
├── kernel.etl                   # Kernel events (may be referenced in VSP)
└── app.etl                      # Application events (may be referenced in VSP)
```

### Event Types in sc.user_aux.etl

Main event providers:

1. **Perfinfo** (~50%): CPU profiling events
2. **Image** (~28%): Module load/unload (DLL, EXE)
3. **Thread** (~12%): Thread creation/termination
4. **ImageId** (~4%): Image identifiers
5. **StackWalk** (~3%): Call stacks
6. **SysConfig** (~1%: System configuration
7. **Process** (~1%): Process creation/termination
8. **EventTrace**: Trace headers
9. **SysConfigEx**: Extended system configuration

### ETL Event Structure

```json
{
  "id": "ProviderName_EventId_Version",
  "providerName": "ProviderName",
  "providerGuid": "guid",
  "timestamp": "DateTimeOffset",
  "ticks": "long",
  "processId": "int",
  "processName": "string",
  "imageName": "string",
  "threadId": "int",
  "data": {
    "EventId": "int",
    "Version": "int",
    "Level": "string",
    "Opcode": "string",
    "Task": "string",
    "Keyword": "string",
    "Is32Bit": "bool",
    "EventName": "string"
    // Additional fields depending on event type
  }
}
```

## Usage Examples

### Reading a VSP File and Extracting ETL Paths

```csharp
var vspFile = new VSPFile();
vspFile.OpenFile("session.vsp");

// Get the header
var header = vspFile.HeaderProperties;

// Extract paths to ETL files
var kernelEtlPath = header["KernelEtlPath"].Value;
var appEtlPath = header["AppEtlPath"].Value;

// Create readers for ETL files
var kernelEtwReader = vspFile.ConstructKernelEtwReader(filter);
var appEtwReader = vspFile.ConstructEtwReader(filter);

// Read events
kernelEtwReader.Read();
appEtwReader.Read();

// Process events
foreach (var evt in kernelEtwReader.AllEvents) {
    Console.WriteLine($"Event: {evt.ProcessId}, {evt.ThreadId}, {evt.Timestamp}");
}
```

### Searching for ETL Files in a diagsession

```csharp
// 1. Open the VSP file (if present)
var vspFile = new VSPFile();
vspFile.OpenFile("session.vsp");

// 2. Get ETL paths from the header
var kernelEtlPath = vspFile.Header.KernelEtlPath;
var appEtlPath = vspFile.Header.AppEtlPath;

// 3. EtwReader automatically searches files:
//    - By absolute path
//    - In the current directory
//    - In the VSP file directory
var etwReader = new EtwReader(kernelEtlPath, "session.vsp", filter, mofData, processList);
etwReader.Read();
```

## Extracting Functions and Top Functions by Calls from sc.user_aux.etl

### Event Structure in the ETL File

The ETL file contains two main event types used for profiling:

1. **PerfInfo events (SampleProf)**:

   * Contain `InstructionPointer` (IP) – address of the instruction where the code was executed
   * Contain `ThreadId` – ID of the thread where the code was executed
   * Contain `Timestamp` – event time
   * **Do not contain** the full call stack

2. **StackWalk events (Stack)**:

   * Contain `StackProcess` – process PID (in hex, e.g. `0x3264`)
   * Contain `StackThread` – thread TID
   * Contain `Stack1`, `Stack2`, ... `Stack32` – function addresses in the call stack
   * Contain `EventTimeStamp` – event time
   * **Contain the full call stack** (up to 32 levels)

### Relationship Between Events

* **PerfInfo.InstructionPointer** must match **StackWalk.Stack1** (the first address in the stack)
* **PerfInfo.ThreadId** must match **StackWalk.StackThread**
* Events are correlated by time and thread

### Function Extraction Process

#### 1. Processing Events via `SampleEventDecoder`

```csharp
// SampleEventDecoder processes events from the ETL
// For an event of type 215801064 (Stack Sample):
ProcessStack<unsigned __int64>(ProcessInfo proc, ulong timeStamp, uint numEntries, ulong* stack)
{
    // 1. Reverse the stack (Stack1 becomes the last element)
    ulong[] reversedStack = ReverseStack(numEntries, stack);
    
    // 2. Add the stack to CallTreeSampling
    callTreeSampling.AddStack(reversedStack, timeStamp, proc, 0UL, true);
}
```

#### 2. Building the Call Tree (`CallTreeSampling`)

```csharp
// CallTreeSampling.AddStack processes each stack:
public bool AddStack(IEnumerable<ulong> stack, ulong timestamp, ProcessInfo procInfo, ulong allocationSize, bool addHiddenNodes)
{
    // 1. Convert addresses to SampleInfo
    List<SampleInfo> sampleInfos = StackTransform(stack, procInfo, timestamp, addHiddenNodes);
    
    // 2. For each address in the stack:
    foreach (SampleInfo si in sampleInfos)
    {
        // 3. Create or find CallTreeNodeSampling
        CallTreeNodeSampling node = PushingOnToStack(currentNode, si, isInlined);
        
        // 4. Increase counters:
        node.InclusiveSamples++;  // All function calls
        if (isEnd)  // If this is the last element of the stack (a leaf)
        {
            node.ExclusiveSamples++;  // Direct function calls
        }
    }
}
```

#### 3. Creating `SampleInfo` for Each Address

```csharp
// SampleInfo stores function information:
public SampleInfo(Symbols symbols, ProcessInfo procInfo, ulong ip, ulong timestamp)
{
    this.IP = ip;  // Instruction address
    
    // 1. Check if this is managed code (JIT event)
    JitEvent jitEvent = procInfo.Jits.FindJitEvent(timestamp, ip);
    
    if (jitEvent != null)
    {
        // Managed code
        this.FunctionAddress = jitEvent.Function.Start;
        this.FunctionToken = jitEvent.Function.Token;
        this.MethodId = jitEvent.Function.MethodId;
        this.CodeType = TypeOfCode.Managed;
    }
    else
    {
        // Native code
        symbols.GetNearestSymbol(ip, timestamp, out functionAddress, out moduleId);
        this.FunctionAddress = functionAddress;
        this.ModuleId = moduleId;
        this.CodeType = TypeOfCode.Native;
    }
}
```

#### 4. Getting the Function Name

```csharp
// CallTreeNodeSampling.LookupFunctionName():
public string LookupFunctionName()
{
    if (CodeType == TypeOfCode.Native)
    {
        // For native code use Symbols
        return symbols.GetNativeFunctionName(Address, Timestamp);
        // Or via EtlProcessSymbols:
        IEtlNativeModuleSymbols nativeModule = symbols.EtlProcessSymbols.GetNativeModuleSymbols(Address, Timestamp);
        return nativeModule.GetFunctionName(Address);
    }
    else if (CodeType == TypeOfCode.Managed)
    {
        // For managed code use FunctionToken
        return symbols.GetManagedFunctionName(ModuleId, FunctionToken);
        // Or via EtlProcessSymbols:
        IEtlManagedModuleSymbols managedModule = symbols.EtlProcessSymbols.GetManagedModuleSymbols(EtlModuleId);
        return managedModule.GetFunctionName(FunctionToken, MethodId);
    }
}
```

### Top Functions by Calls

#### Metrics for Counting

1. **ExclusiveSamples** – number of direct calls to the function (leaf in the call tree)
2. **InclusiveSamples** – total number of calls to the function (including calls from child functions)
3. **TotalSamples** – total number of all samples in `CallTreeSampling`

#### Algorithm for Getting Top Functions

```csharp
// 1. Get all nodes from CallTreeSampling
Collection<CallTreeNode> allNodes = new Collection<CallTreeNode>();
callTreeSampling.CopyTo(allNodes);

// 2. Sort by ExclusiveSamples or InclusiveSamples
var topFunctions = allNodes
    .Cast<CallTreeNodeSampling>()
    .Where(n => !n.IsRoot && n.ExclusiveSamples > 0)
    .OrderByDescending(n => n.ExclusiveSamples)  // or InclusiveSamples
    .Take(100)  // Top 100
    .Select(n => new
    {
        FunctionName = n.LookupFunctionName(),
        ModuleName = n.LookupModulePath(),
        ExclusiveSamples = n.ExclusiveSamples,
        InclusiveSamples = n.InclusiveSamples,
        ExclusivePercent = (n.ExclusiveSamples * 100.0) / callTreeSampling.TotalSamples,
        InclusivePercent = (n.InclusiveSamples * 100.0) / callTreeSampling.TotalSamples,
        Address = n.Address,
        CodeType = n.CodeType
    })
    .ToList();
```

### `CallTreeNodeSampling` Data Structure

```csharp
public class CallTreeNodeSampling : CallTreeNode
{
    // Function address
    public ulong Address { get; set; }
    
    // For managed code
    public uint FunctionToken { get; set; }
    public ulong MethodId { get; set; }
    public long EtlModuleId { get; set; }
    
    // Code type
    public TypeOfCode CodeType { get; set; }  // Native, Managed, Script, Unknown
    
    // Call counters
    public ulong ExclusiveSamples { get; set; }   // Direct calls
    public ulong InclusiveSamples { get; set; }   // All calls (including children)
    
    // For inlined functions
    public ulong InlinedExclusiveSamples { get; set; }
    public ulong InlinedInclusiveSamples { get; set; }
    
    // Child functions (called by this function)
    public Collection<CallTreeNode> Callees { get; set; }
    
    // Parent function
    public CallTreeNode ParentNode { get; set; }
    
    // Methods for retrieving information
    public string LookupFunctionName()  // Function name
    public string LookupModulePath()    // Module path
    public uint LookupLineNumber()      // Line number
    public SourceFileInfo LookupSourceFile()  // Source file
}
```

### Example of the Full Process

```csharp
// 1. Create VSPFile and load ETL
var vspFile = new VSPFile();
vspFile.OpenFile("session.vsp");

// 2. Get paths to ETL files
string kernelEtlPath = vspFile.Header.KernelEtlPath;
string appEtlPath = vspFile.Header.AppEtlPath;

// 3. Create SampleEventDecoder
var sampleDecoder = new SampleEventDecoder(vspFile);

// 4. Process events (automatically called while reading ETL)
// SampleEventDecoder.ProcessStack is called for each StackWalk event

// 5. Get CallTreeSampling for a process
ProcessInfo process = vspFile.Processes[processId];
CallTreeSampling callTree = (CallTreeSampling)process.CallTree;

// 6. Get all nodes
Collection<CallTreeNode> allNodes = new Collection<CallTreeNode>();
callTree.CopyTo(allNodes);

// 7. Get top functions
var topFunctions = allNodes
    .Cast<CallTreeNodeSampling>()
    .Where(n => !n.IsRoot)
    .OrderByDescending(n => n.ExclusiveSamples)
    .Take(50)
    .Select(n => new
    {
        Name = n.LookupFunctionName(),
        Module = Path.GetFileName(n.LookupModulePath()),
        Exclusive = n.ExclusiveSamples,
        Inclusive = n.InclusiveSamples,
        Percent = (n.ExclusiveSamples * 100.0) / callTree.TotalSamples
    });
```

### Important Notes

1. **The stack is reversed**: `Stack1` (first address) becomes the last element in the array.
2. **ExclusiveSamples** – the number of times a function was a leaf in the stack (executed directly).
3. **InclusiveSamples** – the number of times a function appeared in the stack (including calls from child functions).
4. **TotalSamples** – the total number of processed stacks.
5. **For managed code**, `FunctionToken` and `MethodId` are required to identify a function.
6. **For native code**, `Address` and `Timestamp` are used to look up symbols.
7. **Symbols** are loaded through the `Symbols` class, which uses MSITSDI (Microsoft Symbol Server).

## Notes

1. **VSP files** store paths to ETL files in the header, but these paths may be relative.
2. **ETL files** can be located in the same directory as the VSP file.
3. **diagsession** is a container that may hold multiple files.
4. **sc.user_aux.etl** is an auxiliary system-event file, not necessarily associated with a VSP file.
5. Paths in VSP files are stored as UNICODE strings (260 characters = 520 bytes).
6. **StackWalk events** contain the full call stack (up to 32 levels).
7. **PerfInfo events** contain only the `InstructionPointer`, but not the full stack.
8. **The link between events** is based on `ThreadId` and the match of `InstructionPointer` with `Stack1`.

## References

* Visual Studio Performance Tools (VSPerfReader.dll)
* Windows Event Tracing (ETW)
* Microsoft.Windows.EventTracing library
* MSITSDI (Microsoft Symbol Server Interface)
