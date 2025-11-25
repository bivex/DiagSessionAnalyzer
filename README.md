# DiagSession Analyzer

DiagSession Analyzer is a .NET 9 console application for inspecting ETL/DiagSession traces,
loading symbols, and producing Visual Studio–style performance summaries.

## Highlights

- Converts ETL → ETLX with `TraceLogOptions` and forces symbol resolution automatically.
- Animated progress bar that shows downloaded megabytes plus “skip if stuck” logic.
- Optional PID filter with dedicated statistics and call tree output.
- Multiple leaderboards (exclusive/inclusive samples, self/total CPU time).
- Visual Studio–style Call Tree (inclusive vs. exclusive time and percentages).

## Usage

```bash
dotnet run -- <path_to_etl> [options]
```

### Common Options

| Option | Description |
| --- | --- |
| `<path_to_etl>` | Path to the source ETL/DiagSession file (required). |
| `--top N` | Number of rows in leaderboard tables (default: 50). |
| `--pid PID` / `-p PID` | Focus on a specific process ID and enable call tree output. |
| `--symbols PATH` | Override `_NT_SYMBOL_PATH` (symbol server + cache definition). |
| `--verbose` | Print detailed reflection/symbol-loading diagnostics. |
| `--timeout SECONDS` | Skip modules if symbol download shows no progress in this window. |
| `--skip-size MB` | Abort symbol download if total loaded MB exceed this threshold. |

### Example Commands

```bash
# Analyze entire trace
dotnet run -- ..\sc.user_aux.etl

# Show top 100 functions
dotnet run -- ..\sc.user_aux.etl --top 100

# Focus on InterruptEstimator process (PID 4036)
dotnet run -- ..\sc.user_aux.etl --pid 4036

# Aggressive skip policy (timeout 10s, skip >10 MB modules)
dotnet run -- ..\sc.user_aux.etl --timeout 10 --skip-size 10
```

## Output Overview

- **Top Functions by Exclusive/Inclusive Samples** – sample counts and percentages.
- **Top Functions by Self/Total CPU Time (ms)** – time-based views using profiler interval.
- **Module Statistics** for the filtered PID (function count + sample totals per module).
- **Call Tree for PID …** – hierarchical tree identical to Visual Studio Profiler:

```
Function Name                                            Total CPU    Self CPU     Total %   Self %
---------------------------------------------------------------------------------------------------
+ InterruptEstimator (PID: 4036)                        246.00        0.00        100.00%   0.00%
  ├─ [ntdll]                                            179.00        0.00         72.76%   0.00%
  │  └─ BaseThreadInitThunk [kernel32]                  179.00        0.00         72.76%   0.00%
  │     ├─ WorkloadThread [interruptestimator]          117.00        0.00         47.56%   0.00%
  │     │  └─ SleepEx [kernelbase]                       80.00        4.00         32.52%   1.63%
  │     │     └─ ...
```

## Requirements & Notes

- .NET 9.0 SDK or newer.
- `_NT_SYMBOL_PATH` must point to a valid symbol cache/server (e.g., `srv*C:\Temp\SymbolCache*https://msdl.microsoft.com/download/symbols`).
- ETL traces need stack sampling (PerfInfo/StackWalk events) for full call-tree accuracy.
- Existing `.etlx` files are reused; delete them to force symbol regeneration.

## Tags

`ETL analysis`, `DiagSession`, `TraceEvent`, `PerfView`, `Visual Studio profiler`,
`call tree`, `symbol loading`, `Windows performance`, `stack sampling`,
`interrupt estimator`, `CPU profiling`, `ETLX`, `diagnostics tooling`

