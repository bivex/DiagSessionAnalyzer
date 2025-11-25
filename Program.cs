using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DiagSessionAnalyzer;

class Program {
    static void Main ( string[] args )
    {
        if ( args.Length == 0 )
        {
        Console.WriteLine ( "Usage: DiagSessionAnalyzer <path_to_etl_file> [--top N] [--pid PID] [--symbols PATH] [--verbose] [--timeout SECONDS] [--skip-size MB]" );
        Console.WriteLine ( "Example: DiagSessionAnalyzer sc.user_aux.etl --top 50 --pid 4036" );
        Console.WriteLine ( "         DiagSessionAnalyzer sc.user_aux.etl --symbols \"srv*c:\\symbols*https://msdl.microsoft.com/download/symbols\"" );
        Console.WriteLine ( "         DiagSessionAnalyzer sc.user_aux.etl --verbose" );
        Console.WriteLine ( "         DiagSessionAnalyzer sc.user_aux.etl --timeout 30  (skip modules that take longer than 30 seconds)" );
        Console.WriteLine ( "         DiagSessionAnalyzer sc.user_aux.etl --skip-size 100  (skip modules if symbols exceed 100 MB)" );
            return;
        }

        string etlPath = args[0];
        int topCount = 50;
        uint? filterPid = null;
        string? symbolPath = null;
        bool verbose = false;
        int timeoutSeconds = 30; // Default timeout: 30 seconds
        double? maxSizeMB = null; // Maximum size per module in MB (null = no limit)

        // Parse arguments
        for ( int i = 1; i < args.Length; i++ )
        {
            if ( args[i] == "--top" && i + 1 < args.Length )
            {
                if ( int.TryParse ( args[i + 1], out int top ) )
                {
                    topCount = top;
                    i++;
                }
            }
            else if ( ( args[i] == "--pid" || args[i] == "-p" ) && i + 1 < args.Length )
            {
                if ( uint.TryParse ( args[i + 1], out uint pid ) )
                {
                    filterPid = pid;
                    i++;
                }
            }
            else if ( ( args[i] == "--symbols" || args[i] == "-s" ) && i + 1 < args.Length )
            {
                symbolPath = args[i + 1];
                i++;
            }
            else if ( args[i] == "--verbose" || args[i] == "-v" )
            {
                verbose = true;
            }
            else if ( ( args[i] == "--timeout" || args[i] == "-t" ) && i + 1 < args.Length )
            {
                if ( int.TryParse ( args[i + 1], out int timeout ) )
                {
                    timeoutSeconds = timeout;
                    i++;
                }
            }
            else if ( ( args[i] == "--skip-size" || args[i] == "--max-size" ) && i + 1 < args.Length )
            {
                if ( double.TryParse ( args[i + 1], out double maxSize ) )
                {
                    maxSizeMB = maxSize;
                    i++;
                }
            }
        }

        if ( !File.Exists ( etlPath ) )
        {
            Console.WriteLine ( $"Error: File not found: {etlPath}" );
            return;
        }

Console.WriteLine ( $"=== DiagSession Analyzer ===\n" );
        Console.WriteLine ( $"File: {etlPath}" );
        Console.WriteLine ( $"Size: {new FileInfo(etlPath).Length / 1024 / 1024} MB\n" );

        try
        {
            AnalyzeEtlFile ( etlPath, topCount, filterPid, symbolPath, verbose, timeoutSeconds, maxSizeMB );
        }
        catch ( Exception ex )
        {
            Console.WriteLine ( $"Error: {ex.Message}" );
            Console.WriteLine ( $"Stack trace: {ex.StackTrace}" );
        }
    }

    static void AnalyzeEtlFile ( string etlPath, int topCount, uint? filterPid, string? symbolPath, bool verbose, int timeoutSeconds = 30, double? maxSizeMB = null )
    {
        // Configure symbol path via environment variable BEFORE creating TraceLog
        string? originalSymbolPath = null;
        bool symbolPathSet = false;

        if ( !string.IsNullOrEmpty ( symbolPath ) )
        {
            // Save original value
            originalSymbolPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );

            // Format symbol path correctly - if it's a directory, use it as cache
            // Format: "srv*cache*server" for symbol server with cache
            string formattedSymbolPath = symbolPath;
            if ( Directory.Exists ( symbolPath ) )
            {
                // If it's a directory, use it as cache with Microsoft symbol server
                // Format: srv*cache*server means: use cache directory, and download from server if not found
                // Also add the directory itself as a direct path for local PDB files
                formattedSymbolPath = $"{symbolPath};srv*{symbolPath}*https://msdl.microsoft.com/download/symbols";
            }

            // Set new symbol path for both _NT_SYMBOL_PATH and _NT_ALT_SYMBOL_PATH
            Environment.SetEnvironmentVariable ( "_NT_SYMBOL_PATH", formattedSymbolPath );
            Environment.SetEnvironmentVariable ( "_NT_ALT_SYMBOL_PATH", formattedSymbolPath );
            symbolPathSet = true;

            if ( verbose )
            {
                Console.WriteLine ( $"Symbol path set to: {formattedSymbolPath}" );
                Console.WriteLine ( "Loading symbols (this may take a while on first run)...\n" );
            }
            else
            {
                Console.WriteLine ( $"Symbol path configured. Loading symbols...\n" );
            }
        }
        else
        {
            // Check if environment variable is already set
            string? envSymbolPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
            if ( !string.IsNullOrEmpty ( envSymbolPath ) )
            {
                if ( verbose )
                {
                    Console.WriteLine ( $"Using symbol path from _NT_SYMBOL_PATH: {envSymbolPath}" );
                    Console.WriteLine ( "Loading symbols (this may take a while on first run)...\n" );
                }
                else
                {
                    Console.WriteLine ( $"Using symbol path from _NT_SYMBOL_PATH. Loading symbols...\n" );
                }
            }
            else
            {
                if ( verbose )
                {
                    Console.WriteLine ( "No symbol path specified. Use --symbols to specify symbol path or set _NT_SYMBOL_PATH environment variable.\n" );
                }
            }
        }

        // Dictionary to store function call counts
        var functionStats = new Dictionary<string, FunctionStats>();
        var processNames = new Dictionary<uint, string>();
        var callTrees = new Dictionary<uint, CallTreeNode>(); // Root nodes for each process
        long totalStacks = 0;

        Console.WriteLine ( "Converting ETL to ETLX for symbol resolution (this may take a while)...\n" );

        // Convert ETL to ETLX for symbol resolution
        // Note: If symbol path was set, we may need to delete existing ETLX to force symbol loading
        string etlxPath = Path.ChangeExtension ( etlPath, ".etlx" );

        // If symbol path was set and ETLX exists, delete it to force symbol reload
        if ( symbolPathSet && File.Exists ( etlxPath ) )
        {
            if ( verbose )
            {
                Console.WriteLine ( "Deleting existing ETLX file to force symbol reload..." );
            }
            try
            {
                File.Delete ( etlxPath );
            }
            catch ( Exception ex )
            {
                if ( verbose )
                {
                    Console.WriteLine ( $"  Warning: Could not delete ETLX file: {ex.Message}" );
                }
            }
        }

        if ( !File.Exists ( etlxPath ) )
        {
            Console.WriteLine ( "Creating ETLX file for symbol resolution..." );

            // Try to use TraceLogOptions if available
            try
            {
                var createMethod = typeof ( TraceLog ).GetMethod ( "CreateFromEventTraceLogFile",
                                   new[] { typeof ( string ), typeof ( string ), typeof ( TraceLogOptions ) } );
                if ( createMethod != null )
                {
                    if ( verbose )
                    {
                        Console.WriteLine ( "  Using TraceLogOptions for symbol loading..." );
                    }

                    // Try to create TraceLogOptions with symbol loading enabled
                    var optionsType = typeof ( TraceLogOptions );
                    var options = Activator.CreateInstance ( optionsType )
                                  ?? throw new InvalidOperationException ( "Failed to create TraceLogOptions instance." );

                    // Get SymbolReaderOptions property
                    var symbolReaderOptionsProp = optionsType.GetProperty ( "SymbolReaderOptions",
                                                  System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                    if ( symbolReaderOptionsProp != null )
                    {
                        var symbolReaderOptionsType = symbolReaderOptionsProp.PropertyType;
                        var symbolReaderOptions = Activator.CreateInstance ( symbolReaderOptionsType );

                        if ( symbolReaderOptions != null && symbolPathSet )
                        {
                            var envSymbolPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );

                            if ( verbose )
                            {
                                Console.WriteLine ( $"  Configuring SymbolReaderOptions with path: {envSymbolPath}" );
                            }

                            // Try to set SymbolPath property
                            var symbolPathProp = symbolReaderOptionsType.GetProperty ( "SymbolPath",
                                                 System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                            if ( symbolPathProp != null && envSymbolPath != null )
                            {
                                symbolPathProp.SetValue ( symbolReaderOptions, envSymbolPath );
                                if ( verbose )
                                {
                                    Console.WriteLine ( $"    Set SymbolPath property" );
                                }
                            }
                            else if ( envSymbolPath != null )
                            {
                                // Try alternative property names
                                var altPropNames = new[] { "Path", "SymbolServerPath", "CachePath", "SymbolCachePath" };
                                foreach ( var propName in altPropNames )
                                {
                                    var prop = symbolReaderOptionsType.GetProperty ( propName,
                                               System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                    if ( prop != null )
                                    {
                                        prop.SetValue ( symbolReaderOptions, envSymbolPath );
                                        if ( verbose )
                                        {
                                            Console.WriteLine ( $"    Set {propName} property" );
                                        }
                                        break;
                                    }
                                }
                            }

                            // Try to set other symbol-related properties that might help
                            var propertiesToSet = new Dictionary<string, object>();
                            if ( envSymbolPath != null )
                            {
                                propertiesToSet.Add ( "SymbolPath", envSymbolPath );
                                var cachePath = envSymbolPath.Split ( ';' ) [0];
                                if ( !string.IsNullOrEmpty ( cachePath ) )
                                {
                                    propertiesToSet.Add ( "LocalSymbolCache", cachePath );
                                }
                            }
                            propertiesToSet.Add ( "SymbolServer", "https://msdl.microsoft.com/download/symbols" );

                            foreach ( var kvp in propertiesToSet )
                            {
                                var prop = symbolReaderOptionsType.GetProperty ( kvp.Key,
                                           System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                if ( prop != null && prop.CanWrite )
                                {
                                    try
                                    {
                                        prop.SetValue ( symbolReaderOptions, kvp.Value );
                                        if ( verbose )
                                        {
                                            Console.WriteLine ( $"    Set {kvp.Key} = {kvp.Value}" );
                                        }
                                    }
                                    catch
                                    {
                                        // Ignore if can't set
                                    }
                                }
                            }

                            // List all available properties for debugging
                            if ( verbose )
                            {
                                var allProps = symbolReaderOptionsType.GetProperties (
                                                   System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                Console.WriteLine ( $"    Available SymbolReaderOptions properties: {string.Join(", ", allProps.Select(p => p.Name))}" );
                            }

                            symbolReaderOptionsProp.SetValue ( options, symbolReaderOptions );
                        }
                    }
                    else if ( verbose )
                    {
                        Console.WriteLine ( "  Warning: SymbolReaderOptions property not found in TraceLogOptions" );
                    }

                    if ( verbose )
                    {
                        Console.WriteLine ( "  Calling CreateFromEventTraceLogFile with options..." );
                    }

                    createMethod.Invoke ( null, new object[] { etlPath, etlxPath, options } );

                    if ( verbose )
                    {
                        Console.WriteLine ( "  ✓ ETLX file created with TraceLogOptions" );
                    }
                }
                else
                {
                    if ( verbose )
                    {
                        Console.WriteLine ( "  TraceLogOptions method not available, using standard method" );
                    }
                    TraceLog.CreateFromEventTraceLogFile ( etlPath, etlxPath );
                }
            }
            catch ( Exception ex )
            {
                if ( verbose )
                {
                    Console.WriteLine ( $"  Error creating ETLX with options: {ex.Message}" );
                    Console.WriteLine ( $"  Stack trace: {ex.StackTrace}" );
                }
                // Fallback to standard method
                Console.WriteLine ( "  Falling back to standard ETLX creation (symbols may not load)..." );
                TraceLog.CreateFromEventTraceLogFile ( etlPath, etlxPath );
            }
        }
        else
        {
            Console.WriteLine ( "Using existing ETLX file..." );
            if ( symbolPathSet && verbose )
            {
                Console.WriteLine ( "Note: Existing ETLX file may not have symbols. Delete .etlx file to force symbol reload." );
            }
        }

        Console.WriteLine ( "Processing ETL file (this may take a while)...\n" );

        // Create a custom TextWriter that filters symbol messages
        // NOTE: For debugging symbol loading issues, it's better to see all messages
        // So we only filter when NOT in verbose mode AND user hasn't explicitly requested symbol info
        TextWriter? originalOut = null;
        SymbolFilterWriter? symbolFilter = null;

        // Only filter if not verbose - this allows seeing symbol loading messages during debugging
        if ( !verbose )
        {
            originalOut = Console.Out;
            symbolFilter = new SymbolFilterWriter ( originalOut );
            Console.SetOut ( symbolFilter );
        }

        try
        {
            // Try to use OpenOrConvert with options if available
            TraceLog? traceLog = null;
            try
            {
                var openMethod = typeof ( TraceLog ).GetMethod ( "OpenOrConvert",
                                 new[] { typeof ( string ), typeof ( TraceLogOptions ) } );
                if ( openMethod != null && symbolPathSet )
                {
                    if ( verbose )
                    {
                        Console.WriteLine ( "Attempting to use OpenOrConvert with TraceLogOptions..." );
                    }

                    // Create TraceLogOptions with symbol path
                    var optionsType = typeof ( TraceLogOptions );
                    var options = Activator.CreateInstance ( optionsType )
                                  ?? throw new InvalidOperationException ( "Failed to create TraceLogOptions instance." );

                    var symbolReaderOptionsProp = optionsType.GetProperty ( "SymbolReaderOptions",
                                                  System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                    if ( symbolReaderOptionsProp != null )
                    {
                        var symbolReaderOptionsType = symbolReaderOptionsProp.PropertyType;
                        var symbolReaderOptions = Activator.CreateInstance ( symbolReaderOptionsType );
                        if ( symbolReaderOptions != null )
                        {
                            var envSymbolPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
                            var symbolPathProp = symbolReaderOptionsType.GetProperty ( "SymbolPath",
                                                 System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                            if ( symbolPathProp != null && envSymbolPath != null )
                            {
                                symbolPathProp.SetValue ( symbolReaderOptions, envSymbolPath );
                            }
                            symbolReaderOptionsProp.SetValue ( options, symbolReaderOptions );
                        }
                    }

                    traceLog = ( TraceLog? ) openMethod.Invoke ( null, new object[] { etlPath, options } );
                    if ( verbose && traceLog != null )
                    {
                        Console.WriteLine ( "  ✓ Opened TraceLog with TraceLogOptions" );
                    }
                }
            }
            catch ( Exception ex )
            {
                if ( verbose )
                {
                    Console.WriteLine ( $"  Could not use OpenOrConvert with options: {ex.Message}" );
                }
            }

            // Fallback to standard OpenOrConvert
            if ( traceLog == null )
            {
                traceLog = TraceLog.OpenOrConvert ( etlPath );
            }

            using ( traceLog )
            {
                // Implement PerfView's "Warm Symbol Lookup" algorithm
                // Step 1: Analyze modules by iterating through call stacks to find "hot" modules
                if ( verbose )
                {
                    Console.WriteLine ( "\n=== Starting Warm Symbol Lookup (PerfView algorithm) ===" );
                }

                try
                {
                    // Step 1: Collect module metrics from call stacks
                    var moduleMetrics = new Dictionary<string, long>();
                    long totalSamples = 0;

                    if ( verbose )
                    {
                        Console.WriteLine ( "Step 1: Analyzing call stacks to find hot modules..." );
                    }

                    // Iterate through all call stacks to count module usage
                    int stackCount = 0;
                    foreach ( var callStack in traceLog.CallStacks )
                    {
                        if ( callStack == null )
                        {
                            continue;
                        }

                        stackCount++;
                        totalSamples++;

                        // Walk up the call stack
                        var frame = callStack;
                        var modulesSeenOnStack = new HashSet<string>();

                        while ( frame != null )
                        {
                            if ( frame.CodeAddress != null )
                            {
                                var module = frame.CodeAddress.ModuleFile;
                                if ( module != null )
                                {
                                    string moduleName = Path.GetFileNameWithoutExtension ( module.Name ?? "" );
                                    if ( !string.IsNullOrEmpty ( moduleName ) && !modulesSeenOnStack.Contains ( moduleName ) )
                                    {
                                        modulesSeenOnStack.Add ( moduleName );
                                        if ( !moduleMetrics.ContainsKey ( moduleName ) )
                                        {
                                            moduleMetrics[moduleName] = 0;
                                        }
                                        moduleMetrics[moduleName]++;
                                    }
                                }
                            }
                            frame = frame.Caller;
                        }

                        if ( stackCount > 10000 )
                        {
                            break;    // Limit for performance
                        }
                    }

                    if ( verbose )
                    {
                        Console.WriteLine ( $"  Analyzed {stackCount} call stacks, found {moduleMetrics.Count} unique modules" );
                    }

                    // Step 2: Filter modules with >2% metric (PerfView threshold)
                    var modulesToLookup = new List< ( string name, double percent ) >();
                    foreach ( var kvp in moduleMetrics )
                    {
                        double percent = totalSamples > 0
                                         ? ( kvp.Value * 100.0 ) / totalSamples
                                         : 0;
                        if ( percent > 2.0 ) // PerfView uses 2% threshold
                        {
                            modulesToLookup.Add ( ( kvp.Key, percent ) );
                        }
                    }

                    modulesToLookup = modulesToLookup.OrderByDescending ( m => m.percent ).ToList();

                    if ( verbose )
                    {
                        Console.WriteLine ( $"\nStep 2: Found {modulesToLookup.Count} modules with >2% metric:" );
                        foreach ( var ( name, percent ) in modulesToLookup.Take ( 10 ) )
                        {
                            // Try to get module file size
                            TraceModuleFile? moduleFile = null;
                            foreach ( var mf in traceLog.ModuleFiles )
                            {
                                if ( Path.GetFileNameWithoutExtension ( mf.Name ?? "" ) == name )
                                {
                                    moduleFile = mf;
                                    break;
                                }
                            }

                            string sizeInfo = "";
                            if ( moduleFile != null )
                            {
                                try
                                {
                                    // Try to get PDB size
                                    double pdbSizeMB = GetModulePdbSizeMB ( moduleFile, null );
                                    if ( pdbSizeMB > 0.01 )
                                    {
                                        sizeInfo = $" (~{pdbSizeMB:F1} MB)";
                                    }
                                }
                                catch
                                {
                                    // Ignore
                                }
                            }

                            Console.WriteLine ( $"  {name}: {percent:F1}%{sizeInfo}" );
                        }
                    }

                    // Step 3: Call LookupSymbolsForModule for each hot module
                    if ( modulesToLookup.Count > 0 )
                    {
                        if ( verbose )
                        {
                            Console.WriteLine ( "\nStep 3: Loading symbols for hot modules..." );
                        }

                        // Create SymbolReader (as shown in PerfView source code)
                        // SymbolReader constructor: SymbolReader(TextWriter log, string nt_symbol_path = null)
                        // Try to create SymbolReader using reflection since it might not be directly accessible
                        object? symbolReader = null;
                        try
                        {
                            var envSymbolPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
                            if ( verbose )
                            {
                                Console.WriteLine ( $"  Creating SymbolReader with path: {envSymbolPath}" );
                            }

                            // Try to find SymbolReader type
                            Type? symbolReaderType = null;

                            // Method 1: Try to load from fully qualified name
                            try
                            {
                                symbolReaderType = Type.GetType ( "Microsoft.Diagnostics.Symbols.SymbolReader, Microsoft.Diagnostics.Tracing.TraceEvent" );
                                if ( verbose && symbolReaderType != null )
                                {
                                    Console.WriteLine ( $"  Found SymbolReader via Type.GetType: {symbolReaderType.FullName}" );
                                }
                            }
                            catch ( Exception ex )
                            {
                                if ( verbose )
                                {
                                    Console.WriteLine ( $"  Type.GetType failed: {ex.Message}" );
                                }
                            }

                            // Method 2: Search in all loaded assemblies
                            if ( symbolReaderType == null )
                            {
                                foreach ( var assembly in AppDomain.CurrentDomain.GetAssemblies() )
                                {
                                    try
                                    {
                                        symbolReaderType = assembly.GetType ( "Microsoft.Diagnostics.Symbols.SymbolReader" );
                                        if ( symbolReaderType != null )
                                        {
                                            if ( verbose )
                                            {
                                                Console.WriteLine ( $"  Found SymbolReader in assembly: {assembly.FullName}" );
                                            }
                                            break;
                                        }
                                    }
                                    catch
                                    {
                                        // Ignore
                                    }
                                }
                            }

                            // Method 3: Try to load TraceEvent assembly explicitly
                            if ( symbolReaderType == null )
                            {
                                try
                                {
                                    var traceEventAssembly = System.Reflection.Assembly.LoadFrom (
                                                                 Path.Combine ( AppDomain.CurrentDomain.BaseDirectory, "Microsoft.Diagnostics.Tracing.TraceEvent.dll" ) );
                                    symbolReaderType = traceEventAssembly.GetType ( "Microsoft.Diagnostics.Symbols.SymbolReader" );
                                    if ( verbose && symbolReaderType != null )
                                    {
                                        Console.WriteLine ( $"  Found SymbolReader by loading assembly explicitly" );
                                    }
                                }
                                catch ( Exception ex )
                                {
                                    if ( verbose )
                                    {
                                        Console.WriteLine ( $"  Failed to load assembly explicitly: {ex.Message}" );
                                    }
                                }
                            }

                            if ( symbolReaderType != null )
                            {
                                // Create a StringWriter to capture symbol loading messages
                                var symbolLog = new StringWriter();

                                // List all available constructors
                                var constructors = symbolReaderType.GetConstructors();
                                if ( verbose )
                                {
                                    Console.WriteLine ( $"  Found {constructors.Length} constructors:" );
                                    foreach ( var ctor in constructors )
                                    {
                                        var paramTypes = ctor.GetParameters().Select ( p => $"{p.ParameterType.Name} {p.Name}" ).ToArray();
                                        Console.WriteLine ( $"    - SymbolReader({string.Join(", ", paramTypes)})" );
                                    }
                                }

                                // Try constructor: SymbolReader(TextWriter log, string nt_symbol_path = null, DelegatingHandler httpClientDelegatingHandler = null)
                                // First try with TextWriter and string
                                var constructor = symbolReaderType.GetConstructor (
                                                      new[] { typeof ( TextWriter ), typeof ( string ) } );

                                if ( constructor != null )
                                {
                                    try
                                    {
                                        symbolReader = constructor.Invoke ( new object[] { symbolLog, envSymbolPath ?? "" } );
                                        if ( verbose )
                                        {
                                            Console.WriteLine ( $"  ✓ SymbolReader created: {symbolReader.GetType().FullName}" );
                                        }
                                    }
                                    catch ( Exception ex )
                                    {
                                        if ( verbose )
                                        {
                                            Console.WriteLine ( $"  ✗ Constructor failed: {ex.Message}" );
                                            Console.WriteLine ( $"    Inner exception: {ex.InnerException?.Message}" );
                                        }
                                    }
                                }

                                // If that failed, try with just TextWriter
                                if ( symbolReader == null )
                                {
                                    constructor = symbolReaderType.GetConstructor ( new[] { typeof ( TextWriter ) } );
                                    if ( constructor != null )
                                    {
                                        try
                                        {
                                            symbolReader = constructor.Invoke ( new object[] { symbolLog } );
                                            // Try to set SymbolPath property
                                            var symbolPathProp = symbolReaderType.GetProperty ( "SymbolPath" );
                                            if ( symbolPathProp != null && envSymbolPath != null )
                                            {
                                                symbolPathProp.SetValue ( symbolReader, envSymbolPath );
                                            }
                                            if ( verbose )
                                            {
                                                Console.WriteLine ( $"  ✓ SymbolReader created (with TextWriter only)" );
                                            }
                                        }
                                        catch ( Exception ex )
                                        {
                                            if ( verbose )
                                            {
                                                Console.WriteLine ( $"  ✗ Constructor with TextWriter only failed: {ex.Message}" );
                                                Console.WriteLine ( $"    Inner exception: {ex.InnerException?.Message}" );
                                            }
                                        }
                                    }
                                }

                                // If still failed, try with all three parameters (passing null for DelegatingHandler)
                                if ( symbolReader == null )
                                {
                                    constructor = symbolReaderType.GetConstructor (
                                                      new[] { typeof ( TextWriter ), typeof ( string ), typeof ( System.Net.Http.DelegatingHandler ) } );
                                    if ( constructor != null )
                                    {
                                        try
                                        {
                                            System.Net.Http.DelegatingHandler? httpHandler = null;
                                            symbolReader = constructor.Invoke ( new object?[] { symbolLog, envSymbolPath ?? "", httpHandler } );
                                            if ( verbose )
                                            {
                                                Console.WriteLine ( $"  ✓ SymbolReader created (with all parameters)" );
                                            }
                                        }
                                        catch ( Exception ex )
                                        {
                                            if ( verbose )
                                            {
                                                Console.WriteLine ( $"  ✗ Constructor with all parameters failed: {ex.Message}" );
                                                Console.WriteLine ( $"    Inner exception: {ex.InnerException?.Message}" );
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                if ( verbose )
                                {
                                    Console.WriteLine ( "  ⚠ SymbolReader type not found" );
                                    Console.WriteLine ( "  Searching for alternative symbol loading methods..." );

                                    // List all types in TraceEvent assembly that contain "Symbol"
                                    try
                                    {
                                        var traceEventAssembly = System.Reflection.Assembly.LoadFrom (
                                                                     Path.Combine ( AppDomain.CurrentDomain.BaseDirectory, "Microsoft.Diagnostics.Tracing.TraceEvent.dll" ) );
                                        var symbolTypes = traceEventAssembly.GetTypes()
                                                          .Where ( t => t.Name.Contains ( "Symbol" ) && t.IsPublic )
                                                          .Take ( 10 )
                                                          .ToList();

                                        if ( symbolTypes.Count > 0 )
                                        {
                                            Console.WriteLine ( $"  Found {symbolTypes.Count} symbol-related types:" );
                                            foreach ( var t in symbolTypes )
                                            {
                                                Console.WriteLine ( $"    - {t.FullName}" );
                                            }
                                        }
                                    }
                                    catch ( Exception ex )
                                    {
                                        Console.WriteLine ( $"  Could not list types: {ex.Message}" );
                                    }
                                }
                            }
                        }
                        catch ( Exception ex )
                        {
                            if ( verbose )
                            {
                                Console.WriteLine ( $"  ✗ Failed to create SymbolReader: {ex.Message}" );
                            }
                        }

                        if ( symbolReader != null )
                        {
                            // Get CodeAddresses collection
                            var codeAddressesType = traceLog.CodeAddresses.GetType();

                            // Get all LookupSymbolsForModule methods (there might be multiple overloads)
                            var allLookupMethods = codeAddressesType.GetMethods (
                                                       System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance )
                                                   .Where ( m => m.Name == "LookupSymbolsForModule" )
                                                   .ToList();

                            if ( verbose )
                            {
                                Console.WriteLine ( $"  Found {allLookupMethods.Count} LookupSymbolsForModule overloads:" );
                                foreach ( var m in allLookupMethods )
                                {
                                    var paramTypes = m.GetParameters().Select ( p => p.ParameterType.Name ).ToArray();
                                    Console.WriteLine ( $"    - LookupSymbolsForModule({string.Join(", ", paramTypes)})" );
                                }
                            }

                            if ( allLookupMethods.Count > 0 )
                            {
                                // Try method with string parameter first (simpler)
                                var lookupByNameMethod = allLookupMethods.FirstOrDefault ( m =>
                                {
                                    var parameters = m.GetParameters();
                                    return parameters.Length == 1 && parameters[0].ParameterType == typeof ( string );
                                } );

                                if ( lookupByNameMethod != null )
                                {
                                    if ( verbose )
                                    {
                                        Console.WriteLine ( "  Using LookupSymbolsForModule(string) method" );
                                    }

                                    foreach ( var ( moduleName, percent ) in modulesToLookup )
                                    {
                                        if ( verbose )
                                        {
                                            Console.Write ( $"  Loading symbols for {moduleName} ({percent:F1}%)... " );
                                        }

                                        // Get initial cache size
                                        double initialSizeMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );

                                        // Start progress indicator in background with size tracking
                                        var progressToken = new CancellationTokenSource();
                                        var progressTask = Task.Run ( () =>
                                        {
                                            ShowProgressBarWithUpdate ( progressToken.Token, () =>
                                            {
                                                double currentMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
                                                return Math.Max ( 0, currentMB - initialSizeMB );
                                            } );
                                        } );

                                        try
                                        {
                                            // Wrap the symbol lookup in a task
                                            var lookupTask = Task.Run ( () =>
                                            {
                                                lookupByNameMethod.Invoke ( traceLog.CodeAddresses, new object[] { moduleName } );
                                            } );

                                            // Wait for completion with smart timeout (skip only if MB not growing)
                                            bool completed = WaitWithProgressCheck ( lookupTask, timeoutSeconds, initialSizeMB, progressToken, maxSizeMB, moduleName, out string? skipReason );

                                            // Stop progress indicator
                                            progressToken.Cancel();
                                            progressTask.Wait ( 1000 );

                                            if ( !completed )
                                            {
                                                // Module was skipped - show reason
                                                Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                Console.WriteLine ( $"  ⏱ Skipped {moduleName} ({skipReason ?? "unknown reason"})" );
                                                continue; // Skip to next module
                                            }

                                            // Get final cache size
                                            double finalSizeMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
                                            double loadedMB = Math.Max ( 0, finalSizeMB - initialSizeMB );

                                            if ( verbose )
                                            {
                                                // Clear progress bar and show success
                                                Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                if ( loadedMB > 0.01 )
                                                {
                                                    Console.WriteLine ( $"  ✓ Symbols loaded for {moduleName} ({loadedMB:F2} MB)" );
                                                }
                                                else
                                                {
                                                    Console.WriteLine ( $"  ✓ Symbols loaded for {moduleName}" );
                                                }
                                            }
                                        }
                                        catch ( Exception ex )
                                        {
                                            progressToken.Cancel();
                                            progressTask.Wait ( 1000 );

                                            if ( verbose )
                                            {
                                                Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                Console.WriteLine ( $"    ✗ Failed to load symbols for {moduleName}: {ex.Message}" );
                                            }
                                        }
                                    }
                                }
                                // Try method with SymbolReader and TraceModuleFile
                                else
                                {
                                    var lookupWithSymbolReaderMethod = allLookupMethods.FirstOrDefault ( m =>
                                    {
                                        var parameters = m.GetParameters();
                                        if ( parameters.Length == 2 )
                                        {
                                            // Check if first parameter is SymbolReader or compatible type
                                            var firstParamType = parameters[0].ParameterType;
                                            var symbolReaderType = symbolReader.GetType();
                                            return ( firstParamType == symbolReaderType ||
                                                     firstParamType.IsAssignableFrom ( symbolReaderType ) ||
                                                     symbolReaderType.IsAssignableFrom ( firstParamType ) ) &&
                                                   parameters[1].ParameterType == typeof ( TraceModuleFile );
                                        }
                                        return false;
                                    } );

                                    if ( lookupWithSymbolReaderMethod != null )
                                    {
                                        if ( verbose )
                                        {
                                            Console.WriteLine ( "  Using LookupSymbolsForModule(SymbolReader, TraceModuleFile) method" );
                                        }

                                        foreach ( var ( moduleName, percent ) in modulesToLookup )
                                        {
                                            try
                                            {
                                                // Find module file
                                                TraceModuleFile? moduleFile = null;
                                                foreach ( var mf in traceLog.ModuleFiles )
                                                {
                                                    if ( Path.GetFileNameWithoutExtension ( mf.Name ?? "" ) == moduleName )
                                                    {
                                                        moduleFile = mf;
                                                        break;
                                                    }
                                                }

                                                if ( moduleFile != null )
                                                {
                                                    if ( verbose )
                                                    {
                                                        Console.Write ( $"  Loading symbols for {moduleName} ({percent:F1}%)... " );
                                                    }

                                                    // Get initial cache size and PDB size
                                                    double initialSizeMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
                                                    double modulePdbSizeMB = GetModulePdbSizeMB ( moduleFile, symbolReader );

                                                    // Start progress indicator in background with size tracking
                                                    var progressToken = new System.Threading.CancellationTokenSource();
                                                    var progressTask = Task.Run ( () =>
                                                    {
                                                        ShowProgressBarWithUpdate ( progressToken.Token, () =>
                                                        {
                                                            double currentMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
                                                            double loadedMB = Math.Max ( 0, currentMB - initialSizeMB );
                                                            // Если знаем размер PDB, показываем прогресс
                                                            return modulePdbSizeMB > 0 ? Math.Min ( loadedMB, modulePdbSizeMB ) : loadedMB;
                                                        } );
                                                    } );

                                                    try
                                                    {
                                                        // Wrap the symbol lookup in a task
                                                        var lookupTask = Task.Run ( () =>
                                                        {
                                                            lookupWithSymbolReaderMethod.Invoke ( traceLog.CodeAddresses, new object[] { symbolReader, moduleFile } );
                                                        } );

                                                        // Wait for completion with smart timeout (skip only if MB not growing)
                                                        bool completed = WaitWithProgressCheck ( lookupTask, timeoutSeconds, initialSizeMB, progressToken, maxSizeMB, moduleName, out string? skipReason );

                                                        // Stop progress indicator
                                                        progressToken.Cancel();
                                                        progressTask.Wait ( 1000 );

                                                        if ( !completed )
                                                        {
                                                            // Module was skipped - show reason
                                                            Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                            Console.WriteLine ( $"  ⏱ Skipped {moduleName} ({skipReason ?? "unknown reason"})" );
                                                            continue; // Skip to next module
                                                        }

                                                        // Get final cache size
                                                        double finalSizeMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
                                                        double loadedMB = Math.Max ( 0, finalSizeMB - initialSizeMB );

                                                        if ( verbose )
                                                        {
                                                            // Clear progress bar and show success
                                                            Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                            if ( loadedMB > 0.01 )
                                                            {
                                                                Console.WriteLine ( $"  ✓ Symbols loaded for {moduleName} ({loadedMB:F2} MB)" );
                                                            }
                                                            else
                                                            {
                                                                Console.WriteLine ( $"  ✓ Symbols loaded for {moduleName}" );
                                                            }
                                                        }
                                                    }
                                                    catch ( Exception ex )
                                                    {
                                                        progressToken.Cancel();
                                                        progressTask.Wait ( 1000 );

                                                        if ( verbose )
                                                        {
                                                            Console.Write ( "\r" + new string ( ' ', Console.WindowWidth - 1 ) + "\r" );
                                                            Console.WriteLine ( $"    ✗ Failed to load symbols for {moduleName}: {ex.Message}" );
                                                        }
                                                    }
                                                }
                                                else if ( verbose )
                                                {
                                                    Console.WriteLine ( $"    ⚠ Module file not found for {moduleName}" );
                                                }
                                            }
                                            catch ( Exception ex )
                                            {
                                                if ( verbose )
                                                {
                                                    Console.WriteLine ( $"    ✗ Failed to load symbols for {moduleName}: {ex.Message}" );
                                                }
                                            }
                                        }
                                    }
                                    else if ( verbose )
                                    {
                                        Console.WriteLine ( "  Warning: Could not find suitable LookupSymbolsForModule overload" );
                                    }
                                }

                                // Dispose SymbolReader when done (if it implements IDisposable)
                                try
                                {
                                    var disposeMethod = symbolReader.GetType().GetMethod ( "Dispose" );
                                    if ( disposeMethod != null )
                                    {
                                        disposeMethod.Invoke ( symbolReader, null );
                                    }
                                }
                                catch
                                {
                                    // Ignore dispose errors
                                }
                            }
                            else if ( verbose )
                            {
                                Console.WriteLine ( "  Warning: LookupSymbolsForModule method not found on CodeAddresses" );
                            }
                        }
                        else if ( verbose )
                        {
                            Console.WriteLine ( "  Warning: Could not create SymbolReader, skipping symbol loading" );
                        }
                    }

                    if ( verbose )
                    {
                        Console.WriteLine ( "\n=== Warm Symbol Lookup completed ===\n" );
                    }
                }
                catch ( Exception ex )
                {
                    if ( verbose )
                    {
                        Console.WriteLine ( $"  Error during Warm Symbol Lookup: {ex.Message}" );
                        Console.WriteLine ( $"  Stack trace: {ex.StackTrace}" );
                    }
                }

                // Try to access SymbolReader through reflection and force symbol loading
                if ( verbose )
                {
                    Console.WriteLine ( "\nAttempting to access SymbolReader through reflection..." );
                    var traceLogType = traceLog.GetType();

                    // Try both public and non-public properties
                    var symbolReaderProp = traceLogType.GetProperty ( "SymbolReader",
                                           System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                    if ( symbolReaderProp == null )
                    {
                        // Try alternative property names
                        symbolReaderProp = traceLogType.GetProperty ( "Symbols",
                                           System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                    }

                    if ( symbolReaderProp != null )
                    {
                        try
                        {
                            var symbolReader = symbolReaderProp.GetValue ( traceLog );
                            if ( symbolReader != null )
                            {
                                Console.WriteLine ( $"  Found SymbolReader: {symbolReader.GetType().FullName}" );
                                var symbolReaderType = symbolReader.GetType();

                                // Try to set SymbolPath
                                var symbolPathProp = symbolReaderType.GetProperty ( "SymbolPath",
                                                     System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                if ( symbolPathProp != null )
                                {
                                    var currentPath = symbolPathProp.GetValue ( symbolReader );
                                    Console.WriteLine ( $"  Current SymbolPath: {currentPath}" );
                                    var newPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
                                    if ( !string.IsNullOrEmpty ( newPath ) )
                                    {
                                        symbolPathProp.SetValue ( symbolReader, newPath );
                                        Console.WriteLine ( $"  Set SymbolPath to: {newPath}" );
                                    }
                                }

                                // Try to call methods to force symbol loading
                                var loadMethods = symbolReaderType.GetMethods (
                                                      System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                foreach ( var method in loadMethods )
                                {
                                    if ( ( method.Name.Contains ( "Load" ) || method.Name.Contains ( "Resolve" ) ) &&
                                            method.GetParameters().Length == 0 )
                                    {
                                        try
                                        {
                                            Console.WriteLine ( $"  Attempting to call {method.Name}()..." );
                                            method.Invoke ( symbolReader, null );
                                        }
                                        catch ( Exception ex )
                                        {
                                            Console.WriteLine ( $"    Error calling {method.Name}: {ex.Message}" );
                                        }
                                    }
                                }
                            }
                        }
                        catch ( Exception ex )
                        {
                            Console.WriteLine ( $"  Could not access SymbolReader: {ex.Message}" );
                        }
                    }
                    else
                    {
                        Console.WriteLine ( "  SymbolReader property not found" );
                        // List all properties for debugging
                        var allProps = traceLogType.GetProperties ( System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                        Console.WriteLine ( $"  Available properties: {string.Join(", ", allProps.Take(10).Select(p => p.Name))}..." );
                    }

                    Console.WriteLine ( "\nForcing symbol loading by accessing CodeAddress.Method..." );
                    Console.WriteLine ( $"Current _NT_SYMBOL_PATH: {Environment.GetEnvironmentVariable("_NT_SYMBOL_PATH")}" );
                }

                // Force symbol loading by accessing Method property for all code addresses
                // This triggers lazy symbol loading

                // Try to access symbols through CallStacks first - this might trigger symbol loading
                int callStacksWithSymbols = 0;
                int totalCallStacks = 0;
                foreach ( var callStack in traceLog.CallStacks )
                {
                    if ( callStack != null )
                    {
                        totalCallStacks++;
                        var frame = callStack;
                        int framesChecked = 0;
                        while ( frame != null && framesChecked < 5 )
                        {
                            if ( frame.CodeAddress != null )
                            {
                                try
                                {
                                    // Use GetSymbolName helper which checks both Method and SymbolReader
                                    var ( name, _ ) = GetSymbolName ( frame.CodeAddress, traceLog );
                                    if ( !string.IsNullOrEmpty ( name ) )
                                    {
                                        callStacksWithSymbols++;
                                        if ( verbose && callStacksWithSymbols <= 3 )
                                        {
                                            Console.WriteLine ( $"  Found symbol in call stack: {name}" );
                                        }
                                        break; // Found at least one symbol in this stack
                                    }
                                }
                                catch
                                {
                                    // Ignore
                                }
                            }
                            frame = frame.Caller;
                            framesChecked++;
                        }

                        if ( totalCallStacks > 1000 )
                        {
                            break;    // Limit check
                        }
                    }
                }

                if ( verbose )
                {
                    Console.WriteLine ( $"Call stacks checked: {totalCallStacks}, with symbols: {callStacksWithSymbols}" );
                }

                // Now check CodeAddresses directly
                int symbolsLoaded = 0;
                int totalChecked = 0;
                foreach ( var codeAddr in traceLog.CodeAddresses )
                {
                    if ( codeAddr != null )
                    {
                        totalChecked++;
                        try
                        {
                            // Use GetSymbolName helper which checks both Method and SymbolReader
                            var ( name, module ) = GetSymbolName ( codeAddr, traceLog );
                            if ( !string.IsNullOrEmpty ( name ) )
                            {
                                symbolsLoaded++;
                                if ( verbose && symbolsLoaded <= 5 )
                                {
                                    var moduleName = module ?? "Unknown";
                                    Console.WriteLine ( $"  Loaded symbol: {name} [{moduleName}] at 0x{codeAddr.Address:X16}" );
                                }
                            }
                        }
                        catch ( Exception ex )
                        {
                            if ( verbose && totalChecked < 5 )
                            {
                                Console.WriteLine ( $"  Error loading symbol for 0x{codeAddr.Address:X16}: {ex.Message}" );
                            }
                        }

                        // Limit check to avoid too much processing
                        if ( totalChecked > 5000 )
                        {
                            break;
                        }
                    }
                }

                if ( verbose )
                {
                    Console.WriteLine ( $"Symbol loading check: {symbolsLoaded} symbols loaded from {totalChecked} addresses checked" );

                    // Check modules and their symbol status
                    Console.WriteLine ( "\nChecking modules for symbol information..." );
                    var modules = new Dictionary<string, ( int addresses, int withSymbols ) >();
                    foreach ( var codeAddr in traceLog.CodeAddresses.Take ( 1000 ) )
                    {
                        if ( codeAddr != null )
                        {
                            var module = codeAddr.ModuleFile;
                            string moduleName = module?.Name ?? "Unknown";
                            if ( !modules.ContainsKey ( moduleName ) )
                            {
                                modules[moduleName] = ( 0, 0 );
                            }
                            var ( addrCount, symbolCount ) = modules[moduleName];
                            modules[moduleName] = ( addrCount + 1, symbolCount + ( codeAddr.Method != null ? 1 : 0 ) );
                        }
                    }

                    foreach ( var ( moduleName, ( addrCount, symbolCount ) ) in modules.OrderByDescending ( m => m.Value.addresses ).Take ( 10 ) )
                    {
                        Console.WriteLine ( $"  {Path.GetFileName(moduleName)}: {addrCount} addresses, {symbolCount} with symbols" );
                    }
                    Console.WriteLine();
                }

                using ( var source = traceLog.Events.GetSource() )
                {
                    var kernelParser = new KernelTraceEventParser ( source );
                    var dynamicParser = new DynamicTraceEventParser ( source );

                    // Process StackWalk events - these have full call stacks
                    int stackWalkCount = 0;
                    int stackWalkForFilteredPid = 0;
                    kernelParser.StackWalkStack += ( StackWalkStackTraceData data ) =>
                    {
                        totalStacks++;
                        stackWalkCount++;

                        if ( totalStacks % 10000 == 0 )
                        {
                            Console.Write ( $"\rProcessed {totalStacks:N0} stack traces..." );
                        }

                        // Filter by PID if specified
                        if ( filterPid.HasValue && data.ProcessID != filterPid.Value )
                        {
                            return;
                        }

                        if ( filterPid.HasValue && data.ProcessID == filterPid.Value )
                        {
                            stackWalkForFilteredPid++;
                        }

                        // Store process name
                        uint processId = ( uint ) data.ProcessID;
                        if ( !processNames.ContainsKey ( processId ) )
                        {
                            processNames[processId] = data.ProcessName ?? $"PID {processId}";
                        }

                        // Get the call stack and resolve addresses with function names
                        var callStackIndex = data.CallStackIndex();
                        if ( callStackIndex != CallStackIndex.Invalid )
                        {
                            var callStack = traceLog.CallStacks[callStackIndex];
                            if ( callStack != null )
                            {
                                var addresses = new List < ( ulong address, string? functionName, string? moduleName ) > ();

                                // Walk the call stack
                                var frame = callStack;
                                while ( frame != null )
                                {
                                    if ( frame.CodeAddress != null && frame.CodeAddress.Address != 0 )
                                    {
                                        ulong addr = frame.CodeAddress.Address;
                                        string? funcName = null;
                                        string? modName = null;

                                        // Use GetSymbolName helper which checks both Method and SymbolReader
                                        ( funcName, modName ) = GetSymbolName ( frame.CodeAddress, traceLog );

                                        addresses.Add ( ( addr, funcName, modName ) );
                                    }
                                    frame = frame.Caller;
                                }

                                if ( addresses.Count > 0 )
                                {
                                    // Build call tree: reverse the stack (root to leaf)
                                    // In TraceEvent, callStack goes from leaf to root, so we reverse it
                                    var reversedAddresses = new List < ( ulong address, string? functionName, string? moduleName ) > ();
                                    for ( int i = addresses.Count - 1; i >= 0; i-- )
                                    {
                                        reversedAddresses.Add ( addresses[i] );
                                    }

                                    // Get or create root node for this process
                                    if ( !callTrees.ContainsKey ( processId ) )
                                    {
                                        callTrees[processId] = new CallTreeNode
                                        {
                                            FunctionKey = $"ROOT_{processId}",
                                            FunctionName = $"{processNames.GetValueOrDefault(processId, $"PID {processId}")} (PID: {processId})"
                                        };
                                    }
                                    var rootNode = callTrees[processId];
                                    rootNode.InclusiveSamples++;

                                    // Build call tree path
                                    var currentNode = rootNode;
                                    for ( int i = 0; i < reversedAddresses.Count; i++ )
                                    {
                                        var ( address, functionName, moduleName ) = reversedAddresses[i];
                                        string functionKey = GetFunctionKey ( address, processId );

                                        // Update function stats
                                        if ( !functionStats.ContainsKey ( functionKey ) )
                                        {
                                            functionStats[functionKey] = new FunctionStats
                                            {
                                                Address = address,
                                                ProcessId = processId,
                                                ExclusiveSamples = 0,
                                                InclusiveSamples = 0,
                                                FunctionName = functionName,
                                                ModuleName = moduleName
                                            };
                                        }

                                        var stats = functionStats[functionKey];

                                        // Update function name if we found it
                                        if ( string.IsNullOrEmpty ( stats.FunctionName ) && !string.IsNullOrEmpty ( functionName ) )
                                        {
                                            stats.FunctionName = functionName;
                                        }
                                        if ( string.IsNullOrEmpty ( stats.ModuleName ) && !string.IsNullOrEmpty ( moduleName ) )
                                        {
                                            stats.ModuleName = moduleName;
                                        }

                                        // Inclusive: function appears in stack
                                        stats.InclusiveSamples++;

                                        // Exclusive: function is at the bottom of reversed stack (leaf)
                                        if ( i == reversedAddresses.Count - 1 )
                                        {
                                            stats.ExclusiveSamples++;
                                        }

                                        // Build call tree
                                        if ( !currentNode.Children.ContainsKey ( functionKey ) )
                                        {
                                            currentNode.Children[functionKey] = new CallTreeNode
                                            {
                                                FunctionKey = functionKey,
                                                Address = address,
                                                FunctionName = stats.FunctionName,
                                                ModuleName = stats.ModuleName,
                                                Parent = currentNode
                                            };
                                        }

                                        var childNode = currentNode.Children[functionKey];
                                        childNode.InclusiveSamples++;
                                        if ( i == reversedAddresses.Count - 1 )
                                        {
                                            childNode.ExclusiveSamples++;
                                        }

                                        currentNode = childNode;
                                    }
                                }
                            }
                        }
                    };

                    // Process PerfInfo events (SampleProf) - these have InstructionPointer
                    kernelParser.PerfInfoSample += ( SampledProfileTraceData data ) =>
                    {
                        totalStacks++;

                        if ( totalStacks % 10000 == 0 )
                        {
                            Console.Write ( $"\rProcessed {totalStacks:N0} samples..." );
                        }

                        // Filter by PID if specified
                        uint processId = ( uint ) data.ProcessID;
                        if ( filterPid.HasValue && processId != filterPid.Value )
                        {
                            return;
                        }

                        // Store process name
                        if ( !processNames.ContainsKey ( processId ) )
                        {
                            processNames[processId] = data.ProcessName ?? $"PID {processId}";
                        }

                        // PerfInfo events contain InstructionPointer
                        // Try to get call stack if available (some PerfInfo events may have stacks)
                        var callStackIndex = data.CallStackIndex();
                        if ( callStackIndex != CallStackIndex.Invalid )
                        {
                            // PerfInfo has a call stack - process it like StackWalk
                            var callStack = traceLog.CallStacks[callStackIndex];
                            if ( callStack != null )
                            {
                                var addresses = new List < ( ulong address, string? functionName, string? moduleName ) > ();

                                // Walk the call stack
                                var frame = callStack;
                                while ( frame != null )
                                {
                                    if ( frame.CodeAddress != null && frame.CodeAddress.Address != 0 )
                                    {
                                        ulong addr = frame.CodeAddress.Address;
                                        string? funcName = null;
                                        string? modName = null;

                                        // Use GetSymbolName helper which checks both Method and SymbolReader
                                        ( funcName, modName ) = GetSymbolName ( frame.CodeAddress, traceLog );

                                        addresses.Add ( ( addr, funcName, modName ) );
                                    }
                                    frame = frame.Caller;
                                }

                                if ( addresses.Count > 0 )
                                {
                                    // Build call tree: reverse the stack (root to leaf) - like Microsoft does
                                    var reversedAddresses = new List < ( ulong address, string? functionName, string? moduleName ) > ();
                                    for ( int i = addresses.Count - 1; i >= 0; i-- )
                                    {
                                        reversedAddresses.Add ( addresses[i] );
                                    }

                                    // Get or create root node for this process
                                    if ( !callTrees.ContainsKey ( processId ) )
                                    {
                                        callTrees[processId] = new CallTreeNode
                                        {
                                            FunctionKey = $"ROOT_{processId}",
                                            FunctionName = $"{processNames.GetValueOrDefault(processId, $"PID {processId}")} (PID: {processId})"
                                        };
                                    }
                                    var rootNode = callTrees[processId];
                                    rootNode.InclusiveSamples++;

                                    // Build call tree path
                                    var currentNode = rootNode;
                                    for ( int i = 0; i < reversedAddresses.Count; i++ )
                                    {
                                        var ( address, functionName, moduleName ) = reversedAddresses[i];
                                        string functionKey = GetFunctionKey ( address, processId );

                                        // Update function stats
                                        if ( !functionStats.ContainsKey ( functionKey ) )
                                        {
                                            functionStats[functionKey] = new FunctionStats
                                            {
                                                Address = address,
                                                ProcessId = processId,
                                                ExclusiveSamples = 0,
                                                InclusiveSamples = 0,
                                                FunctionName = functionName,
                                                ModuleName = moduleName
                                            };
                                        }

                                        var stats = functionStats[functionKey];

                                        // Update function name if we found it
                                        if ( string.IsNullOrEmpty ( stats.FunctionName ) && !string.IsNullOrEmpty ( functionName ) )
                                        {
                                            stats.FunctionName = functionName;
                                        }
                                        if ( string.IsNullOrEmpty ( stats.ModuleName ) && !string.IsNullOrEmpty ( moduleName ) )
                                        {
                                            stats.ModuleName = moduleName;
                                        }

                                        // Inclusive: function appears in stack
                                        stats.InclusiveSamples++;

                                        // Exclusive: function is at the bottom of reversed stack (leaf)
                                        if ( i == reversedAddresses.Count - 1 )
                                        {
                                            stats.ExclusiveSamples++;
                                        }

                                        // Build call tree
                                        if ( !currentNode.Children.ContainsKey ( functionKey ) )
                                        {
                                            currentNode.Children[functionKey] = new CallTreeNode
                                            {
                                                FunctionKey = functionKey,
                                                Address = address,
                                                FunctionName = stats.FunctionName,
                                                ModuleName = stats.ModuleName,
                                                Parent = currentNode
                                            };
                                        }

                                        var childNode = currentNode.Children[functionKey];
                                        childNode.InclusiveSamples++;
                                        if ( i == reversedAddresses.Count - 1 )
                                        {
                                            childNode.ExclusiveSamples++;
                                        }

                                        currentNode = childNode;
                                    }

                                    // Skip the rest - we already processed the stack
                                    return;
                                }
                            }
                        }

                        // PerfInfo without call stack - only InstructionPointer
                        if ( data.InstructionPointer != 0 )
                        {
                            ulong address = data.InstructionPointer;
                            string functionKey = GetFunctionKey ( address, processId );

                            if ( !functionStats.ContainsKey ( functionKey ) )
                            {
                                // Try to resolve function name from TraceLog using InstructionPointer
                                string? functionName = null;
                                string? moduleName = null;

                                try
                                {
                                    // Find code address by searching through all code addresses
                                    // This is not ideal but PerfInfo doesn't have direct CodeAddressIndex
                                    foreach ( var codeAddr in traceLog.CodeAddresses )
                                    {
                                        if ( codeAddr != null && codeAddr.Address == address )
                                        {
                                            // Use GetSymbolName helper which checks both Method and SymbolReader
                                            ( functionName, moduleName ) = GetSymbolName ( codeAddr, traceLog );
                                            break;
                                        }
                                    }
                                }
                                catch
                                {
                                    // Symbol resolution failed, continue without function name
                                }

                                functionStats[functionKey] = new FunctionStats
                                {
                                    Address = address,
                                    ProcessId = processId,
                                    ExclusiveSamples = 0,
                                    InclusiveSamples = 0,
                                    FunctionName = functionName,
                                    ModuleName = moduleName
                                };
                            }

                            var stats = functionStats[functionKey];

                            // Update function name if we found it later (will be resolved in post-processing)

                            // For PerfInfo without stack, we count both as exclusive (since we don't have full stack)
                            stats.ExclusiveSamples++;
                            stats.InclusiveSamples++;
                        }
                    };

                    // Process the trace
                    source.Process();

                    Console.WriteLine ( $"\n\n✓ Processed {totalStacks:N0} stack traces" );
                    if ( verbose )
                    {
                        Console.WriteLine ( $"  - StackWalk events: {stackWalkCount:N0}" );
                        if ( filterPid.HasValue )
                        {
                            Console.WriteLine ( $"  - StackWalk events for PID {filterPid.Value}: {stackWalkForFilteredPid:N0}" );
                            Console.WriteLine ( $"  - Call trees built: {callTrees.Count} (PIDs: {string.Join(", ", callTrees.Keys)})" );
                        }
                    }
                    Console.WriteLine ( $"✓ Found {functionStats.Count:N0} unique functions\n" );

                    // Show statistics for filtered process if specified
                    if ( filterPid.HasValue )
                    {
                        var targetProcessFunctions = functionStats.Values
                                                     .Where ( f => f.ProcessId == filterPid.Value )
                                                     .ToList();

                        if ( targetProcessFunctions.Count > 0 )
                        {
                            string processName = processNames.ContainsKey ( filterPid.Value )
                                                 ? Path.GetFileName ( processNames[filterPid.Value] )
                                                 : $"PID {filterPid.Value}";

                            var targetProcessSamples = targetProcessFunctions.Sum ( f => f.ExclusiveSamples );
                            var targetProcessModules = targetProcessFunctions
                                                       .Where ( f => !string.IsNullOrEmpty ( f.ModuleName ) )
                                                       .Select ( f => Path.GetFileName ( f.ModuleName ?? "" ) )
                                                       .Distinct()
                                                       .ToList();

                            Console.WriteLine ( $"=== Statistics for {processName} (PID {filterPid.Value}) ===\n" );
                            Console.WriteLine ( $"Functions found: {targetProcessFunctions.Count:N0}" );
                            Console.WriteLine ( $"Total samples: {targetProcessSamples:N0}" );
                            Console.WriteLine ( $"Modules: {targetProcessModules.Count} ({string.Join(", ", targetProcessModules.Take(10))}{(targetProcessModules.Count > 10 ? "..." : "")})" );
                            Console.WriteLine();
                        }
                    }

                    // Post-process: resolve symbols for functions that don't have names yet
                    Console.WriteLine ( "Resolving function names from symbols...\n" );

                    // Debug: Check how many code addresses have methods
                    int codeAddressesWithMethods = 0;
                    int totalCodeAddresses = 0;
                    foreach ( var ca in traceLog.CodeAddresses )
                    {
                        totalCodeAddresses++;
                        if ( ca?.Method != null )
                        {
                            codeAddressesWithMethods++;
                        }
                    }
                    if ( verbose )
                    {
                        Console.WriteLine ( $"Debug: Total code addresses: {totalCodeAddresses}, with methods: {codeAddressesWithMethods}" );
                    }

                    ResolveFunctionNames ( traceLog, functionStats, verbose );

                    // Get profile interval for time calculation
                    double profileIntervalMs = GetProfileIntervalMs ( traceLog, verbose );

                    // Display top functions
                    DisplayTopFunctions ( functionStats, processNames, topCount, totalStacks, filterPid, profileIntervalMs, callTrees, verbose );
                }
            }
        }
        finally
        {
            // Restore console output
            if ( !verbose && originalOut != null )
            {
                Console.SetOut ( originalOut );
                symbolFilter?.Dispose();
            }

            // Restore original symbol path if we changed it
            if ( symbolPathSet )
            {
                if ( originalSymbolPath == null )
                {
                    Environment.SetEnvironmentVariable ( "_NT_SYMBOL_PATH", null );
                }
                else
                {
                    Environment.SetEnvironmentVariable ( "_NT_SYMBOL_PATH", originalSymbolPath );
                }
            }
        }
    }

    static string GetFunctionKey ( ulong address, uint processId )
    {
        return $"{processId:X8}:{address:X16}";
    }

    /// <summary>
    /// Получает имя функции и модуля из TraceCodeAddress.
    /// Использует не только Method.FullMethodName, но и рефлексию для доступа к SymbolReader,
    /// так как TraceEvent часто хранит символы в SymbolReader, а не в Method.
    /// </summary>
    static ( string? name, string? module ) GetSymbolName ( TraceCodeAddress ca, TraceLog? traceLog = null )
    {
        string? moduleName = null;
        string? methodName = null;

        try
        {
            moduleName = ca.ModuleFile?.Name;

            // 1. Пытаемся использовать Method.FullMethodName, если он есть
            if ( ca.Method != null && !string.IsNullOrEmpty ( ca.Method.FullMethodName ) )
            {
                methodName = ca.Method.FullMethodName;
            }

            // 2. Fallback — используем рефлексию для доступа к SymbolReader через TraceLog
            // и пытаемся разрешить символы напрямую
            if ( string.IsNullOrEmpty ( methodName ) && traceLog != null )
            {
                try
                {
                    // Попробуем получить SymbolReader через рефлексию
                    var traceLogType = traceLog.GetType();
                    var symbolReaderProp = traceLogType.GetProperty ( "SymbolReader",
                                           System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                    if ( symbolReaderProp != null )
                    {
                        var symbolReader = symbolReaderProp.GetValue ( traceLog );
                        if ( symbolReader != null )
                        {
                            var symbolReaderType = symbolReader.GetType();

                            // Попробуем вызвать методы разрешения символов
                            // Ищем методы типа GetSymbolName, GetFunctionName, ResolveSymbol и т.д.
                            var methods = symbolReaderType.GetMethods ( System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                            foreach ( var method in methods )
                            {
                                // Ищем методы, которые принимают TraceCodeAddress или ulong (address)
                                var parameters = method.GetParameters();
                                if ( parameters.Length == 1 )
                                {
                                    try
                                    {
                                        object? result = null;
                                        if ( parameters[0].ParameterType == typeof ( TraceCodeAddress ) )
                                        {
                                            result = method.Invoke ( symbolReader, new object[] { ca } );
                                        }
                                        else if ( parameters[0].ParameterType == typeof ( ulong ) || parameters[0].ParameterType == typeof ( long ) )
                                        {
                                            result = method.Invoke ( symbolReader, new object[] { ca.Address } );
                                        }

                                        if ( result != null )
                                        {
                                            var resultStr = result.ToString();
                                            if ( !string.IsNullOrEmpty ( resultStr ) &&
                                                    !resultStr.Contains ( "CodeAddress" ) &&
                                                    !resultStr.Contains ( "<" ) &&
                                                    resultStr.Length < 500 ) // Разумная длина для имени функции
                                            {
                                                methodName = resultStr;
                                                break;
                                            }
                                        }
                                    }
                                    catch
                                    {
                                        // Продолжаем поиск
                                    }
                                }
                            }
                        }
                    }

                    // Если SymbolReader не помог, попробуем получить свойство Symbol на TraceCodeAddress
                    if ( string.IsNullOrEmpty ( methodName ) )
                    {
                        var codeAddrType = ca.GetType();

                        // Попробуем получить свойство Symbol
                        var symbolProp = codeAddrType.GetProperty ( "Symbol",
                                         System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                        if ( symbolProp != null )
                        {
                            var symbol = symbolProp.GetValue ( ca );
                            if ( symbol != null )
                            {
                                var symbolType = symbol.GetType();

                                // Попробуем разные свойства для имени функции
                                var nameProps = new[] { "Name", "FunctionName", "FullName", "MethodName", "SymbolName" };
                                foreach ( var propName in nameProps )
                                {
                                    var nameProp = symbolType.GetProperty ( propName,
                                                                            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                                    if ( nameProp != null )
                                    {
                                        var name = nameProp.GetValue ( symbol ) ?.ToString();
                                        if ( !string.IsNullOrEmpty ( name ) && !name.Contains ( "CodeAddress" ) && !name.Contains ( "<" ) )
                                        {
                                            methodName = name;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        // Попробуем использовать ToString() - иногда он содержит имя функции
                        if ( string.IsNullOrEmpty ( methodName ) )
                        {
                            try
                            {
                                var toString = ca.ToString();
                                if ( !string.IsNullOrEmpty ( toString ) &&
                                        !toString.Contains ( "CodeAddress" ) &&
                                        !toString.Contains ( "<" ) &&
                                        !toString.StartsWith ( "0x" ) &&
                                        toString.Length < 200 )
                                {
                                    // Проверяем, что это похоже на имя функции (содержит буквы и не только адрес)
                                    if ( toString.Any ( char.IsLetter ) )
                                    {
                                        methodName = toString;
                                    }
                                }
                            }
                            catch
                            {
                                // Ignore
                            }
                        }
                    }
                }
                catch
                {
                    // Игнорируем ошибки рефлексии
                }
            }
        }
        catch
        {
            // игнорируем, оставим null
        }

        return ( methodName, moduleName );
    }

    static void ResolveFunctionNames ( TraceLog traceLog, Dictionary<string, FunctionStats> functionStats, bool verbose = false )
    {
        // Build lookup: address -> code address with method
        var addressToCodeAddress = new Dictionary<ulong, TraceCodeAddress>();
        var addressToMethod = new Dictionary<ulong, TraceMethod>();

        // Also build lookup by module and address range for better matching
        var moduleAddressRanges = new Dictionary<string, List< ( ulong start, ulong end, TraceCodeAddress codeAddr ) >>();

        foreach ( var codeAddr in traceLog.CodeAddresses )
        {
            if ( codeAddr != null )
            {
                // Store by exact address
                if ( !addressToCodeAddress.ContainsKey ( codeAddr.Address ) )
                {
                    addressToCodeAddress[codeAddr.Address] = codeAddr;
                }

                // Store method if available
                var method = codeAddr.Method;
                if ( method != null )
                {
                    // Store method start address
                    if ( !addressToMethod.ContainsKey ( codeAddr.Address ) )
                    {
                        addressToMethod[codeAddr.Address] = method;
                    }
                }

                // Group by module for range-based lookup
                var module = codeAddr.ModuleFile;
                if ( module != null )
                {
                    string moduleName = module.Name ?? "Unknown";
                    if ( !moduleAddressRanges.ContainsKey ( moduleName ) )
                    {
                        moduleAddressRanges[moduleName] = new List< ( ulong, ulong, TraceCodeAddress ) >();
                    }
                    // Estimate range (method typically spans some bytes)
                    ulong endAddr = codeAddr.Address + 0x1000; // Default estimate
                    moduleAddressRanges[moduleName].Add ( ( codeAddr.Address, endAddr, codeAddr ) );
                }
            }
        }

        // Also build method ranges for nearest match
        var methodRanges = new List < ( ulong start, ulong end, TraceMethod method, TraceModuleFile? module, TraceCodeAddress codeAddr ) > ();
        foreach ( var codeAddr in traceLog.CodeAddresses )
        {
            if ( codeAddr != null && codeAddr.Method != null )
            {
                var method = codeAddr.Method;
                // Estimate method end (start + size if available, or use next method start)
                ulong methodStart = codeAddr.Address;
                ulong methodEnd = methodStart + 0x1000; // Default estimate

                methodRanges.Add ( ( methodStart, methodEnd, method, codeAddr.ModuleFile, codeAddr ) );
            }
        }

        int resolved = 0;
        int exactMatches = 0;
        int nearestMatches = 0;
        int addressesInLookup = addressToCodeAddress.Count;
        int methodsInLookup = addressToMethod.Count;

        if ( verbose )
        {
            Console.WriteLine ( $"Debug: Addresses in lookup: {addressesInLookup}, Methods in lookup: {methodsInLookup}" );
            Console.WriteLine ( $"Debug: Functions to resolve: {functionStats.Values.Count(f => string.IsNullOrEmpty(f.FunctionName))}" );
        }

        foreach ( var func in functionStats.Values )
        {
            if ( string.IsNullOrEmpty ( func.FunctionName ) )
            {
                bool found = false;

                // Try exact match first
                if ( addressToCodeAddress.TryGetValue ( func.Address, out var codeAddr ) )
                {
                    try
                    {
                        // Try to load symbols for the module if not already loaded
                        var module = codeAddr.ModuleFile;
                        if ( module != null && codeAddr.Method == null )
                        {
                            try
                            {
                                // Try to load symbols for this module
                                var moduleNameForLookup = Path.GetFileNameWithoutExtension ( module.Name ?? "" );
                                if ( !string.IsNullOrEmpty ( moduleNameForLookup ) )
                                {
                                    var lookupMethods = traceLog.CodeAddresses.GetType().GetMethods (
                                                            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance )
                                                        .Where ( m => m.Name == "LookupSymbolsForModule" )
                                                        .ToList();

                                    var lookupByNameMethod = lookupMethods.FirstOrDefault ( m =>
                                    {
                                        var parameters = m.GetParameters();
                                        return parameters.Length == 1 && parameters[0].ParameterType == typeof ( string );
                                    } );

                                    if ( lookupByNameMethod != null )
                                    {
                                        try
                                        {
                                            lookupByNameMethod.Invoke ( traceLog.CodeAddresses, new object[] { moduleNameForLookup } );
                                            // Re-check the code address after loading symbols
                                            codeAddr = addressToCodeAddress[func.Address];
                                        }
                                        catch
                                        {
                                            // Ignore errors during symbol loading
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                // Ignore errors
                            }
                        }

                        // Use GetSymbolName helper which checks both Method and SymbolReader
                        var ( methodName, moduleName ) = GetSymbolName ( codeAddr, traceLog );
                        if ( !string.IsNullOrEmpty ( methodName ) )
                        {
                            func.FunctionName = methodName;
                            resolved++;
                            exactMatches++;
                            found = true;

                            if ( verbose && resolved <= 5 )
                            {
                                Console.WriteLine ( $"Debug: Resolved {func.Address:X16} -> {methodName}" );
                            }
                        }
                        else if ( verbose && resolved == 0 )
                        {
                            Console.WriteLine ( $"Debug: Could not resolve function name for {func.Address:X16}" );
                        }

                        // Update module name if we got it
                        if ( string.IsNullOrEmpty ( func.ModuleName ) && !string.IsNullOrEmpty ( moduleName ) )
                        {
                            func.ModuleName = moduleName;
                        }

                        if ( string.IsNullOrEmpty ( func.ModuleName ) )
                        {
                            var moduleFile = codeAddr.ModuleFile;
                            if ( moduleFile != null )
                            {
                                func.ModuleName = moduleFile.Name;
                            }
                        }
                    }
                    catch ( Exception ex )
                    {
                        if ( verbose && resolved == 0 )
                        {
                            Console.WriteLine ( $"Debug: Exception resolving {func.Address:X16}: {ex.Message}" );
                        }
                    }
                }
                else
                {
                    // Address not found in lookup - try to find it by searching through modules
                    if ( !string.IsNullOrEmpty ( func.ModuleName ) )
                    {
                        try
                        {
                            // Try to find the module and create a code address for this address
                            TraceModuleFile? targetModule = null;
                            foreach ( var mf in traceLog.ModuleFiles )
                            {
                                if ( mf.Name != null && ( mf.Name.Contains ( func.ModuleName ) || Path.GetFileNameWithoutExtension ( mf.Name ) == func.ModuleName ) )
                                {
                                    targetModule = mf;
                                    break;
                                }
                            }

                            if ( targetModule != null )
                            {
                                // Try to find a code address in this module that's close to our address
                                TraceCodeAddress? closestCodeAddr = null;
                                ulong closestDistance = ulong.MaxValue;

                                foreach ( var ca in traceLog.CodeAddresses )
                                {
                                    if ( ca != null && ca.ModuleFile == targetModule )
                                    {
                                        if ( ca.Address == func.Address )
                                        {
                                            closestCodeAddr = ca;
                                            closestDistance = 0;
                                            break;
                                        }
                                        else if ( ca.Address < func.Address )
                                        {
                                            ulong distance = func.Address - ca.Address;
                                            if ( distance < closestDistance && distance < 0x100000 ) // Within 1MB
                                            {
                                                closestDistance = distance;
                                                closestCodeAddr = ca;
                                            }
                                        }
                                    }
                                }

                                if ( closestCodeAddr != null )
                                {
                                    var ( methodName, moduleName ) = GetSymbolName ( closestCodeAddr, traceLog );
                                    if ( !string.IsNullOrEmpty ( methodName ) )
                                    {
                                        func.FunctionName = methodName;
                                        if ( closestDistance > 0 )
                                        {
                                            func.FunctionName += $"+0x{closestDistance:X}";
                                        }
                                        resolved++;
                                        nearestMatches++;
                                        found = true;

                                        if ( verbose && resolved <= 5 )
                                        {
                                            Console.WriteLine ( $"Debug: Resolved {func.Address:X16} -> {methodName} (nearest match, distance: 0x{closestDistance:X})" );
                                        }
                                    }
                                }
                            }
                        }
                        catch
                        {
                            // Ignore errors
                        }
                    }

                    if ( verbose && resolved == 0 && exactMatches == 0 && !found )
                    {
                        // Only show first few misses
                        if ( nearestMatches < 3 )
                        {
                            Console.WriteLine ( $"Debug: Address {func.Address:X16} not found in CodeAddresses lookup" );
                        }
                    }
                }

                // Try nearest match if exact match failed
                if ( !found )
                {
                    TraceMethod? nearestMethod = null;
                    TraceModuleFile? nearestModule = null;
                    ulong nearestDistance = ulong.MaxValue;

                    // First try in the same module if we know it
                    if ( !string.IsNullOrEmpty ( func.ModuleName ) && moduleAddressRanges.ContainsKey ( func.ModuleName ) )
                    {
                        foreach ( var ( start, end, rangeCodeAddr ) in moduleAddressRanges[func.ModuleName] )
                        {
                            if ( func.Address >= start && func.Address < end )
                            {
                                ulong distance = func.Address - start;
                                if ( distance < nearestDistance )
                                {
                                    nearestDistance = distance;
                                    var method = rangeCodeAddr.Method;
                                    if ( method != null )
                                    {
                                        nearestMethod = method;
                                        nearestModule = rangeCodeAddr.ModuleFile;
                                    }
                                }
                            }
                            else if ( start < func.Address && func.Address - start < 0x100000 ) // Within 1MB (increased from 64KB)
                            {
                                ulong distance = func.Address - start;
                                if ( distance < nearestDistance )
                                {
                                    nearestDistance = distance;
                                    var method = rangeCodeAddr.Method;
                                    if ( method != null )
                                    {
                                        nearestMethod = method;
                                        nearestModule = rangeCodeAddr.ModuleFile;
                                    }
                                }
                            }
                        }
                    }

                    // If not found in same module, try all modules
                    TraceCodeAddress? nearestCodeAddr = null;
                    if ( nearestMethod == null )
                    {
                        foreach ( var ( start, end, method, module, methodCodeAddr ) in methodRanges )
                        {
                            if ( func.Address >= start && func.Address < end )
                            {
                                ulong distance = func.Address - start;
                                if ( distance < nearestDistance )
                                {
                                    nearestDistance = distance;
                                    nearestMethod = method;
                                    nearestModule = module;
                                    nearestCodeAddr = methodCodeAddr;
                                }
                            }
                            else if ( start < func.Address && func.Address - start < 0x100000 ) // Within 1MB (increased from 64KB)
                            {
                                ulong distance = func.Address - start;
                                if ( distance < nearestDistance )
                                {
                                    nearestDistance = distance;
                                    nearestMethod = method;
                                    nearestModule = module;
                                    nearestCodeAddr = methodCodeAddr;
                                }
                            }
                        }
                    }
                    else
                    {
                        // Find the code address for the nearest method from moduleAddressRanges
                        if ( !string.IsNullOrEmpty ( func.ModuleName ) && moduleAddressRanges.ContainsKey ( func.ModuleName ) )
                        {
                            foreach ( var ( start, end, rangeCodeAddr ) in moduleAddressRanges[func.ModuleName] )
                            {
                                if ( rangeCodeAddr.Method == nearestMethod )
                                {
                                    nearestCodeAddr = rangeCodeAddr;
                                    break;
                                }
                            }
                        }
                    }

                    if ( nearestMethod != null && nearestDistance < 0x100000 ) // Increased from 64KB to 1MB
                    {
                        try
                        {
                            string? methodName = null;

                            // First try Method.FullMethodName
                            if ( !string.IsNullOrEmpty ( nearestMethod.FullMethodName ) )
                            {
                                methodName = nearestMethod.FullMethodName;
                            }

                            // Fallback: use GetSymbolName on the code address
                            if ( string.IsNullOrEmpty ( methodName ) && nearestCodeAddr != null )
                            {
                                // Note: traceLog is not available here, but we can try without it
                                var ( name, _ ) = GetSymbolName ( nearestCodeAddr, null );
                                methodName = name;
                            }

                            if ( !string.IsNullOrEmpty ( methodName ) )
                            {
                                func.FunctionName = methodName;
                                if ( nearestDistance > 0 )
                                {
                                    func.FunctionName += $"+0x{nearestDistance:X}";
                                }
                                resolved++;
                                nearestMatches++;
                                found = true;
                            }

                            if ( string.IsNullOrEmpty ( func.ModuleName ) && nearestModule != null )
                            {
                                func.ModuleName = nearestModule.Name;
                            }
                            else if ( string.IsNullOrEmpty ( func.ModuleName ) && nearestCodeAddr != null )
                            {
                                var ( _, moduleName ) = GetSymbolName ( nearestCodeAddr, null );
                                if ( !string.IsNullOrEmpty ( moduleName ) )
                                {
                                    func.ModuleName = moduleName;
                                }
                            }
                        }
                        catch
                        {
                            // Ignore errors
                        }
                    }
                }
            }
        }

        if ( resolved > 0 )
        {
            Console.WriteLine ( $"✓ Resolved {resolved:N0} function names from symbols ({exactMatches} exact, {nearestMatches} nearest)\n" );
        }
        else
        {
            Console.WriteLine ( "⚠ No function names resolved (symbols may not be available)\n" );
        }
    }

    static void ShowProgressBar ( CancellationToken cancellationToken, double? megabytes = null )
    {
        const string snake = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
        int index = 0;
        double? currentMB = megabytes;

        while ( !cancellationToken.IsCancellationRequested )
        {
            string mbText = currentMB.HasValue ? $" {currentMB.Value:F2} MB" : "";
            Console.Write ( $"\r{snake[index % snake.Length]}{mbText}" );
            index++;
            Thread.Sleep ( 100 );
        }
    }

    static void ShowProgressBarWithUpdate ( CancellationToken cancellationToken, Func < double? > getMegabytes )
    {
        const string snake = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
        int index = 0;

        while ( !cancellationToken.IsCancellationRequested )
        {
            double? currentMB = getMegabytes();
            string mbText = currentMB.HasValue ? $" {currentMB.Value:F2} MB" : "";
            Console.Write ( $"\r{snake[index % snake.Length]}{mbText}" );
            index++;
            Thread.Sleep ( 100 );
        }
    }

    /// <summary>
    /// Ожидает завершения задачи с умным таймаутом: пропускает только если размер кэша не растет.
    /// Если мегабайты загружаются, продолжает ждать даже после таймаута.
    /// Также пропускает, если размер символов превышает maxSizeMB.
    /// </summary>
    static bool WaitWithProgressCheck ( Task lookupTask, int timeoutSeconds, double initialSizeMB, CancellationTokenSource progressToken, double? maxSizeMB, string? moduleName, out string? skipReason )
    {
        skipReason = null;
        const int checkIntervalMs = 2000; // Проверяем размер каждые 2 секунды
        const double minProgressMB = 0.01; // Минимальный прогресс в MB для считания активной загрузки

        DateTime startTime = DateTime.Now;
        DateTime lastProgressTime = DateTime.Now;
        double lastSizeMB = initialSizeMB;

        while ( !lookupTask.IsCompleted )
        {
            // Проверяем, завершилась ли задача
            if ( lookupTask.Wait ( TimeSpan.FromMilliseconds ( checkIntervalMs ) ) )
            {
                return true; // Задача завершилась успешно
            }

            // Проверяем текущий размер кэша
            double currentSizeMB = GetSymbolCacheSizeMB ( Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" ) );
            double loadedMB = Math.Max ( 0, currentSizeMB - initialSizeMB );

            // Проверяем лимит размера (если установлен)
            if ( maxSizeMB.HasValue && loadedMB > maxSizeMB.Value )
            {
                // Размер превысил лимит - пропускаем
                skipReason = FormatSkipReason ( $"size {loadedMB:F2} MB exceeds limit {maxSizeMB.Value:F0} MB", moduleName );
                progressToken.Cancel();
                return false;
            }

            // Если размер вырос, обновляем время последнего прогресса
            if ( currentSizeMB - lastSizeMB >= minProgressMB )
            {
                lastProgressTime = DateTime.Now;
                lastSizeMB = currentSizeMB;
            }

            // Проверяем, не прошло ли слишком много времени без прогресса
            TimeSpan timeSinceLastProgress = DateTime.Now - lastProgressTime;
            if ( timeSinceLastProgress.TotalSeconds >= timeoutSeconds )
            {
                // Нет прогресса в течение таймаута - пропускаем
                skipReason = FormatSkipReason ( $"no progress for {timeoutSeconds}s", moduleName );
                progressToken.Cancel();
                return false;
            }

            // Если общее время ожидания превысило таймаут в 3 раза, но есть прогресс, продолжаем
            // Но если нет прогресса вообще, пропускаем
            TimeSpan totalTime = DateTime.Now - startTime;
            if ( totalTime.TotalSeconds >= timeoutSeconds * 3 && loadedMB < minProgressMB )
            {
                // Слишком долго ждем и нет прогресса
                skipReason = FormatSkipReason ( $"no progress for {totalTime.TotalSeconds:F0}s", moduleName );
                progressToken.Cancel();
                return false;
            }
        }

        // Задача завершилась
        return true;
    }

    static string FormatSkipReason ( string reason, string? moduleName )
    => moduleName != null ? $"{reason} ({moduleName})" : reason;

    /// <summary>
    /// Получает размер кэша символов в мегабайтах
    /// </summary>
    static double GetSymbolCacheSizeMB ( string? symbolPath = null )
    {
        try
        {
            // Получаем путь к кэшу символов
            string? cachePath = null;

            if ( !string.IsNullOrEmpty ( symbolPath ) )
            {
                // Формат: "srv*cache*server" или "cache;..."
                var parts = symbolPath.Split ( ';' );
                foreach ( var part in parts )
                {
                    if ( part.StartsWith ( "srv*" ) )
                    {
                        var srvParts = part.Split ( '*' );
                        if ( srvParts.Length >= 2 && !string.IsNullOrEmpty ( srvParts[1] ) )
                        {
                            cachePath = srvParts[1];
                            break;
                        }
                    }
                    else if ( Directory.Exists ( part ) )
                    {
                        cachePath = part;
                        break;
                    }
                }
            }

            // Если не нашли в symbolPath, пробуем из переменной окружения
            if ( string.IsNullOrEmpty ( cachePath ) )
            {
                var envPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
                if ( !string.IsNullOrEmpty ( envPath ) )
                {
                    var parts = envPath.Split ( ';' );
                    foreach ( var part in parts )
                    {
                        if ( part.StartsWith ( "srv*" ) )
                        {
                            var srvParts = part.Split ( '*' );
                            if ( srvParts.Length >= 2 && !string.IsNullOrEmpty ( srvParts[1] ) )
                            {
                                cachePath = srvParts[1];
                                break;
                            }
                        }
                        else if ( Directory.Exists ( part ) )
                        {
                            cachePath = part;
                            break;
                        }
                    }
                }
            }

            // Если все еще не нашли, используем стандартный путь кэша
            if ( string.IsNullOrEmpty ( cachePath ) )
            {
                cachePath = Path.Combine ( Environment.GetFolderPath ( Environment.SpecialFolder.LocalApplicationData ), "SymbolCache" );
            }

            // Вычисляем размер директории
            if ( Directory.Exists ( cachePath ) )
            {
                long totalSize = 0;
                try
                {
                    var files = Directory.GetFiles ( cachePath, "*", SearchOption.AllDirectories );
                    foreach ( var file in files )
                    {
                        try
                        {
                            var fileInfo = new FileInfo ( file );
                            totalSize += fileInfo.Length;
                        }
                        catch
                        {
                            // Игнорируем ошибки доступа к отдельным файлам
                        }
                    }
                }
                catch
                {
                    // Игнорируем ошибки доступа
                }

                return totalSize / ( 1024.0 * 1024.0 ); // Конвертируем в MB
            }
        }
        catch
        {
            // Игнорируем ошибки
        }

        return 0;
    }

    /// <summary>
    /// Получает размер PDB файла для модуля, если он доступен
    /// </summary>
    static double GetModulePdbSizeMB ( TraceModuleFile? moduleFile, object? symbolReader = null )
    {
        if ( moduleFile == null )
        {
            return 0;
        }

        try
        {
            // Пробуем получить путь к PDB через рефлексию
            if ( symbolReader != null )
            {
                var symbolReaderType = symbolReader.GetType();

                // Ищем методы для получения пути к PDB
                var methods = symbolReaderType.GetMethods (
                                  System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                foreach ( var method in methods )
                {
                    if ( ( method.Name.Contains ( "FindSymbolFilePath" ) || method.Name.Contains ( "GetPdbPath" ) ) &&
                            method.GetParameters().Length >= 1 )
                    {
                        try
                        {
                            var parameters = method.GetParameters();
                            object? result = null;

                            // Пробуем вызвать с TraceModuleFile
                            if ( parameters[0].ParameterType == typeof ( TraceModuleFile ) ||
                                    parameters[0].ParameterType.IsAssignableFrom ( typeof ( TraceModuleFile ) ) )
                            {
                                result = method.Invoke ( symbolReader, new object[] { moduleFile } );
                            }
                            // Или с именем модуля
                            else if ( parameters[0].ParameterType == typeof ( string ) )
                            {
                                result = method.Invoke ( symbolReader, new object[] { moduleFile.Name ?? "" } );
                            }

                            if ( result is string pdbPath && File.Exists ( pdbPath ) )
                            {
                                var fileInfo = new FileInfo ( pdbPath );
                                return fileInfo.Length / ( 1024.0 * 1024.0 );
                            }
                        }
                        catch
                        {
                            // Продолжаем поиск
                        }
                    }
                }
            }

            // Fallback: пробуем найти PDB по стандартным путям
            if ( !string.IsNullOrEmpty ( moduleFile.Name ) )
            {
                var moduleName = Path.GetFileNameWithoutExtension ( moduleFile.Name );
                var pdbName = moduleName + ".pdb";

                // Проверяем стандартные пути
                var searchPaths = new List<string>();

                // Из переменной окружения
                var envPath = Environment.GetEnvironmentVariable ( "_NT_SYMBOL_PATH" );
                if ( !string.IsNullOrEmpty ( envPath ) )
                {
                    var parts = envPath.Split ( ';' );
                    foreach ( var part in parts )
                    {
                        if ( part.StartsWith ( "srv*" ) )
                        {
                            var srvParts = part.Split ( '*' );
                            if ( srvParts.Length >= 2 && !string.IsNullOrEmpty ( srvParts[1] ) )
                            {
                                searchPaths.Add ( srvParts[1] );
                            }
                        }
                        else if ( Directory.Exists ( part ) )
                        {
                            searchPaths.Add ( part );
                        }
                    }
                }

                // Стандартный кэш
                var defaultCache = Path.Combine ( Environment.GetFolderPath ( Environment.SpecialFolder.LocalApplicationData ), "SymbolCache" );
                if ( Directory.Exists ( defaultCache ) )
                {
                    searchPaths.Add ( defaultCache );
                }

                // Ищем PDB файл
                foreach ( var searchPath in searchPaths )
                {
                    try
                    {
                        var files = Directory.GetFiles ( searchPath, pdbName, SearchOption.AllDirectories );
                        if ( files.Length > 0 )
                        {
                            var fileInfo = new FileInfo ( files[0] );
                            return fileInfo.Length / ( 1024.0 * 1024.0 );
                        }
                    }
                    catch
                    {
                        // Игнорируем
                    }
                }
            }
        }
        catch
        {
            // Игнорируем ошибки
        }

        return 0;
    }

    /// <summary>
    /// Получает интервал профилирования в миллисекундах из TraceLog.
    /// Согласно документации Microsoft, интервал можно получить из Stats или вычислить из временных меток событий.
    /// </summary>
    static double GetProfileIntervalMs ( TraceLog traceLog, bool verbose = false )
    {
        try
        {
            // Метод 1: Попробуем получить из Stats
            var stats = traceLog.Stats;
            if ( stats != null )
            {
                var statsType = stats.GetType();

                // Список возможных имен свойств для интервала
                var intervalPropNames = new[]
                {
                    "SampleProfileInterval",
                    "ProfileInterval",
                    "SamplingInterval",
                    "SampleInterval",
                    "Interval"
                };

                foreach ( var propName in intervalPropNames )
                {
                    var intervalProp = statsType.GetProperty ( propName,
                                       System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                    if ( intervalProp != null )
                    {
                        var interval = intervalProp.GetValue ( stats );
                        if ( interval != null )
                        {
                            double intervalValueMs = ConvertIntervalToMs ( interval, verbose );
                            if ( intervalValueMs > 0 )
                            {
                                if ( verbose )
                                {
                                    Console.WriteLine ( $"Found profile interval in Stats.{propName}: {intervalValueMs:F3} ms" );
                                }
                                return intervalValueMs;
                            }
                        }
                    }
                }

                // Попробуем получить все свойства Stats для отладки
                if ( verbose )
                {
                    var allProps = statsType.GetProperties (
                                       System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );
                    var intervalRelatedProps = allProps.Where ( p =>
                                               p.Name.Contains ( "Interval", StringComparison.OrdinalIgnoreCase ) ||
                                               p.Name.Contains ( "Sample", StringComparison.OrdinalIgnoreCase ) ||
                                               p.Name.Contains ( "Profile", StringComparison.OrdinalIgnoreCase ) ).ToList();

                    if ( intervalRelatedProps.Count > 0 )
                    {
                        Console.WriteLine ( $"Available interval-related properties in Stats: {string.Join(", ", intervalRelatedProps.Select(p => p.Name))}" );
                    }
                }
            }

            // Метод 2: Попробуем получить из свойств TraceLog напрямую
            var traceLogType = traceLog.GetType();
            var traceLogPropNames = new[]
            {
                "SampleProfileInterval",
                "ProfileInterval",
                "SamplingInterval"
            };

            foreach ( var propName in traceLogPropNames )
            {
                var intervalProp = traceLogType.GetProperty ( propName,
                                   System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance );

                if ( intervalProp != null )
                {
                    var interval = intervalProp.GetValue ( traceLog );
                    if ( interval != null )
                    {
                        double intervalValueMs = ConvertIntervalToMs ( interval, verbose );
                        if ( intervalValueMs > 0 )
                        {
                            if ( verbose )
                            {
                                Console.WriteLine ( $"Found profile interval in TraceLog.{propName}: {intervalValueMs:F3} ms" );
                            }
                            return intervalValueMs;
                        }
                    }
                }
            }

            // Метод 3: Вычислить интервал из временных меток PerfInfo событий
            try
            {
                var intervals = new List<double>();
                double? lastTimestamp = null;
                int sampleCount = 0;

                using ( var source = traceLog.Events.GetSource() )
                {
                    var kernelParser = new KernelTraceEventParser ( source );

                    kernelParser.PerfInfoSample += ( SampledProfileTraceData data ) =>
                    {
                        sampleCount++;
                        if ( sampleCount > 100 )
                        {
                            return;    // Ограничиваем для производительности
                        }

                        // Получаем timestamp в миллисекундах относительно начала трассировки
                        double currentTimestampMs = data.TimeStampRelativeMSec;

                        if ( lastTimestamp.HasValue && currentTimestampMs > lastTimestamp.Value )
                        {
                            // Вычисляем интервал в миллисекундах
                            double intervalMs = currentTimestampMs - lastTimestamp.Value;

                            // Фильтруем разумные значения (от 0.1 мс до 100 мс)
                            if ( intervalMs >= 0.1 && intervalMs <= 100 )
                            {
                                intervals.Add ( intervalMs );
                            }
                        }

                        lastTimestamp = currentTimestampMs;
                    };

                    // Обрабатываем первые события для вычисления интервала
                    source.Process();
                }

                if ( intervals.Count > 10 )
                {
                    // Используем медиану для более точного результата
                    intervals.Sort();
                    double medianInterval = intervals[intervals.Count / 2];

                    if ( verbose )
                    {
                        Console.WriteLine ( $"Calculated profile interval from event timestamps: {medianInterval:F3} ms (from {intervals.Count} samples)" );
                    }
                    return medianInterval;
                }
            }
            catch ( Exception ex )
            {
                if ( verbose )
                {
                    Console.WriteLine ( $"Could not calculate interval from timestamps: {ex.Message}" );
                }
            }
        }
        catch ( Exception ex )
        {
            if ( verbose )
            {
                Console.WriteLine ( $"Warning: Could not determine profile interval: {ex.Message}" );
            }
        }

        // По умолчанию используем 1 мс (1000 Гц) - стандартный интервал для CPU profiling
        if ( verbose )
        {
            Console.WriteLine ( "Using default profile interval: 1.0 ms (1000 Hz)" );
        }
        return 1.0;
    }

    /// <summary>
    /// Конвертирует значение интервала в миллисекунды
    /// </summary>
    static double ConvertIntervalToMs ( object interval, bool verbose = false )
    {
        try
        {
            // Проверяем, является ли это TimeSpan
            if ( interval is TimeSpan timeSpan )
            {
                return timeSpan.TotalMilliseconds;
            }

            // Попробуем конвертировать в число
            double intervalValue = 0;

            if ( interval is IConvertible convertible )
            {
                intervalValue = convertible.ToDouble ( System.Globalization.CultureInfo.InvariantCulture );
            }
            else if ( double.TryParse ( interval.ToString(), System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out double parsed ) )
            {
                intervalValue = parsed;
            }
            else
            {
                return 0;
            }

            // Определяем единицы измерения на основе значения
            // Если это тики (100ns), конвертируем в мс
            if ( intervalValue > 10000 ) // Если больше 10000, вероятно это тики (100ns)
            {
                return intervalValue / 10000.0; // 100ns -> ms
            }
            // Если это микросекунды
            else if ( intervalValue > 10 )
            {
                return intervalValue / 1000.0; // us -> ms
            }
            // Если уже в миллисекундах
            else if ( intervalValue > 0 )
            {
                return intervalValue;
            }
        }
        catch ( Exception ex )
        {
            if ( verbose )
            {
                Console.WriteLine ( $"Error converting interval to ms: {ex.Message}" );
            }
        }

        return 0;
    }

    static void DisplayTopFunctions (
        Dictionary<string, FunctionStats> functionStats,
        Dictionary<uint, string> processes,
        int topCount,
        long totalSamples,
        uint? filterPid = null,
        double profileIntervalMs = 1.0,
        Dictionary<uint, CallTreeNode>? callTrees = null,
        bool verbose = false )
    {
        // If filtering by PID, show functions from that process first
        if ( filterPid.HasValue )
        {
            var targetProcessFunctions = functionStats.Values
                                         .Where ( f => f.ProcessId == filterPid.Value )
                                         .OrderByDescending ( f => f.ExclusiveSamples )
                                         .ToList();

            if ( targetProcessFunctions.Count > 0 )
            {
                string processName = processes.ContainsKey ( filterPid.Value )
                                     ? Path.GetFileName ( processes[filterPid.Value] )
                                     : $"PID {filterPid.Value}";

                Console.WriteLine ( $"=== Top {Math.Min(topCount, targetProcessFunctions.Count)} Functions from {processName} (PID {filterPid.Value}) by Exclusive Samples ===\n" );

                Console.WriteLine ( $"{"Rank",-6} {"Exclusive",-12} {"Inclusive",-12} {"Excl % ",-10} {"Incl % ",-10} {"Address",-18} {"Function / Module",-60}" );
                Console.WriteLine ( new string ( '-', 130 ) );

                int targetRank = 1;
                foreach ( var func in targetProcessFunctions.Take ( topCount ) )
                {
                    double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
                    double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

                    string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                         ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                         : !string.IsNullOrEmpty ( func.ModuleName )
                                         ? $"[{Path.GetFileName(func.ModuleName)}]"
                                         : processName;

                    Console.WriteLine ( $"{targetRank,-6} {func.ExclusiveSamples,-12:N0} {func.InclusiveSamples,-12:N0} " +
                                        $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                        $"0x{func.Address:X16} {funcDisplay,-60}" );

                    targetRank++;
                }

                // Show module statistics for target process
                var moduleStats = targetProcessFunctions
                                  .GroupBy ( f => Path.GetFileName ( f.ModuleName ?? "Unknown" ) )
                .Select ( g => new { Module = g.Key, Count = g.Count(), TotalExclusive = g.Sum ( f => f.ExclusiveSamples ), TotalInclusive = g.Sum ( f => f.InclusiveSamples ) } )
                .OrderByDescending ( m => m.TotalExclusive )
                .ToList();

                if ( moduleStats.Count > 0 )
                {
                    Console.WriteLine ( $"\n=== Module Statistics for {processName} ===\n" );
                    Console.WriteLine ( $"{"Module",-40} {"Functions",-12} {"Exclusive",-12} {"Inclusive",-12}" );
                    Console.WriteLine ( new string ( '-', 80 ) );
                    foreach ( var mod in moduleStats )
                    {
                        Console.WriteLine ( $"{mod.Module,-40} {mod.Count,-12:N0} {mod.TotalExclusive,-12:N0} {mod.TotalInclusive,-12:N0}" );
                    }
                    Console.WriteLine();

                    // Display call tree for filtered process (like Visual Studio)
                    if ( callTrees != null && callTrees.ContainsKey ( filterPid.Value ) )
                    {
                        var rootNode = callTrees[filterPid.Value];
                        if ( rootNode.Children.Count > 0 )
                        {
                            // Use target process samples for percentage calculation
                            long targetProcessSamples = rootNode.InclusiveSamples;
                            if ( targetProcessSamples <= 0 )
                            {
                                targetProcessSamples = targetProcessFunctions.Sum ( f => f.InclusiveSamples > 0 ? f.InclusiveSamples : f.ExclusiveSamples );
                            }

                            Console.WriteLine ( $"\n=== Call Tree for {processName} (PID {filterPid.Value}) ===\n" );
                            Console.WriteLine ( $"{"Function Name",-70} {"Total CPU",-20} {"Self CPU",-20} {"Total % ",-15} {"Self % ",-15}" );
                            Console.WriteLine ( new string ( '-', 140 ) );
                            DisplayCallTree (
                                rootNode,
                                functionStats,
                                targetProcessSamples > 0 ? targetProcessSamples : totalSamples,
                                profileIntervalMs,
                                "",
                                0,
                                10,
                                false,
                                true );
                            Console.WriteLine();
                        }
                        else if ( verbose )
                        {
                            Console.WriteLine ( $"\n[Debug] Call tree for PID {filterPid.Value} has no children (root node exists but empty)\n" );
                        }
                    }
                    else if ( verbose )
                    {
                        if ( callTrees == null )
                        {
                            Console.WriteLine ( $"\n[Debug] callTrees is null\n" );
                        }
                        else if ( !callTrees.ContainsKey ( filterPid.Value ) )
                        {
                            Console.WriteLine ( $"\n[Debug] Call tree not found for PID {filterPid.Value}. Available PIDs: {string.Join(", ", callTrees.Keys)}\n" );
                        }
                    }
                }

                Console.WriteLine ( $"\n=== Top {topCount} Functions by Exclusive Samples (All Processes) ===\n" );
            }
        }
        else
        {
            Console.WriteLine ( $"=== Top {topCount} Functions by Exclusive Samples ===\n" );
        }

        var topByExclusive = functionStats.Values
                             .OrderByDescending ( f => f.ExclusiveSamples )
                             .Take ( topCount )
                             .ToList();

        Console.WriteLine ( $"{"Rank",-6} {"Exclusive",-12} {"Inclusive",-12} {"Excl % ",-10} {"Incl % ",-10} {"Address",-18} {"Function / Module",-60}" );
        Console.WriteLine ( new string ( '-', 130 ) );

        int rank = 1;
        foreach ( var func in topByExclusive )
        {
            double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
            double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

            string processName = processes.ContainsKey ( func.ProcessId )
                                 ? Path.GetFileName ( processes[func.ProcessId] )
                                 : $"PID {func.ProcessId}";

            string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                 ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                 : !string.IsNullOrEmpty ( func.ModuleName )
                                 ? $"[{Path.GetFileName(func.ModuleName)}]"
                                 : processName;

            Console.WriteLine ( $"{rank,-6} {func.ExclusiveSamples,-12:N0} {func.InclusiveSamples,-12:N0} " +
                                $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                $"0x{func.Address:X16} {funcDisplay,-60}" );

            rank++;
        }

        Console.WriteLine ( $"\n=== Top {topCount} Functions by Inclusive Samples ===\n" );

        var topByInclusive = functionStats.Values
                             .OrderByDescending ( f => f.InclusiveSamples )
                             .Take ( topCount )
                             .ToList();

        Console.WriteLine ( $"{"Rank",-6} {"Exclusive",-12} {"Inclusive",-12} {"Excl % ",-10} {"Incl % ",-10} {"Address",-18} {"Function / Module",-60}" );
        Console.WriteLine ( new string ( '-', 130 ) );

        rank = 1;
        foreach ( var func in topByInclusive )
        {
            double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
            double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

            string processName = processes.ContainsKey ( func.ProcessId )
                                 ? Path.GetFileName ( processes[func.ProcessId] )
                                 : $"PID {func.ProcessId}";

            string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                 ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                 : !string.IsNullOrEmpty ( func.ModuleName )
                                 ? $"[{Path.GetFileName(func.ModuleName)}]"
                                 : processName;

            Console.WriteLine ( $"{rank,-6} {func.ExclusiveSamples,-12:N0} {func.InclusiveSamples,-12:N0} " +
                                $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                $"0x{func.Address:X16} {funcDisplay,-60}" );

            rank++;
        }

        // Statistics
        Console.WriteLine ( $"\n=== Statistics ===\n" );
        Console.WriteLine ( $"Total unique functions: {functionStats.Count:N0}" );
        Console.WriteLine ( $"Total stack samples: {totalSamples:N0}" );
        if ( functionStats.Values.Any ( f => f.ExclusiveSamples > 0 ) )
        {
            Console.WriteLine ( $"Average stack depth: {functionStats.Values.Average(f => (double)f.InclusiveSamples / Math.Max(1, f.ExclusiveSamples)):F2}" );
        }

        // Display functions sorted by time (milliseconds) - Microsoft style (Self CPU / Total CPU)
        Console.WriteLine ( $"\n=== Top {topCount} Functions by Self CPU Time (ms) ===\n" );
        Console.WriteLine ( $"Profile interval: {profileIntervalMs:F3} ms\n" );

        var topByExclusiveTime = functionStats.Values
                                 .Select ( f => new
        {
            Func = f,
            ExclusiveTimeMs = f.ExclusiveSamples * profileIntervalMs,
            InclusiveTimeMs = f.InclusiveSamples * profileIntervalMs
        } )
        .OrderByDescending ( x => x.ExclusiveTimeMs )
        .Take ( topCount )
        .ToList();

        Console.WriteLine ( $"{"Rank",-6} {"Self CPU",-12} {"Total CPU",-12} {"Self % ",-10} {"Total % ",-10} {"Address",-18} {"Function / Module",-60}" );
        Console.WriteLine ( new string ( '-', 130 ) );

        rank = 1;
        foreach ( var item in topByExclusiveTime )
        {
            var func = item.Func;
            double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
            double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

            string processName = processes.ContainsKey ( func.ProcessId )
                                 ? Path.GetFileName ( processes[func.ProcessId] )
                                 : $"PID {func.ProcessId}";

            string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                 ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                 : !string.IsNullOrEmpty ( func.ModuleName )
                                 ? $"[{Path.GetFileName(func.ModuleName)}]"
                                 : processName;

            Console.WriteLine ( $"{rank,-6} {item.ExclusiveTimeMs,-12:F2} {item.InclusiveTimeMs,-12:F2} " +
                                $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                $"0x{func.Address:X16} {funcDisplay,-60}" );

            rank++;
        }

        Console.WriteLine ( $"\n=== Top {topCount} Functions by Total CPU Time (ms) ===\n" );

        var topByInclusiveTime = functionStats.Values
                                 .Select ( f => new
        {
            Func = f,
            ExclusiveTimeMs = f.ExclusiveSamples * profileIntervalMs,
            InclusiveTimeMs = f.InclusiveSamples * profileIntervalMs
        } )
        .OrderByDescending ( x => x.InclusiveTimeMs )
        .Take ( topCount )
        .ToList();

        Console.WriteLine ( $"{"Rank",-6} {"Self CPU",-12} {"Total CPU",-12} {"Self % ",-10} {"Total % ",-10} {"Address",-18} {"Function / Module",-60}" );
        Console.WriteLine ( new string ( '-', 130 ) );

        rank = 1;
        foreach ( var item in topByInclusiveTime )
        {
            var func = item.Func;
            double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
            double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

            string processName = processes.ContainsKey ( func.ProcessId )
                                 ? Path.GetFileName ( processes[func.ProcessId] )
                                 : $"PID {func.ProcessId}";

            string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                 ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                 : !string.IsNullOrEmpty ( func.ModuleName )
                                 ? $"[{Path.GetFileName(func.ModuleName)}]"
                                 : processName;

            Console.WriteLine ( $"{rank,-6} {item.ExclusiveTimeMs,-12:F2} {item.InclusiveTimeMs,-12:F2} " +
                                $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                $"0x{func.Address:X16} {funcDisplay,-60}" );

            rank++;
        }

        // If filtering by PID, also show time-based sorting for target process
        if ( filterPid.HasValue )
        {
            var targetProcessFunctions = functionStats.Values
                                         .Where ( f => f.ProcessId == filterPid.Value )
                                         .Select ( f => new
            {
                Func = f,
                ExclusiveTimeMs = f.ExclusiveSamples * profileIntervalMs,
                InclusiveTimeMs = f.InclusiveSamples * profileIntervalMs
            } )
            .OrderByDescending ( x => x.ExclusiveTimeMs )
            .Take ( topCount )
            .ToList();

            if ( targetProcessFunctions.Count > 0 )
            {
                string processName = processes.ContainsKey ( filterPid.Value )
                                     ? Path.GetFileName ( processes[filterPid.Value] )
                                     : $"PID {filterPid.Value}";

                Console.WriteLine ( $"\n=== Top {Math.Min(topCount, targetProcessFunctions.Count)} Functions from {processName} by Self CPU Time (ms) ===\n" );

                Console.WriteLine ( $"{"Rank",-6} {"Self CPU",-12} {"Total CPU",-12} {"Self % ",-10} {"Total % ",-10} {"Address",-18} {"Function / Module",-60}" );
                Console.WriteLine ( new string ( '-', 130 ) );

                int targetTimeRank = 1;
                foreach ( var item in targetProcessFunctions )
                {
                    var func = item.Func;
                    double exclPercent = totalSamples > 0 ? ( func.ExclusiveSamples * 100.0 ) / totalSamples : 0;
                    double inclPercent = totalSamples > 0 ? ( func.InclusiveSamples * 100.0 ) / totalSamples : 0;

                    string funcDisplay = !string.IsNullOrEmpty ( func.FunctionName )
                                         ? $"{func.FunctionName} [{Path.GetFileName(func.ModuleName ?? "Unknown")}]"
                                         : !string.IsNullOrEmpty ( func.ModuleName )
                                         ? $"[{Path.GetFileName(func.ModuleName)}]"
                                         : processName;

                    Console.WriteLine ( $"{targetTimeRank,-6} {item.ExclusiveTimeMs,-12:F2} {item.InclusiveTimeMs,-12:F2} " +
                                        $"{exclPercent,-10:F2}% {inclPercent,-10:F2}% " +
                                        $"0x{func.Address:X16} {funcDisplay,-60}" );

                    targetTimeRank++;
                }
            }
        }
    }

    // Display call tree recursively (like Visual Studio)
    static void DisplayCallTree (
        CallTreeNode node,
        Dictionary<string, FunctionStats> functionStats,
        long totalSamples,
        double profileIntervalMs,
        string prefix,
        int depth,
        int maxDepth = 10,
        bool isLast = false,
        bool isRoot = false )
    {
        if ( depth > maxDepth )
        {
            return;
        }

        // Calculate times and percentages
        long inclusiveSamples = node.InclusiveSamples;
        long exclusiveSamples = node.ExclusiveSamples;
        double inclusiveTimeMs = inclusiveSamples * profileIntervalMs;
        double exclusiveTimeMs = exclusiveSamples * profileIntervalMs;
        double inclusivePercent = totalSamples > 0 ? ( inclusiveSamples * 100.0 ) / totalSamples : 0;
        double exclusivePercent = totalSamples > 0 ? ( exclusiveSamples * 100.0 ) / totalSamples : 0;

        // Build display name
        string displayName;
        if ( node.FunctionKey.StartsWith ( "ROOT_" ) )
        {
            // Root node: show process name like VS does
            displayName = node.FunctionName ?? "Unknown Process";
        }
        else
        {
            displayName = node.GetDisplayName();
            FunctionStats? stats = null;
            if ( functionStats.ContainsKey ( node.FunctionKey ) )
            {
                stats = functionStats[node.FunctionKey];
            }

            if ( string.IsNullOrEmpty ( displayName ) && stats != null )
            {
                displayName = !string.IsNullOrEmpty ( stats.FunctionName )
                              ? $"{stats.FunctionName} [{Path.GetFileName(stats.ModuleName ?? "Unknown")}]"
                              : !string.IsNullOrEmpty ( stats.ModuleName )
                              ? $"[{Path.GetFileName(stats.ModuleName)}]"
                              : $"0x{node.Address:X16}";
            }

            // Format external calls
            if ( stats != null && !string.IsNullOrEmpty ( stats.ModuleName ) &&
                    !string.IsNullOrEmpty ( stats.FunctionName ) &&
                    stats.FunctionName.StartsWith ( "0x" ) )
            {
                displayName = $"[External Call] {Path.GetFileName(stats.ModuleName)}!{stats.FunctionName}";
            }
        }

        // Display node - Visual Studio style
        string connector;
        string childPrefix;

        if ( isRoot || node.FunctionKey.StartsWith ( "ROOT_" ) )
        {
            // Root node: use + prefix like VS
            connector = "+ ";
            childPrefix = "  ";
        }
        else
        {
            // Child nodes: use tree connectors
            connector = depth > 0 ? ( isLast ? "└─ " : "├─ " ) : "";
            childPrefix = prefix + ( depth > 0 ? ( isLast ? "   " : "│  " ) : "" );
        }

        // Format output like Visual Studio: Function Name | Total CPU | Self CPU | Total % | Self %
        // VS format: Total CPU [unit, %] and Self CPU [unit, %] in separate columns
        Console.WriteLine ( $"{prefix}{connector}{displayName,-70} {inclusiveTimeMs,-15:F2} {exclusiveTimeMs,-15:F2} {inclusivePercent,-12:F2}% {exclusivePercent,-12:F2}%" );

        // Sort children by Total CPU (Inclusive samples) and display
        var sortedChildren = node.Children.Values
                             .OrderByDescending ( c => c.InclusiveSamples )
                             .ToList();

        for ( int i = 0; i < sortedChildren.Count; i++ )
        {
            var child = sortedChildren[i];
            bool childIsLast = i == sortedChildren.Count - 1;
            DisplayCallTree ( child, functionStats, totalSamples, profileIntervalMs, childPrefix, depth + 1, maxDepth, childIsLast, false );
        }
    }
}

class FunctionStats {
    public ulong Address { get; set; }
    public uint ProcessId { get; set; }
    public long ExclusiveSamples { get; set; }
    public long InclusiveSamples { get; set; }
    public string? FunctionName { get; set; }
    public string? ModuleName { get; set; }
}

// Call tree node for hierarchical display (like Visual Studio)
class CallTreeNode {
    public string FunctionKey { get; set; } = "";
    public ulong Address { get; set; }
    public string? FunctionName { get; set; }
    public string? ModuleName { get; set; }
    public long ExclusiveSamples { get; set; }
    public long InclusiveSamples { get; set; }
    public Dictionary<string, CallTreeNode> Children { get; set; } = new Dictionary<string, CallTreeNode>();
    public CallTreeNode? Parent { get; set; }

    public string GetDisplayName()
    {
        if ( !string.IsNullOrEmpty ( FunctionName ) )
        {
            return $"{FunctionName} [{Path.GetFileName(ModuleName ?? "Unknown")}]";
        }
        if ( !string.IsNullOrEmpty ( ModuleName ) )
        {
            return $"[{Path.GetFileName(ModuleName)}]";
        }
        return $"0x{Address:X16}";
    }
}

// Custom TextWriter that filters out verbose symbol loading messages
class SymbolFilterWriter : TextWriter {
    private readonly TextWriter _baseWriter;
    private readonly StringBuilder _buffer = new StringBuilder();

    public SymbolFilterWriter ( TextWriter baseWriter )
    {
        _baseWriter = baseWriter;
    }

    public override Encoding Encoding => _baseWriter.Encoding;

    public override void Write ( char value )
    {
        _buffer.Append ( value );

        // Check if we have a complete line
        if ( value == '\n' )
        {
            FlushLine();
        }
    }

    public override void Write ( string? value )
    {
        if ( value == null )
        {
            return;
        }

        _buffer.Append ( value );

        // Check if we have a complete line
        if ( value.Contains ( '\n' ) )
        {
            FlushLine();
        }
    }

    private void FlushLine()
    {
        string line = _buffer.ToString();
        _buffer.Clear();

        // Filter out verbose symbol messages
        if ( line.Contains ( "Symbols loaded for" ) ||
                line.Contains ( "Symbols failed to load for" ) ||
                line.Contains ( "Skipping reanalysis" ) ||
                line.Contains ( "Failed to find symbol file" ) ||
                line.Trim().Length == 0 )
        {
            // Suppress these messages
            return;
        }

        // Write important messages
        _baseWriter.Write ( line );
    }

    public override void Flush()
    {
        if ( _buffer.Length > 0 )
        {
            FlushLine();
        }
        _baseWriter.Flush();
    }

    protected override void Dispose ( bool disposing )
    {
        Flush();
        if ( disposing )
        {
            _buffer.Clear();
        }
        base.Dispose ( disposing );
    }
}
