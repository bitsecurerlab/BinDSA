## Project Overview

BinDSA is a binary data structure analysis framework built as a Ghidra script collection. The project implements Data Structure Analysis (DSA) algorithms for binary reverse engineering and program analysis.

## Core Architecture

### Main Components

1. **IndirectCallTargetResolving.java** - The primary entry point script that performs indirect call target resolution using DSA
2. **Graph.java** - Core data structure representing function-level graphs with cells, nodes, and call sites
3. **DSNode.java** - Represents data structure nodes in the analysis graph
4. **Cell.java** - Represents memory cells that can point to DSNodes
5. **CallSiteNode.java** - Represents function call sites in the analysis
6. **GlobalRegion.java** - Manages global memory regions and data structures

### Key Data Structures

- **Graph**: Contains `HashMap<VarnodeAST, Cell>` for variable-to-cell mapping and manages function-level analysis
- **DSNode**: Represents heap/stack objects with member tracking, type information, and allocation sites
- **Cell**: Links variables to DSNodes and tracks pointer relationships
- **CallSiteNode**: Models function calls with argument/return value tracking

### Analysis Flow

The DSA analysis works by:
1. Building graphs for each function containing cells and DSNodes
2. Resolving indirect call targets through bottom-up analysis
3. Resolving other points-to relationships through top-down analysis

## Running the Analysis

To execute the main analysis script in Ghidra:
1. Load your binary in Ghidra
2. Run the `IndirectCallTargetResolving.java` script from the Script Manager
3. The script will perform DSA and output results

## Dependencies

- **Ghidra API**: Full dependency on Ghidra framework for binary analysis
- **json-simple-1.1.1.jar**: JSON processing library included in the repository
- **Python helpers**: `DefineUndefinedFunctions.py` for preprocessing

## File Structure

- Core analysis classes: `Graph.java`, `DSNode.java`, `Cell.java`
- Main entry point: `IndirectCallTargetResolving.java`
- Utilities: `DebugUtil.java`, `Pair.java`, `AllocSite.java`
- Configuration: `SetAutoAnalysisOptions.java`
- Preprocessing: `DefineUndefinedFunctions.py`, `ExtractFuncSig.java`

## More
We've update the code to be compatible with Ghidra 12.1. To start, please see run_all.sh
However, there may still be some issues, and some data is missing. We are working on fixing it. Please stay tuned.