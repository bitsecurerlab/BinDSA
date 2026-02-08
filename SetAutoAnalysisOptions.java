//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.Map;

import ghidra.app.script.GhidraScript;

public class SetAutoAnalysisOptions extends GhidraScript {

	private static final String STACK = "Stack";
	private static final String X86_CONST_REF_ANALYZER = "x86 Constant Reference Analyzer";
	private static final String WINDOWS_X86_PE_EXCEPTION_HANDLING = "Windows x86 PE Exception Handling";
	private static final String PDB_UNIVERSAL = "PDB Universal";
	private static final String NON_RETURN_FUNCTIONS_D = "Non-Returning Functions - Discovered";
	private static final String DECOMPILER_SWITCH_ANALYSIS = "Decompiler Switch Analysis";
	private static final String DEMANGLER_MS_ANALYZER = "Demangler Microsoft";
	private static final String DEMANGLER_GNU_ANALYZER = "Demangler GNU";
	private static final String DECOMPILER_PARAMETER_ID = "Decompiler Parameter ID";
	@Override
	protected void run() throws Exception {
		//TODO: Add script code here
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (options.containsKey(DECOMPILER_PARAMETER_ID)) {
			setAnalysisOption(currentProgram, DECOMPILER_PARAMETER_ID, "true");
		}
	}
}
