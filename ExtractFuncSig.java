//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;

import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ExtractFuncSig extends GhidraScript {

	public final void createFunctionFromDefinition(Address funcAddr, FunctionDefinition defenition, String name)
			throws InvalidInputException, DuplicateNameException {

		ArrayList<ParameterImpl> parametrs = new ArrayList<ParameterImpl>();
		ParameterDefinition[] parametrDefenitions = defenition.getArguments();

		for (ParameterDefinition parameterDefinition : parametrDefenitions) {
			parametrs.add(new ParameterImpl(parameterDefinition.getName(), parameterDefinition.getDataType(),
					getCurrentProgram()));
		}

		if (name == null) {
			name = defenition.getName();
		}

		Function func = getFunctionAt(funcAddr);
		if (func == null) {
			func = this.createFunction(funcAddr, name);
			if (func == null) {
				Msg.error(this, "Can't create function!");
				Msg.error(this, funcAddr.toString());
				return;
			}
		} else {
			func.setName(name, SourceType.ANALYSIS);
		}

		ReturnParameterImpl returnValue = new ReturnParameterImpl(defenition.getReturnType(), getCurrentProgram());

		func.updateFunction(null, returnValue, parametrs, FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, false,
				SourceType.ANALYSIS);
	}
	
	@Override
	protected void run() throws Exception {
		ApplyFunctionDataTypesCmd cmd = new ApplyFunctionDataTypesCmd(currentProgram.getDataTypeManager().getRootCategory(), null, SourceType.USER_DEFINED, true, false);
		cmd.applyTo(currentProgram);
		
		
		// extract function signature
		FunctionIterator functionManager = this.currentProgram.getFunctionManager().getFunctions(true);
		String outpath = System.getProperty("user.home") + "/spec2006x86/O2_out/" + this.currentProgram.getName() + "_funcs.txt";
		BufferedWriter out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(outpath)));
		for (Function func : functionManager) {
			String s = func.getName() + " " + Long.toHexString(func.getEntryPoint().getOffset()) + " ";
			if (func.hasVarArgs())
				s += "True ";
			else
				s += "False ";
			for (int i = 0 ; i < func.getParameterCount(); i++) {
				Parameter p = func.getParameter(i);
				s += String.valueOf(p.getDataType().getLength()) + " ";
			}
			out.write(s);
			out.newLine();	
		}
		out.close();
		
		// extract global var size
		SymbolTable symtab = this.currentProgram.getSymbolTable();
		MemoryBlock mem = currentProgram.getMemory().getBlock(".data");
		MemoryBlock romem = currentProgram.getMemory().getBlock(".rodata");
		MemoryBlock bssmem = currentProgram.getMemory().getBlock(".bss");
        SymbolIterator symiter = symtab.getAllSymbols(true);
        String globalpath = System.getProperty("user.home") + "/spec2006x86/O2_out/" + this.currentProgram.getName() + "_globals.txt";
        out = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(globalpath)));
        while (symiter.hasNext() && !this.monitor.isCancelled()) {
        	Symbol sym = symiter.next();
            Address addr = sym.getAddress();
            if (!mem.contains(addr) && !bssmem.contains(addr) && !romem.contains(addr))
                continue;
            Data data = this.currentProgram.getListing().getDataAt(addr);
            if (data == null)
                continue;
            String s = sym.getName() + " " + Long.toHexString(addr.getOffset()) + " " + String.valueOf(data.getBytes().length);
            out.write(s);
			out.newLine();	
        }
        out.close();
	}
}
