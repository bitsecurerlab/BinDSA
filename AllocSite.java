import java.util.ArrayList;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;

public class AllocSite {
	private Varnode definedVar;
	private ArrayList<Function> callpath;

	public AllocSite() {
		this.callpath = new ArrayList<Function>();
	}

	public AllocSite(Varnode v, Function f) {
		this.definedVar = v;
		this.callpath = new ArrayList<Function>();
		callpath.add(f);
	}

	public Varnode getDefinedVar() {
		return definedVar;
	}

	public void setDefinedVar(Varnode definedVar) {
		this.definedVar = definedVar;
	}

	public ArrayList<Function> getCallpath() {
		return callpath;
	}

	public void addCallpath(Function f) {
		this.callpath.add(f);
	}

	public AllocSite deepcopy() {
		AllocSite as = new AllocSite();
		as.setDefinedVar(this.definedVar);
		for (Function f : this.callpath)
			as.addCallpath(f);
		return as;
	}
}


