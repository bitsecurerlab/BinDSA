import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class CallSiteNode extends DSNode implements Comparable{
	private ArrayList<Address> callPath;
	private String tokens;
	private HashSet<Address> resolvedAddr;
	private boolean resolved;
	public boolean isIndirect;
	public boolean isGlobalAddr;
	public int numIndirectCall;
	private String funcName;
	private HashSet<Function> funcArgInSCC;

	public CallSiteNode() {
		this.members = new HashMap<Integer, Cell>();
		this.callPath = new ArrayList<Address>();
		this.resolvedAddr = new HashSet<Address>();
		this.setFuncArgInSCC(new HashSet<Function>());
		this.resolved = false;
		this.isIndirect = false;
		this.isGlobalAddr = false;
		this.numIndirectCall = 0;
	}

//	public boolean getResolvedAddr() {
//		HashSet<Address> remainedAddr = new HashSet<Address>(this.members.get(1).getPossiblePointers());
//		remainedAddr.removeAll(resolvedAddr);
////		return remainedAddr.size() == 0;
//		for (Address addr : remainedAddr) {
//			
//		}
//	}

	public void addResolved(Address b) {
		this.resolvedAddr.add(b);
	}

	public boolean getResolved() {
		return resolved;
	}

	public void setResolved(boolean b) {
		resolved = b;
	}

	public CallSiteNode(Cell returnCell, Cell func, ArrayList<Cell> args, Address loc, Graph newg) {
		this.members = new HashMap<Integer, Cell>();
		this.members.put(0, returnCell);
		if (returnCell != null)
			returnCell.addInCallSite(new Pair<CallSiteNode, String>(this, "ret"));
		this.members.put(1, func);
		this.loc = loc;
		func.addInCallSite(new Pair<CallSiteNode, String>(this, "func"));
		for (int i = 0; i < args.size(); i++) {
			this.members.put(i + 2, args.get(i));
			args.get(i).addInCallSite(new Pair<CallSiteNode, String>(this, String.valueOf(i + 1)));
		}
		this.setGraph(newg);
		this.callPath = new ArrayList<Address>();
		callPath.add(loc);
		this.resolvedAddr = new HashSet<Address>();
		this.resolved = false;
		this.isIndirect = false;
		this.isGlobalAddr = false;
		this.numIndirectCall = 0;
		this.funcName = newg.getF().getName();
		this.setFuncArgInSCC(new HashSet<Function>());
	}

	public void setTokens(String t) {
		tokens = t;
	}

	public String getTokens() {
		return tokens;
	}

	public void update(Cell returnCell, Cell func, ArrayList<Cell> args) {
		if (this.members.get(0) != returnCell) {
			this.members.put(0, returnCell);
			if (returnCell != null)
				returnCell.addInCallSite(new Pair<CallSiteNode, String>(this, "ret"));
		}

		if (this.members.get(1) != func) {
			this.members.put(1, func);
			func.addInCallSite(new Pair<CallSiteNode, String>(this, "func"));
		}

		for (int i = 0; i < args.size(); i++) {
			if (this.members.get(i + 2) == args.get(i))
				continue;
			this.members.put(i + 2, args.get(i));
			args.get(i).addInCallSite(new Pair<CallSiteNode, String>(this, String.valueOf(i + 1)));
		}
	}

	public Cell getReturn() {
		return this.members.get(0);
	}

	public Cell getFunc() {
		return this.members.get(1);
	}

	public Cell getArgI(int i) {
		return this.members.get(i + 2);
	}

	public ArrayList<Cell> getAllArgs() {
		ArrayList<Cell> ret = new ArrayList<Cell>();
		int i = 2;
		while (this.members.containsKey(i)) {
			ret.add(this.members.get(i));
			i++;
		}
		return ret;
	}

	public void setMember(int i, Cell c) {
		this.members.put(i, c);
	}

	public CallSiteNode deepCopy(Map<DSNode, DSNode> isomorphism, Graph newg, CallSiteNode cs) {
		CallSiteNode newCS = (CallSiteNode) isomorphism.get(this);
		if (newCS != null)
			return newCS;

		ArrayList<Address> newCallPath = new ArrayList<Address>();
		if (cs != null)
			newCallPath.addAll(cs.callPath);
		newCallPath.addAll(this.callPath);

//		if (cs.numIndirectCall + this.numIndirectCall > 1)
//			return null;

		newCS = new CallSiteNode();
		isomorphism.put(this, newCS);
		newCS.setGraph(newg);

		newCS.loc = this.loc;
		newCS.funcName = this.funcName;
		newCS.callPath = new ArrayList<Address>();
		newCS.callPath.addAll(newCallPath);

		newCS.numIndirectCall = this.numIndirectCall;
		if (cs != null)
			newCS.numIndirectCall += cs.numIndirectCall;

		newCS.tokens = tokens;
		newCS.resolved = this.resolved;
		newCS.resolvedAddr.addAll(this.resolvedAddr);
		newCS.isIndirect = isIndirect;
		DebugUtil.print("Added CS " + newCS);
		for (int i : this.members.keySet()) {
			Cell copiedCell = null;
			Cell thisCell = this.members.get(i);
			if (thisCell != null) {
				DSNode thisParent = thisCell.getParent();
				if (thisParent != null) {
					DSNode copiedParent = thisParent.deepCopy(isomorphism, newg, cs, true);
					copiedCell = copiedParent.get(thisCell.getFieldOffset());
					if (copiedParent.isGlobal()) {
						// if is global, this relation is not added in DSNode.deepCopy
						String s;
						if (i == 0)
							s = "ret";
						else if (i == 1)
							s = "func";
						else
							s = String.valueOf(i + 1);
						copiedCell.addInCallSite(new Pair<CallSiteNode, String>(newCS, s));
					}
				}
			}
			newCS.members.put(i, copiedCell);
		}
		newCS = newg.addCallNodesToTmp(newCS.getLoc(), newCS);
		return newCS;
	}

	public String toString() {
		String s = "Node@";
		for (Address f : this.callPath)
			s += f.toString() + "@";
		s += funcName + "@";
		s += tokens;
//		s += members.toString();
		return s;
	}

	public String toDetailedString() {
		String s = "Node@";
		for (Address f : this.callPath)
			s += f.toString() + "@";
		s += funcName + "@";
		s += tokens + "\n {";
		if (this.getReturn() != null) {
			s += "Return: " + "\n";
			s += this.getReturn().toString() + "\n";
		}

		int i = 2;
		while (this.members.containsKey(i)) {
			s += "Arg" + String.valueOf(i - 1) + ": " + "\n";
			s += this.members.get(i).toString() + "\n";
			i++;
		}
		return s;
	}

	public Graph getGraph() {
		return this.g;
	}

	public Address getLoc() {
		return this.loc;
	}

	public ArrayList<Address> getCallPath() {
		return this.callPath;
	}

	public HashSet<Function> getFuncArgInSCC() {
		return funcArgInSCC;
	}

	public void setFuncArgInSCC(HashSet<Function> funcArgInSCC) {
		this.funcArgInSCC = funcArgInSCC;
	}

	public void addFuncArgInSCC(Function funcArgInSCC) {
		this.funcArgInSCC.add(funcArgInSCC);
	}
	
	@Override
	public int compareTo(Object o) {
		CallSiteNode other = (CallSiteNode) o;
		Long addr1 = this.getLoc().getOffset();
		Long addr2 = other.getLoc().getOffset();
		return addr1.compareTo(addr2);  
	}

}

