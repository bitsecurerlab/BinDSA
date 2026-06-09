import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;

public class Graph {
	private HashMap<VarnodeAST, Cell> Ev = new HashMap<VarnodeAST, Cell>();
	private HashMap<Varnode, Pair<Varnode, Integer>> varRelation = new HashMap<Varnode, Pair<Varnode, Integer>>();
	private HashMap<Address, CallSiteNode> callNodes = new HashMap<Address, CallSiteNode>();
	private HashMap<Address, HashSet<CallSiteNode>> callNodesTemp = new HashMap<Address, HashSet<CallSiteNode>>();
	private HashMap<PcodeOp, Cell> pcodeOutputCells = new HashMap<PcodeOp, Cell>();
	private ArrayList<Varnode> args = new ArrayList<Varnode>();
	private HashSet<Varnode> ret = new HashSet<Varnode>();
	public HashMap<Function, CallSiteNode> funcArgMap = new HashMap<Function, CallSiteNode>();
	public HashMap<Integer, Cell> stackObj = new HashMap<Integer, Cell>();
	private Function f;
	public boolean changed = false;
	public boolean resolvedNewCallSite = false;
	public boolean hasFuncPtr = false;
	public boolean hasIndirectCallee = false;
	public GlobalRegion globalRegion;
	public HashMap<Function, Graph> allLocalGraphs;
	private HashMap<PcodeOp, ArrayList<ClangToken>> mapping;
	private HashMap<String, Cell> calleeargs = new HashMap<String, Cell>();
	private HashMap<Integer, DSNode> stackObjPtr = new HashMap<Integer, DSNode>();
	public HashMap<Address, HashSet<Cell>> memAccessInstrMap;

	public HashMap<String, Cell> getCalleeargs() {
		return calleeargs;
	}

	public void setCalleeargs(HashMap<String, Cell> calleeargs) {
		this.calleeargs = calleeargs;
	}

	public void addArg(Varnode v, String argno) {
		Cell c = this.getCell(v);
		c.getParent().setArgNo(argno);
		c.getParent().setIsArg(true);
		args.add(v);
	}

	public HashMap<PcodeOp, ArrayList<ClangToken>> getMapping() {
		return mapping;
	}

	public void setMapping(HashMap<PcodeOp, ArrayList<ClangToken>> m) {
		mapping = m;
	}

	public void setPcodeOutputCell(PcodeOp op, Cell cell) {
		if (op != null && cell != null)
			pcodeOutputCells.put(op, cell);
	}

	public Cell getPcodeOutputCell(PcodeOp op) {
		return pcodeOutputCells.get(op);
	}

	public void addRet(Varnode v) {
		this.getCell(v);
		ret.add(v);
	}

	public Cell getReturnCell() {
		Cell merged = new Cell(new DSNode(), 0);
		for (Varnode v : ret) {
			Cell c = this.getCell(v);
			if (c == null || c.getParent() == null)
				continue;
			merged = c.merge(merged);
		}
		return merged;
	}

	public ArrayList<Cell> getArgCell() {
		ArrayList<Cell> cells = new ArrayList<Cell>();
		for (Varnode v : args) {
			cells.add(this.getCell(v));
		}
		return cells;
	}

	public Cell getArgCell(int i) {
		Varnode v = args.get(i);
		return this.getCell(v);
	}

	public HashMap<Address, CallSiteNode> getCallNodes() {
		return callNodes;
	}

	public CallSiteNode getCallNodes(Address addr) {
		return callNodes.get(addr);
	}

//	public CallSiteNode getCallNodes(Address addr) {
//		ArrayList<Address> addrlist = new ArrayList<Address>();
//		addrlist.add(addr);
//		return callNodes.get(addrlist.toString());
//	}

	public CallSiteNode addCallNodes(Address addr, CallSiteNode cn) {
		callNodes.put(addr, cn);
		return cn;
	}

	public CallSiteNode addCallNodesToTmp(Address addr, CallSiteNode cn) {
		if (!callNodesTemp.containsKey(addr))
			callNodesTemp.put(addr, new HashSet<CallSiteNode>());
//			callNodesTemp.get(addr).add(cn);
		callNodesTemp.get(addr).add(cn);
		return cn;
	}

	public HashSet<CallSiteNode> getTmpCallNodes(Address addr) {
		return callNodesTemp.get(addr);
	}

//	public void addCallNodes(Address addr, CallSiteNode cn) {
//		ArrayList<Address> addrlist = new ArrayList<Address>();
//		addrlist.add(addr);
//		callNodes.put(addrlist.toString(), cn);
//	}

	public Pair<Varnode, Integer> getRelation(Varnode var) {
		return this.varRelation.get(var);
	}

	public void setRelation(Varnode var, Pair<Varnode, Integer> rel) {
		if (this.varRelation.containsKey(var)) {
			Pair<Varnode, Integer> existingPair = this.varRelation.get(var);
			if (existingPair.getK() == rel.getK() && existingPair.getV().intValue() == rel.getV().intValue())
				return;
			if (existingPair.getK() != rel.getK() || existingPair.getV().intValue() != rel.getV().intValue()) {
				Ev.remove(var);
			}
		}
		this.varRelation.put(var, rel);
		this.changed = true;
		this.getCell(rel.getK());
		this.getCell(var);
	}

	public Cell getOrCreateFromStack(long offset, Address addr) {
		if (stackObj.containsKey((int) offset))
			return stackObj.get((int) offset);

		DSNode nnode = new DSNode(addr, this);
		nnode.setOnStack(true);
		Cell ncell = new Cell(nnode, 0);
		stackObj.put((int) offset, ncell);
		ncell.addStackLocs(f, (int) offset);
		return ncell;
	}
	

	public Cell getCell(Varnode var) {
		if (var == null)
			return null;

		// for variables such as A_0035fdd8, it directly represents the content of the
		// global variable
		// only merge with the global if stores pointer to it
		Cell globalCell = null;
		Cell stackCell = null;
		if (var.getAddress().isMemoryAddress()) {
			globalCell = globalRegion.getGlobalMem(var.getAddress());
		} else if (var.getAddress().isStackAddress()) { // && var.getAddress().getOffset() < 0) {
			long offset = var.getAddress().getOffset();
			Cell newCell = getOrCreateFromStack(offset, var.getPCAddress());
			stackCell = newCell;
		}
		if (!varRelation.containsKey(var) && globalCell != null) {
			Ev.put((VarnodeAST) var, globalCell);
			globalCell.addInEvEdges(var);
			return globalCell;
		}

		Cell oldCell = null;
		if (Ev.containsKey(var) && Ev.get(var) != null && Ev.get(var).getParent() != null)
			oldCell = Ev.get(var);
		if (varRelation.containsKey(var)) {
			// get Cell according to the relation with existing nodes
			Pair<Varnode, Integer> vr = varRelation.get(var);
			Varnode varBase = vr.getK();
			int offset = vr.getV();
			Cell baseCell;
			DSNode baseNode;

			String varBaseStr = varBase.toString(this.getCurrentProgram().getLanguage());

			if (Ev.containsKey(varBase) && Ev.get(varBase) != null && Ev.get(varBase).getParent() != null) {
				baseCell = Ev.get(varBase);
				baseNode = baseCell.getParent();
				int baseField = baseCell.getFieldOffset();
				// if varBase is RSP, we will create a new DSNode for var, we don't use the
				// DSNode for varBase
				if (varBaseStr.equals("RSP") || varBaseStr.equals("ESP")) {
					// TODO: need to check whether new node is necessary
					DSNode dsNode = new DSNode(var.getPCAddress(), this);
					Cell newCell = new Cell(dsNode, 0);
					dsNode.addLocations(new Pair<String, Long>("S_" + f.getEntryPoint().toString(), (long) offset));

					if (offset < 0) {
						Cell stackobj = getOrCreateFromStack(offset, var.getPCAddress());
						boolean isTainted = false;
						for (Cell stackPtr : stackobj.getInEdges())
							isTainted |= stackPtr.isTainted();
						newCell.setTainted(isTainted);
						newCell.setOutEdges(stackobj);
						newCell.setRSPOffset(this.getF(), offset);
					}
					Ev.put((VarnodeAST) var, newCell);
				} else if (baseNode.isCollapsed() || baseField == IndirectCallTargetResolving.TOP
						|| offset == IndirectCallTargetResolving.TOP) {
					Ev.put((VarnodeAST) var, baseNode.getOrCreateCell(0));
				} else if (baseNode.isArray() && baseNode.getPossibleStride() != null)
					Ev.put((VarnodeAST) var,
							baseNode.getOrCreateCell(IndirectCallTargetResolving.mod((offset + baseField), baseNode.getPossibleStride())));
				else
					Ev.put((VarnodeAST) var, baseNode.getOrCreateCell(offset + baseField));

			} else if (varBase.getAddress().isMemoryAddress() && globalRegion.findPtr(varBase.getAddress()) != null) {
				baseCell = globalRegion.getGlobalMem(varBase.getAddress());
				baseNode = baseCell.getParent();
				int baseField = baseCell.getFieldOffset();
				if (baseNode.isCollapsed() || baseField == IndirectCallTargetResolving.TOP
						|| offset == IndirectCallTargetResolving.TOP) {
					Ev.put((VarnodeAST) var, baseNode.getOrCreateCell(0));
				} else if (baseNode.isArray() && baseNode.getPossibleStride() != null)
					Ev.put((VarnodeAST) var,
							baseNode.getOrCreateCell(IndirectCallTargetResolving.mod((offset + baseField), baseNode.getPossibleStride())));
				else
					Ev.put((VarnodeAST) var, baseNode.getOrCreateCell(offset + baseField));
			} else {
				// need to create new node for baseNode
				baseNode = new DSNode(varBase.getPCAddress(), this);
				if (varBase.isConstant())
					baseNode.addConstants((int) varBase.getOffset());
				baseCell = new Cell(baseNode, 0);
				Ev.put((VarnodeAST) varBase, baseCell);

				if (varBaseStr.equals("RSP") || varBaseStr.equals("ESP")) {
					DSNode dsNode = new DSNode(var.getPCAddress(), this);
					Cell newCell = new Cell(dsNode, 0);
					dsNode.addLocations(new Pair<String, Long>("S_" + f.getEntryPoint().toString(), (long) offset));
					if (offset < 0) {
						Cell stackobj = getOrCreateFromStack(offset, var.getPCAddress());
						newCell.setOutEdges(stackobj);
						newCell.setRSPOffset(this.getF(), offset);
					}
					Ev.put((VarnodeAST) var, newCell);
				}

				else if (offset == IndirectCallTargetResolving.TOP) {
					Ev.put((VarnodeAST) var, baseCell);
				} else
					Ev.put((VarnodeAST) var, new Cell(baseNode, offset));
			}
			if (!baseNode.isCollapsed()) {
				if (baseNode.isArray() && baseNode.getPossibleStride() != null)
					offset = IndirectCallTargetResolving.mod(offset, baseNode.getPossibleStride());
				HashSet<Address> keySet = new HashSet<Address>(baseCell.getPossiblePointers());
				for (Address ptr : keySet) {
					try {
						Ev.get(var).addPointersWithLoading(ptr.add(offset));
					} catch (Exception e) {
						baseCell.getPossiblePointers().remove(ptr);
					}
				}
			}
		} else if (oldCell == null){
			// create new nodes on its own
			DSNode dsNode = new DSNode(var.getPCAddress(), this);
			Cell newCell = new Cell(dsNode, 0);
			if (var.isConstant()) {
				// the constant could be a pointer
				try {
					Address memAddr = this.getCurrentProgram().getAddressFactory()
						.getAddress(this.getCurrentProgram().getAddressFactory().getAddressSpace("ram").getSpaceID(), var.getOffset());
					Function fp = this.getCurrentProgram().getFunctionManager().getFunctionAt(memAddr);
					if (fp != null || globalRegion.findPtr(memAddr) != null)
						newCell.addPointersWithLoading(memAddr);
					else
						dsNode.addConstants((int) var.getOffset());
				} catch (Exception e) {
					dsNode.addConstants((int) var.getOffset());
				}
			}
			String varStr = var.toString(this.getCurrentProgram().getLanguage());
			if (varStr.equals("RSP") || varStr.equals("ESP")) {
				dsNode.addLocations(new Pair<String, Long>("S_" + f.getEntryPoint().toString(), (long) 0));
				newCell.setRSPOffset(this.getF(), 0);
			}
			Ev.put((VarnodeAST) var, newCell);
		}
		
		if (globalCell != null) {
			globalCell.merge(Ev.get(var));
			Ev.put((VarnodeAST) var, globalCell);
		}
		Ev.get(var).addInEvEdges(var);
		if (oldCell == null) {
			this.changed = true;
			return Ev.get(var);
		}

		Cell newCell = Ev.get(var);
		if (newCell != oldCell) {
			this.changed = true;
		}
		return Ev.get(var);
	}

	public Cell getEv(Varnode var) {
		return this.Ev.get(var);
	}

	public HashMap<VarnodeAST, Cell> getEv() {
		return this.Ev;
	}

	public void setEv(Varnode var, Cell c) {
		if (c == null) {
			this.Ev.remove(var);
			return;
		}
		c.addInEvEdges(var);
		this.Ev.put((VarnodeAST) var, c);
	}

	public Function getF() {
		return f;
	}

	public void setF(Function f) {
		this.f = f;
	}

	public Program getCurrentProgram() {
		return this.f.getProgram();
	}

	public void setAllGlobals(GlobalRegion map) {
		this.globalRegion = map;
	}

	public GlobalRegion getAllGlobals() {
		return this.globalRegion;
	}

	public void setAllLocalGraphs(HashMap<Function, Graph> allLocalGraphs) {
		this.allLocalGraphs = allLocalGraphs;
	}

	public HashMap<Function, Graph> getAllLocalGraphs() {
		return this.allLocalGraphs;
	}

	public void cloneGraphIntoThis(Graph callee, Function calleef, CallSiteNode cs, Map<DSNode, DSNode> isomorphism) {
		System.out.println(
				"merge " + calleef.toString() + " to " + this.getF().toString() + " @" + cs.getLoc().toString());
		DebugUtil
				.print("merge " + calleef.toString() + " to " + this.getF().toString() + " @" + cs.getLoc().toString());

		ArrayList<Cell> argFormal = null;
		Cell retCell = null;

		// if callee is in the same SCC as this (other callers in SCC have merged
		// callee), get args from funcArgMap
		// if callee is in a SCC, the getArgCell and getReturnCell no longer stores its
		// args, get args from funcArgMap
		if (this.funcArgMap.containsKey(calleef) && this.funcArgMap.get(calleef) != null && this == callee) {
			CallSiteNode calleearg = this.funcArgMap.get(calleef);
			argFormal = calleearg.getAllArgs();
			retCell = calleearg.getReturn();
		} else if (callee.funcArgMap.containsKey(calleef) && callee.funcArgMap.get(calleef) != null) {
			CallSiteNode calleearg = callee.funcArgMap.get(calleef);
			argFormal = calleearg.getAllArgs();
			retCell = calleearg.getReturn();
		} else {
			argFormal = callee.getArgCell();
			retCell = callee.getReturnCell();
		}

		// check arity and types
		int actualsize = 0;
		if (cs.getMembers().containsKey(0))
			actualsize = -1;
		if (argFormal.size() > actualsize + cs.getMembers().size() - 1) {
			cs.getFunc().possiblePointers.remove(callee.getF().getEntryPoint());
			return;
		}
		for (int i = 0; i < argFormal.size(); i++) {
			Cell formalArgCell = argFormal.get(i);
			Cell actualArgCell = cs.getArgI(i);
			if (cs.isIndirect && hasTypeConflict(formalArgCell, actualArgCell)) {
				cs.getFunc().possiblePointers.remove(callee.getF().getEntryPoint());
				return;
			}
		}

		// copy formal args
		for (int i = 0; i < argFormal.size(); i++) {
			Cell arg = argFormal.get(i);
			if (arg == null)
				continue;
			DSNode argNode = arg.getParent();
			if (argNode == null)
				continue;
			int offset = arg.getFieldOffset();
			Cell formalArgCell;
			if (this != callee) {
				DSNode copiedNode = argNode.deepCopy(isomorphism, this, cs, true);
				formalArgCell = copiedNode.get(offset);
			} else
				formalArgCell = arg;
			if (formalArgCell == null)
				continue;
			this.calleeargs.put("CALLEEARG" + String.valueOf(i), formalArgCell);
			formalArgCell.addCalleeArgLabel("CALLEEARG" + String.valueOf(i));
		}

		// copy return cells
		if (retCell != null) {
			DSNode retNode = retCell.getParent();
			int offset = retCell.getFieldOffset();
			if (retNode != null && (retNode.getOnHeap() || retNode.getIsArg() || retNode.getMembers().size() > 1)) {
				Cell formalArgCell;
				if (this != callee) {
					DSNode copiedRetNode = retNode.deepCopy(isomorphism, this, cs, true);
					formalArgCell = copiedRetNode.get(offset);
				} else
					formalArgCell = retCell;
				if (formalArgCell != null) {
					this.calleeargs.put("CALLEERET", formalArgCell);
					formalArgCell.addCalleeArgLabel("CALLEERET");
				}
			}
		}

		// TODO: divide the stack

		// merge args and ret
		HashSet<String> keySet = new HashSet<String>();
		keySet.addAll(this.calleeargs.keySet());
		for (String key : keySet) {
			Cell formalArgCell = this.calleeargs.get(key);
			Cell actualArgCell = null;
			if (key.equals("CALLEERET"))
				actualArgCell = cs.getReturn();
			else {
				String argno = key.substring(9, key.length());
				int i = Integer.valueOf(argno);
				actualArgCell = cs.getArgI(i);
			}
			if (actualArgCell == null || formalArgCell == null || formalArgCell.getParent() == null)
				continue;
			if (actualArgCell.isRSP(this.f)) {
				int stackoffset = actualArgCell.getRSPOffset(this.f);
				int objsize = formalArgCell.getParent().getSize() - formalArgCell.getParent().getMinOffset();
				this.mergeStackObj(actualArgCell, stackoffset, objsize);
			}
			if ((cs.getLoc().toString().contains("114b0") || cs.getLoc().toString().contains("114ca")) && key.equals("CALLEEARG1")) {
				System.out.println(actualArgCell.toString());
				System.out.println(formalArgCell.toString());
			}
			formalArgCell.merge(actualArgCell);
		}

		for (Address addr : this.callNodesTemp.keySet()) {
			Iterator<CallSiteNode> iter = this.callNodesTemp.get(addr).iterator();
			if (!callNodes.containsKey(addr)) {
				callNodes.put(addr, iter.next());
			}
			CallSiteNode exist = callNodes.get(addr);
			while (iter.hasNext()) {
				CallSiteNode cn = iter.next();
				mergeCallSite(exist, cn);
			}
			this.callNodesTemp.get(addr).clear();
		}
		this.callNodesTemp.clear();

		if (callee.resolvedNewCallSite) {
			this.resolvedNewCallSite = true;
			callee.resolvedNewCallSite = false;
		}
		if (callee.hasFuncPtr)
			this.hasFuncPtr = true;
		if (callee.hasIndirectCallee)
			this.hasIndirectCallee = true;

		for (String key : this.calleeargs.keySet()) {
			Cell formalArgCell = this.calleeargs.get(key);
			formalArgCell.clearCalleeArgLabel();
		}
		this.calleeargs.clear();
		DebugUtil.print("Used memory "
				+ String.valueOf(Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()));
		DebugUtil.print("Free memory " + String.valueOf(Runtime.getRuntime().freeMemory()));
	}

	// keep exist, clear cn
	public void mergeCallSite(CallSiteNode exist, CallSiteNode cn) {
		if (exist.getMembers().size() != cn.getMembers().size()) {
			return;
		}
		if (exist.g != cn.g)
			return;
		if (exist == cn)
			return;
		DebugUtil.print("Merge CallSite " + cn.toString() + " to " + exist.toString());
		Set<Integer> size = exist.getMembers().keySet();
		int max = Collections.max(size);
		for (int i = 0; i < max; i++) {
			// merge newCell to existCell
			Cell newCell = cn.getMembers().get(i);
			Cell existCell = exist.getMembers().get(i);
			if (newCell != null) {
				HashSet<Pair<CallSiteNode, String>> csNodePairs = new HashSet<Pair<CallSiteNode, String>>();
				csNodePairs.addAll(newCell.getInCallSite());
				// remove the callsitenode in newCell that relates to cn, because we don't want
				// to copy that
				for (Pair<CallSiteNode, String> csNodePair : csNodePairs) {
					if (csNodePair.getK() == cn) {
						String v = csNodePair.getV();
						newCell.getInCallSite().remove(csNodePair);

						if (existCell == null) {
							exist.getMembers().put(i, newCell);
							csNodePair = new Pair<CallSiteNode, String>(exist, v);
							newCell.addInCallSite(csNodePair); // newCell is now in exist
						}
					}
				}
			}
			if (existCell != null)
				existCell.merge(newCell);
		}
		cn.getMembers().clear();
		for (Function func : cn.getFuncArgInSCC()) {
			cn.g.funcArgMap.put(func, exist);
			exist.addFuncArgInSCC(func);
		}
	}

	public static boolean hasTypeConflict(Cell formalArgCell, Cell actualArgCell) {
		if (formalArgCell == null || actualArgCell == null)
			return false;
		int field1 = formalArgCell.getFieldOffset();
		int field2 = actualArgCell.getFieldOffset();
		DSNode parent1 = formalArgCell.getParent();
		DSNode parent2 = actualArgCell.getParent();
		if (parent1 == null || parent2 == null)
			return false;
		if (parent1.getIsConstant() && parent2.hasOut())
			return true;
		else if (parent2.getIsConstant() && parent1.hasOut())
			return true;
		else if (parent1.getIsConstant() && parent2.getIsConstant())
			return false;
		else if (parent1.isCharPointer() && !parent2.isCharPointer() && parent2.hasOut())
			return true;
		else if (parent2.isCharPointer() && !parent1.isCharPointer() && parent1.hasOut())
			return true;

		Set<Integer> keyset1 = new HashSet<Integer>(parent1.members.keySet());
		Set<Integer> keyset2 = new HashSet<Integer>(parent2.members.keySet());
		if (keyset1.size() == 0 || keyset2.size() == 0)
			return false;
		if (parent1.isCollapsed() || parent2.isCollapsed()) {
			field1 = Collections.min(keyset1);
			field2 = Collections.min(keyset2);
		}
		int offset = field1 - field2;
		keyset2.clear();
		for (int key : parent2.members.keySet()) {
			keyset2.add(key + offset);
		}
		keyset1.retainAll(keyset2);
		for (int key : keyset1) {
			Boolean type1 = parent1.getMemberType().get(key);
			Boolean type2 = parent2.getMemberType().get(key - offset);
			if (type1 == null || type2 == null)
				continue;
			if (type1 && !type2)
				return true;
			if (!type1 && type2)
				return true;
		}

		return false;
	}

	private void mergeStackObj(Cell actualArgCell, int stackoffset, int objsize) {
		ArrayList<Integer> keyset = new ArrayList<Integer>();
		keyset.addAll(stackObj.keySet());
		Collections.sort(keyset);
		assert (actualArgCell.getOutEdges() == stackObj.get(stackoffset));
		DSNode curObjPtr = actualArgCell.getParent();
		if (curObjPtr == null)
			return;
		int originCellOffset = actualArgCell.getFieldOffset();
		int existSize = curObjPtr.getSize(); // we don't merge if it's been merged before
		for (int i : keyset) {
			if (i > existSize - originCellOffset + stackoffset && i < stackoffset + objsize) {
				Cell newCell = curObjPtr.getOrCreateCell(i - stackoffset + originCellOffset);
				newCell.addOutEdges(stackObj.get(i));
//				stackObj.remove(i);
			}
		}
		this.addStackObjPtr(stackoffset, curObjPtr);
	}

	public HashMap<Integer, DSNode> getStackObjPtr() {
		return stackObjPtr;
	}

	public void addStackObjPtr(int offset, DSNode stackObj) {
		DSNode oldObj = this.stackObjPtr.get(offset);
		if (oldObj != null) {
			oldObj.getStackObjPtrOffset().remove(offset);
		}
		this.stackObjPtr.put(offset, stackObj);
		stackObj.setStackObjPtrOffset(offset);
	}

	public void setMemAccessInstrMap(HashMap<Address, HashSet<Cell>> map) {
		memAccessInstrMap = map;
	}

	public HashSet<Cell> getMemAccessInstrMap(Address addr) {
		return memAccessInstrMap.get(addr);
	}

	public void addMemAccessInstrMap(Address addr, Cell cell) {
		if (!memAccessInstrMap.containsKey(addr))
			memAccessInstrMap.put(addr, new HashSet<Cell>());
		this.memAccessInstrMap.get(addr).add(cell);
	}

}
