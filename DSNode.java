import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;

public class DSNode {
	private int size;
	private String name;
	protected HashMap<Integer, Cell> members;
	private HashMap<Integer, Integer> memberSize;
	private HashMap<Integer, Boolean> memberType; // false: constant, true: pointer, null: not sure
	private HashMap<Cell, HashSet<Cell>> subTypes;// Cell1 >= Cell2
	private HashMap<Cell, HashSet<Cell>> superTypes; // Cell1 <= Cell2
	private boolean isArray;
	private boolean hasStride;
	private boolean isGlobal;
	private boolean collapsed;
	private Integer possibleStride;
	private boolean onHeap;
	private boolean onStack;
	private boolean isArg;
	private int minkey;
	protected Address loc;
	protected Graph g;
	private String argNo;
	private HashSet<AllocSite> allocationSites;
	private ArrayList<Address> mergedWith;
	private Integer possibleConstant;
	private Pointer dtype;
	private boolean isConstant;
	private boolean isCharPointer;
	private HashSet<Integer> stackObjPtrOffset;
	private boolean isTainted;

	private HashSet<Pair<String, Long>> locations;

	public DSNode() {
		this.members = new HashMap<Integer, Cell>();
		this.memberSize = new HashMap<Integer, Integer>();
		this.setMemberType(new HashMap<Integer, Boolean>());
		this.subTypes = new HashMap<Cell, HashSet<Cell>>();
		this.superTypes = new HashMap<Cell, HashSet<Cell>>();
		this.isArray = false;
		this.hasStride = false;
		this.collapsed = false;
		this.allocationSites = new HashSet<AllocSite>();
		this.mergedWith = new ArrayList<Address>();
		this.stackObjPtrOffset = new HashSet<Integer>();
		this.possibleConstant = null;
		this.possibleStride = null;
		this.isConstant = false;
		this.setCharPointer(false);
		this.onHeap = false;
		this.onStack = false;
		this.isArg = false;
		this.minkey = 0;
		this.locations = new HashSet<Pair<String, Long>>();
	}

	public DSNode(Address loc, Graph g) {
		this.members = new HashMap<Integer, Cell>();
		this.memberSize = new HashMap<Integer, Integer>();
		this.setMemberType(new HashMap<Integer, Boolean>());
		this.subTypes = new HashMap<Cell, HashSet<Cell>>();
		this.stackObjPtrOffset = new HashSet<Integer>();
		this.isArray = false;
		this.hasStride = false;
		this.collapsed = false;
		this.allocationSites = new HashSet<AllocSite>();
		this.mergedWith = new ArrayList<Address>();
		this.mergedWith.add(loc);
		this.possibleConstant = null;
		this.possibleStride = null;
		this.isConstant = false;
		this.setCharPointer(false);
		this.onHeap = false;
		this.onStack = false;
		this.isArg = false;
		this.loc = loc;
		this.g = g;
		this.minkey = 0;
		this.locations = new HashSet<Pair<String, Long>>();
	}

	public DSNode(int size, Address loc, Graph g) {
		this.size = size;
		this.members = new HashMap<Integer, Cell>();
		this.memberSize = new HashMap<Integer, Integer>();
		this.setMemberType(new HashMap<Integer, Boolean>());
		this.subTypes = new HashMap<Cell, HashSet<Cell>>();
		this.superTypes = new HashMap<Cell, HashSet<Cell>>();
		this.stackObjPtrOffset = new HashSet<Integer>();
		this.isArray = false;
		this.hasStride = false;
		this.collapsed = false;
		this.allocationSites = new HashSet<AllocSite>();
		this.mergedWith = new ArrayList<Address>();
		this.mergedWith.add(loc);
		this.possibleConstant = null;
		this.possibleStride = null;
		this.isConstant = false;
		this.setCharPointer(false);
		this.onHeap = false;
		this.onStack = false;
		this.isArg = false;
		this.loc = loc;
		this.g = g;
		this.minkey = 0;
		this.locations = new HashSet<Pair<String, Long>>();
	}

	public boolean isOnStack() {
		return onStack;
	}

	public void setOnStack(boolean onStack) {
		this.onStack = onStack;
	}

	public void setIsConstant(boolean t) {
		this.isConstant = t;
		if (!t) {
			this.clearConstant();
		} else if (this.members.size() > 1){
			this.collapse(true);
		}
	}

	public Pointer getDataType(Program currentProgram) {
		if (this.dtype != null)
			return this.dtype;

		ProgramBasedDataTypeManager dm = currentProgram.getDataTypeManager();
		BuiltInDataTypeManager bdm = BuiltInDataTypeManager.getDataTypeManager();
		String structName = (this.name != null) ? this.name : ("dsnode_" + Integer.toHexString(System.identityHashCode(this)));
		StructureDataType newStruct = new StructureDataType(new CategoryPath("/struct"), structName, this.size);
		HashMap<Integer, DataType> sizeLookup = new HashMap<Integer, DataType>();
		sizeLookup.put(1, bdm.getDataType("/char"));
		sizeLookup.put(2, bdm.getDataType("/short"));
		sizeLookup.put(4, bdm.getDataType("/int"));
		sizeLookup.put(8, bdm.getDataType("/longlong"));

		for (Cell c : this.members.values()) {
			int offset = c.getFieldOffset();
			if (offset < 0 || offset >= this.size) continue; // skip out-of-bounds offsets
			DataType fieldDt = c.getAccessDataType();
			if (fieldDt != null) {
				int len = fieldDt.getLength() > 0 ? fieldDt.getLength() : size;
				newStruct.replaceAtOffset(offset, fieldDt, len, "entry_" + String.valueOf(offset), "");
			} else if (c.getOutEdges() != null) {
				Pointer subStructDtype = c.getParent().getDataType(currentProgram);
				newStruct.replaceAtOffset(offset, subStructDtype, currentProgram.getDefaultPointerSize(),
						"entry_" + String.valueOf(offset), "");
			} else {
				if (sizeLookup.containsKey(size))
					newStruct.replaceAtOffset(offset, sizeLookup.get(size), size, "entry_" + String.valueOf(offset),
							"");
				else {
					ArrayDataType arrDtype = new ArrayDataType(sizeLookup.get(1), size, 1);
					newStruct.replaceAtOffset(offset, arrDtype, size, "entry_" + String.valueOf(offset), "");
				}
			}
		}

		dm.addDataType(newStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		this.dtype = dm.getPointer(newStruct, currentProgram.getDefaultPointerSize());
		return this.dtype;
	}

	public void setCollapsed(boolean b) {
		this.collapsed = b;
		this.isArray = b;
	}

	public boolean isCollapsed() {
		return this.collapsed;
	}

	public void setOnHeap(boolean b) {
		this.onHeap = b;
	}

	public boolean getOnHeap() {
		return this.onHeap;
	}

	public boolean getIsArg() {
		return this.isArg;
	}

	public void setIsArg(boolean b) {
		this.isArg = b;
	}

	public int getMinOffset() {
		return this.minkey;
	}

	public Integer getPossibleStride() {
		return this.possibleStride;
	}

	public void setPossibleStride(Integer s) {
		if (s == null)
			return;
		this.hasStride = true;
		if (this.possibleStride != null && this.possibleStride < s)
			return;
		if (this.possibleStride != null && this.getLocations().toString().contains("G"))
			return;
		this.possibleStride = s;
	}

	public Address getLoc() {
		return loc;
	}

	public Graph getGraph() {
		return this.g;
	}

	public void setGraph(Graph newg) {
		this.g = newg;
	}

	// if node holds more than one constant, need
	// to differentiate whether it is T or a stride
	// both cases the node is collapsed
	public void addConstants(int i) {
		if (i == 0 && this.hasOut())
			return;
		this.setIsConstant(true);
		Integer oldValue = this.possibleConstant;
		this.possibleConstant = i;
		if (this.isCollapsed())
			return;
		if (i == IndirectCallTargetResolving.TOP) {
			this.collapse(true);
			return;
		}
		if (oldValue != null && oldValue.intValue() != i) {
			this.getGraph().changed = true;
			this.collapse(true);
			return;
		}
	}

	public void clearConstant() {
		this.possibleConstant = null;
	}

	public Integer getConstants() {
		return this.possibleConstant;
	}

	public HashMap<Integer, Cell> getMembers() {
		return members;
	}

	public void setMembers(HashMap<Integer, Cell> members) {
		this.members = members;
	}

	public void extend(int offset) {
		int sizenew = offset + 4 - minkey;
		if (this.size > sizenew)
			return;
		this.size = sizenew;
	}

	public Cell get(int offset) {
		if (this.isCollapsed()) {
			return this.members.get(0);
		} else if (!this.members.containsKey(offset)) {
			return null;
		} else {
			return this.members.get(offset);
		}
	}

	public Cell getOrCreateCell(int offset) {
		if (this.isCollapsed())
			return this.members.get(0);
		this.extend(offset);
		if (!this.members.containsKey(offset)) {
			Cell newCell = new Cell(this, offset);
			this.insertMember(offset, newCell);
		}
		return this.members.get(offset);
	}

	public void removeCell(int offset) {
		if (this.isCollapsed())
			return;
		if (this.members.containsKey(offset))
			this.members.remove(offset);
	}

	public void setArray(boolean isarray) {
		this.isArray = isarray;
	}

	public boolean isArray() {
		return this.isArray;
	}

	public boolean hasStride() {
		return this.hasStride;
	}

	public void insertMember(int offset, Cell subStruct) {
		this.members.put(offset, subStruct);
		if (offset < minkey) {
			int distance = minkey - offset;
			minkey = offset;
			for (Pair<String, Long> location : this.locations) {
				long o = location.getV();
				location.setV(o - distance);
			}
		}
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public void addLocations(Pair<String, Long> p) {
		this.locations.add(p);
	}

	public void addAllLocations(HashSet<Pair<String, Long>> p) {
		this.locations.addAll(p);
	}

	public HashSet<Pair<String, Long>> getLocations() {
		return this.locations;
	}

	public boolean isGlobal() {
		return isGlobal;
	}

	public void setGlobal(boolean isGlobal, Address addr) {
		this.isGlobal = isGlobal;
		if (this.loc == null)
			this.loc = addr;
	}

	public void collapse(boolean isConstant) {
		HashSet<DSNode> visited = new HashSet<DSNode>();
		this.collapse(isConstant, visited);
	}

	public void collapse(boolean isConstant, HashSet<DSNode> visited) {
		if (isConstant) {
			if (IndirectCallTargetResolving.conductCollapse)
				this.possibleConstant = IndirectCallTargetResolving.TOP;
			else
				return;
		}
		else
			this.possibleConstant = null;
		if (this.collapsed)
			return;

		this.collapsed = true;
		Graph thisg = this.getGraph();
		Function f = thisg.getF();
		thisg.changed = true;

		if (this.hasOut())
			this.collectMemberTypes();

		HashSet<Integer> allcell = new HashSet<Integer>();
		HashSet<Address> possiblePointers = new HashSet<Address>();
		allcell.addAll(this.getMembers().keySet());
		Cell minCell = this.getMembers().get(0);
		if (minCell == null) {
			minCell = new Cell(this, 0);
		}
		Cell e = minCell.getOutEdges();

		for (Integer cell : allcell) {
			if (this.getMembers().get(cell) != null) {
				possiblePointers.addAll(this.getMembers().get(cell).getPossiblePointersWithLoading(visited));
			}
		}
		minCell.addAllPointers(possiblePointers);

		for (Integer cell : allcell) {
			if (cell == 0)
				continue;
			Cell thiscell = this.getMembers().get(cell);
			if (thiscell != null) {
				// merge out edge
				Cell out = thiscell.getOutEdges();

				// we don't include the cell's out to this if it is a constant
				if (out != null && out.getParent() != null && out.getParent().isConstant) {
					this.getMembers().remove(cell);
					// assign it to stand alone node
					DSNode newParent = new DSNode(thiscell.getParent().loc, thisg);
					newParent.insertMember(thiscell.getFieldOffset(), thiscell);
					thiscell.setParent(newParent);
					if (cell == 0)
						minCell = new Cell(this, 0);
					continue;
				}

				if (out != null && e == null) {
					e = out;
					out.removeInEdges(thiscell);
					thiscell.removeOutEdges();
					minCell.setOutEdges(e);
				} else if (out != null) {
					out.removeInEdges(thiscell);
					thiscell.removeOutEdges();
					HashSet<DSNode> visiteddfs = new HashSet<DSNode>();
					e = e.mergeContent(out, visited, visiteddfs);
				}

				// merge the in edges
				HashSet<Cell> inedges = new HashSet<Cell>();
				inedges.addAll(thiscell.getInEdges());
				for (Cell inEdge : inedges) {
					// if inedge is collapsed, the original cell has been deleted, so we get the
					// cell 0
					if (inEdge.getParent() == null)
						continue;
					if (inEdge.getParent().isCollapsed()) {
						thiscell.removeInEdges(inEdge);
						inEdge.removeOutEdges();
						if (inEdge.getParent().get(0) == null)
							System.out.println("debug here");
						inEdge.getParent().get(0).setOutEdges(minCell);
					} else
						inEdge.setOutEdges(minCell);
				}
//				thiscell.getInEdges().clear();

				for (Varnode inEdge : thiscell.getInEvEdges()) {
					Function inEdgeFunc = inEdge.getHigh().getHighFunction().getFunction();
					if (inEdgeFunc != null) {
						Graph inEdgeG = thisg.getAllLocalGraphs().get(inEdgeFunc);
						if (inEdgeG != null)
							inEdgeG.setEv(inEdge, minCell);
						continue;
					}
				}
//				thiscell.getInEvEdges().clear();

				// merge callsites
				for (Pair<CallSiteNode, String> cs : thiscell.getInCallSite()) {
					CallSiteNode csn = cs.getK();
					String s = cs.getV();
					if (s == "ret") {
						csn.setMember(0, minCell);
					} else if (s == "func") {
						csn.setMember(1, minCell);

					} else {
						int argind = Integer.valueOf(s);
						csn.setMember(argind + 1, minCell);
					}
					minCell.addInCallSite(cs);
				}
//				thiscell.getInCallSite().clear();

				HashSet<Address> allglobals = new HashSet<Address>(thiscell.getGlobalAddrs());
				for (Address global : allglobals) {
					thiscell.getGlobalAddrs().remove(global);
					this.getGraph().getAllGlobals().setGlobalPtr(global, minCell);
					minCell.getGlobalAddrs().add(global);
				}

				if (thiscell.getCalleeArgLabel() != null) {
					for (String label : thiscell.getCalleeArgLabel()) {
						thisg.getCalleeargs().put(label, minCell);
						minCell.addCalleeArgLabel(label);
					}
					thiscell.getCalleeArgLabel().clear();
				}

				if (thiscell.getStackLocs().containsKey(f)) {
					HashSet<Integer> stackLocSet = new HashSet<Integer>();
					stackLocSet.addAll(thiscell.getStackLocs(f));
					for (Integer stackLoc : stackLocSet) {
						thiscell.getStackLocs(f).remove(stackLoc);
						minCell.addStackLocs(f, stackLoc);
						thisg.stackObj.put(stackLoc, minCell);
					}
				}

				if (thiscell.isRSP(f)) {
					int offset = thiscell.getRSPOffset(f);
					thiscell.setRSPOffset(f, null);
					minCell.setRSPOffset(f, offset);
				}

				for (Function key : thiscell.getStackLocs().keySet()) {
					HashSet<Integer> stackLocSet = new HashSet<Integer>();
					stackLocSet.addAll(thiscell.getStackLocs(key));
					if (stackLocSet.size() > 0) {
						for (Integer stackLoc : stackLocSet) {
							thiscell.getStackLocs(key).remove(stackLoc);
							minCell.addStackLocs(key, stackLoc);
							Graph curg = g.getAllLocalGraphs().get(key);
							curg.stackObj.put(stackLoc, minCell);
						}
					}
				}

				for (Function key : thiscell.getRSPOffset().keySet()) {
					if (thiscell.isRSP(key)) {
						int offset = thiscell.getRSPOffset(key);
						thiscell.setRSPOffset(key, null);
						minCell.setRSPOffset(key, offset);
					}
				}

				minCell.getReadFunc().addAll(thiscell.getReadFunc());
				minCell.getWriteFunc().addAll(thiscell.getWriteFunc());
			}

			if (cell != 0) {
				this.getMembers().remove(cell);
//				thiscell.setParent(null);
			}
		}

		if (e != null && this.get(0) != null)
			this.get(0).setOutEdges(e);

		this.minkey = 0;
	}

	public void collectMemberTypes() {
		for (int i : this.members.keySet()) {
			Cell cell = this.members.get(i);
			Cell outEdge = cell.getOutEdges();
			if (outEdge != null && outEdge.getParent() != null) {
				if (outEdge.getParent().hasOut())
					this.memberType.put(i, true);
				else if (outEdge.getParent().getIsConstant())
					this.memberType.put(i, false);
				else
					this.memberType.put(i, null);
			}
		}
	}

	
	public DSNode clone(Graph newg) {
		DSNode newDS = new DSNode(this.size, this.loc, newg);
		HashSet<Integer> keyset = new HashSet<Integer>();
		keyset.addAll(this.members.keySet());
		for (int i : keyset) {
			Cell thisCell = this.members.get(i);
			Cell copiedCell = new Cell(newDS, thisCell.getFieldOffset());
			copiedCell.addAllPointers(thisCell.getPossiblePointers());
			copiedCell.getWriteFunc().addAll(thisCell.getWriteFunc());
			copiedCell.getReadFunc().addAll(thisCell.getReadFunc());
//			copiedCell.addAllMemAccessInstr(thisCell.getMemAccessInstr());
			copiedCell.setTainted(thisCell.isTainted());
			newDS.insertMember(i, copiedCell);
			newDS.memberSize.put(i, this.memberSize.get(i));
		}
		newDS.isArray = this.isArray;
		newDS.hasStride = this.hasStride;
		newDS.collapsed = this.collapsed;
		newDS.onHeap = this.onHeap;
		newDS.isArg = this.isArg;
		newDS.isGlobal = this.isGlobal;
		newDS.onStack = this.onStack;
		newDS.isTainted = this.isTainted;
		newDS.addAllLocations(this.getLocations());
		newDS.possibleStride = this.possibleStride;
		newDS.possibleConstant = this.possibleConstant;
		newDS.mergedWith.addAll(this.mergedWith);
		for (AllocSite as : this.allocationSites) {
			AllocSite asCopied = as.deepcopy();
			asCopied.addCallpath(newg.getF());
			newDS.allocationSites.add(asCopied);
		}
		return newDS;
	}

	public DSNode deepCopy(Map<DSNode, DSNode> isomorphism, Graph newG, CallSiteNode cs, boolean copyCallsite) {
		if (this.isGlobal())
			return this;
		DSNode newDS = isomorphism.get(this);
		if (newDS == null) {
			newDS = this.clone(newG);
			isomorphism.put(this, newDS);

			HashSet<CallSiteNode> csnodeset = new HashSet<CallSiteNode>();
			for (CallSiteNode csn : this.getGraph().getCallNodes().values()) {
				if (!csn.getResolved())
					csnodeset.add(csn);
			}

			HashSet<Integer> indexes = new HashSet<Integer>();
			indexes.addAll(this.members.keySet());
			for (int i : indexes) {
				Cell c = this.members.get(i);
				Cell newc = newDS.getMembers().get(i);
				if (c == null || newc == null)
					continue;

				if (c.getOutEdges() != null) {
					DSNode outEdgeNode = c.getOutEdges().getParent();
					if (outEdgeNode != null) {
						int outEdgeOffset = c.getOutEdges().getFieldOffset();
						DSNode newOutEdgeNode = outEdgeNode.deepCopy(isomorphism, newG, cs, copyCallsite);
						newc.addOutEdges(newOutEdgeNode.get(outEdgeOffset));
					}
				}

				HashSet<Cell> inedges = new HashSet<Cell>();
				inedges.addAll(c.getInEdges());
				for (Cell inEdge : inedges) {
					DSNode inEdgeNode = inEdge.getParent();
					if (inEdgeNode == null)
						continue;
					int inEdgeOffset = inEdge.getFieldOffset();
					DSNode newInEdgeNode = inEdgeNode.deepCopy(isomorphism, newG, cs, copyCallsite);
					newc.addInEdges(newInEdgeNode.get(inEdgeOffset));
				}

				if (copyCallsite) {
					// copy the relation between callsitenode and cell
					HashSet<Pair<CallSiteNode, String>> csNodePairs = new HashSet<Pair<CallSiteNode, String>>();
					csNodePairs.addAll(c.getInCallSite());
					for (Pair<CallSiteNode, String> csNodePair : csNodePairs) {
						CallSiteNode csnode = csNodePair.getK();
						String s = csNodePair.getV();
						if (!csnodeset.contains(csnode) && !csnode.isGlobalAddr)
							continue;
						if (!csnode.isIndirect && newG.funcArgMap.size() <= 1)
							continue;
//					ArrayList<Address> cp = new ArrayList<Address>();
//					cp.addAll(cs.getCallPath());
//					cp.retainAll(csnode.getCallPath());
//					
//					if (cs.getCallPath().contains(csnode.getLoc()))
//						continue;

						CallSiteNode newCSNode = csnode.deepCopy(isomorphism, newG, cs);
						if (newCSNode == null)
							continue;
						newc.addInCallSite(new Pair<CallSiteNode, String>(newCSNode, s));
					}
				}

			}

		}

		return newDS;
	}

	public String toString() {
		HashSet<DSNode> visited = new HashSet<DSNode>();
		return this.toString("", visited);
	}

	public String toString(String indent, HashSet<DSNode> visited) {
		if (visited.contains(this))
			return "";
		String s = indent + "Node@";
		if (argNo == null && this.loc != null)
			s += this.loc.toString();
		else if (argNo != null)
			s += this.argNo;
		
		if (this.locations.size() > 0)
			s += this.locations.toString();

		if (this.isGlobal)
			s += " Global";
		if (this.isTainted)
			s += " Tainted";
		if (this.isConstant) {
			s += " Const";
			if (this.possibleConstant != null)
				s += ": " + String.valueOf(this.possibleConstant);
		}
		if (this.isCollapsed())
			s += " Collapsed";
		s += "\n";

		visited.add(this);
		HashSet<Integer> keyset = new HashSet<Integer>();
		keyset.addAll(this.members.keySet());
		for (int i : this.members.keySet()) {
			s += indent + "offset " + String.valueOf(i);
			Cell curCell = this.members.get(i);
			if (curCell.isTainted())
				s += " Tainted";
			if (curCell != null && curCell.getPossiblePointers().size() > 0)
				s += " Ptr: " + curCell.getPossiblePointers().toString();
			if (curCell == null) {
				s += "\n" + indent + "    <null, 0>\n";
				continue;
			}
			for (Pair<CallSiteNode, String> csite : curCell.getInCallSite()) {
				if (csite.getV().equals("func") && csite.getK().isIndirect)
					s += "\n" + indent + "is target of " + csite.getK().toString() + "\n";
			}
			Cell c = curCell.getOutEdges();
			if (c == null) {
				s += "\n" + indent + "    <null, 0>\n";
				continue;
			}
			DSNode parent = c.getParent();
			if (parent == null) {
				s += "\n" + indent + "    <null, 0>\n";
				continue;
			}
			int offset = c.getFieldOffset();
			s += " -> offset" + String.valueOf(offset) + "\n";
			s += parent.toString(indent + "    ", visited);
		}

		return s;
	}

	public String getArgNo() {
		return argNo;
	}

	public void setArgNo(String argNo) {
		this.argNo = argNo;
	}

	public boolean hasCycle(HashSet<Address> currentAddrs) {
		for (Cell c : this.members.values()) {
			Cell outE = c.getOutEdges();
			if (outE == null || outE.getParent() == null)
				continue;
			if (currentAddrs.contains(outE.getParent().getLoc()))
				return true;
			Address cloc = outE.getParent().getLoc();
			currentAddrs.add(cloc);
			if (outE.getParent().hasCycle(currentAddrs))
				return true;
			currentAddrs.remove(cloc);
		}
		return false;
	}

	public void getDesendants(HashSet<DSNode> des) {
		des.add(this);
		for (Cell c : this.members.values()) {
			Cell outCell = c.getOutEdges();
			if (outCell != null && outCell.getParent() != null && !des.contains(outCell.getParent()))
				outCell.getParent().getDesendants(des);
		}
	}

	public void getDirectDesendants(HashSet<DSNode> des) {
		des.add(this);
		for (Cell c : this.members.values()) {
			Cell outCell = c.getOutEdges();
			if (outCell != null && outCell.getParent() != null && !des.contains(outCell.getParent()))
				des.add(outCell.getParent());
		}
	}

	public void getPreDesendants(HashSet<DSNode> des) {
		des.add(this);
		for (Cell c : this.members.values()) {
			HashSet<Cell> inCell = c.getInEdges();
			for (Cell in : inCell) {
				if (in != null && in.getParent() != null && !des.contains(in.getParent()))
					in.getParent().getPreDesendants(des);
			}
		}
	}

	public void addMergedWith(Address loc2) {
		if (!mergedWith.contains(loc2))
			mergedWith.add(loc2);
	}

	public boolean hasOut() {
		boolean hasOut = false;
		boolean hasTwoLevelOut = false;
		for (Cell c : this.members.values()) {
			Cell cout = c.getOutEdges();
			if (cout != null) {
				hasOut |= true;
				if (cout.getParent() == null)
					continue;
				for (Cell c2 : cout.getParent().members.values())
					if (c2.getOutEdges() != null)
						hasTwoLevelOut |= true;
			}
		}
		if (hasOut && (this.isConstant || this.isCharPointer)) {
			if (!hasTwoLevelOut)
				this.setCharPointer(true);
			else
				this.setCharPointer(false);
			this.isConstant = false;
			this.clearConstant();
		} else if (hasOut) {
			this.setCharPointer(false);
			this.isConstant = false;
			this.clearConstant();
		}
		return hasOut;
	}

	public boolean getIsConstant() {
		this.hasOut();
		boolean hasPointer = false;
		for (Cell c : this.members.values()) {
			if (c.possiblePointers.size() > 0)
				hasPointer |= true;
		}
		if (hasPointer) {
			this.setCharPointer(false);
			this.isConstant = false;
			this.clearConstant();
		}

		// if the constant is 0, it could still be a pointer
		if (this.getConstants() != null && this.getConstants() == 0)
			return false;

		return this.isConstant;
	}

	public HashMap<Integer, Boolean> getMemberType() {
		return memberType;
	}

	public void setMemberType(HashMap<Integer, Boolean> memberType) {
		this.memberType = memberType;
	}

	public void addMemberType(int offset, boolean type) {
		this.memberType.put(offset, type);
	}

	public void addSubTypeCell(Cell cell, Cell input) {
		if (!this.subTypes.containsKey(cell))
			this.subTypes.put(cell, new HashSet<Cell>());
		this.subTypes.get(cell).add(input);
	}

	public void addSuperTypeCell(Cell cell, Cell input) {
		if (!this.superTypes.containsKey(cell))
			this.superTypes.put(cell, new HashSet<Cell>());
		this.superTypes.get(cell).add(input);
	}

	public HashSet<Function> getReadFunc() {
		HashSet<Function> accessFunc = new HashSet<Function>();
		for (Cell c : this.members.values()) {
			accessFunc.addAll(c.getReadFunc());
		}
		return accessFunc;
	}

	public HashSet<Function> getWriteFunc() {
		HashSet<Function> accessFunc = new HashSet<Function>();
		for (Cell c : this.members.values()) {
			accessFunc.addAll(c.getWriteFunc());
		}
		return accessFunc;
	}

	public HashSet<Function> getAllReadFunc() {
		HashSet<Function> accessFunc = new HashSet<Function>();
		HashSet<DSNode> des = new HashSet<DSNode>();
		this.getDesendants(des);
		for (DSNode n : des) {
			accessFunc.addAll(n.getReadFunc());
		}
		return accessFunc;
	}

	public HashSet<Function> getAllWriteFunc() {
		HashSet<Function> accessFunc = new HashSet<Function>();
		HashSet<DSNode> des = new HashSet<DSNode>();
		this.getDesendants(des);
		for (DSNode n : des) {
			accessFunc.addAll(n.getWriteFunc());
		}
		return accessFunc;
	}

	public boolean isCharPointer() {
		return isCharPointer;
	}

	public void setCharPointer(boolean isCharPointer) {
		if (isCharPointer) {
			ArrayList<Integer> keyset = new ArrayList<Integer>();
			keyset.addAll(this.members.keySet());
			Collections.sort(keyset);
			boolean isCharPtr = true;
			for (int i = 1; i < keyset.size(); i++) {
				if (keyset.get(i) - keyset.get(i - 1) == 1)
					continue;
				isCharPtr = false;
				break;
			}
			this.isCharPointer = isCharPtr;
		} else
			this.isCharPointer = isCharPointer;
	}

	public HashSet<Integer> getStackObjPtrOffset() {
		return stackObjPtrOffset;
	}

	public void setStackObjPtrOffset(int stackObjPtrOffset) {
		this.stackObjPtrOffset.add(stackObjPtrOffset);
	}

	public boolean isTainted() {
		return isTainted;
	}

	public void setTainted(boolean isTainted) {
		this.isTainted = isTainted;
		HashSet<DSNode> des = new HashSet<DSNode>();
		this.getDesendants(des);
		for (DSNode n : des)
			n.isTainted = true;
	}

}


