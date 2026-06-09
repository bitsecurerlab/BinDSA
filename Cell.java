import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class Cell {
	private HashSet<Cell> inEdges;
	private HashSet<Varnode> inEvEdges;
	private HashSet<Pair<CallSiteNode, String>> inCallsite;
	private Cell outEdge;
	private int fieldOffset;
	private DSNode parent;
	private HashSet<String> accessMode;
	public HashSet<Address> possiblePointers;
	private HashSet<String> allInCallSites;
	private HashSet<Address> globalAddrs;
	private HashMap<Function, HashSet<Integer>> stackLocs;
	private HashSet<String> calleeArgLabel; // used for cloned Cells
	private HashMap<Function, Integer> isRSP;
	public boolean isLoopVariant;
	private boolean isTainted;
	private HashSet<Function> readFunc;
	private HashSet<Function> writeFunc;
	private HashSet<Address> memAccessInstr;
	private DataType accessDataType; // DataType inferred by the decompiler for this field's access

	public Cell(DSNode parent, int fieldOffset) {
		this.parent = parent;
		this.fieldOffset = fieldOffset;
		this.inEdges = new HashSet<Cell>();
		this.inEvEdges = new HashSet<Varnode>();
		this.accessMode = new HashSet<String>();
		if (parent != null)
			parent.insertMember(fieldOffset, this);
		this.inCallsite = new HashSet<Pair<CallSiteNode, String>>();
		this.possiblePointers = new HashSet<Address>();
		this.stackLocs = new HashMap<Function, HashSet<Integer>>();
		this.allInCallSites = new HashSet<String>();
		this.globalAddrs = new HashSet<Address>();
		this.isRSP = new HashMap<Function, Integer>();
		this.isLoopVariant = false;
		this.readFunc = new HashSet<Function>();
		this.writeFunc = new HashSet<Function>();
		this.isTainted = false;
		this.memAccessInstr = new HashSet<Address>();
	}

	public boolean hasTaintedInEdge() {
		for (Cell in : this.inEdges) {
			if (in.isTainted())
				return true;
		}
		return false;
	}

	public boolean isTainted() {
		if (this.parent != null && this.parent.isTainted())
			this.isTainted = true;
		return isTainted;
	}

	public void setTainted(boolean isTainted) {
		this.isTainted = isTainted;
	}

	public void setSubTypeRelation(Cell input) {
		DSNode parent1 = this.parent;
		DSNode parent2 = input.parent;
		if (parent1 == null || parent2 == null || parent1 == parent2)
			return;
		parent1.addSubTypeCell(this, input);
		parent2.addSuperTypeCell(input, this);
	}

	public HashSet<Function> getReadFunc() {
		return readFunc;
	}

	public void setReadFunc(Function readFunc) {
		this.readFunc.add(readFunc);
	}

	public HashSet<Function> getWriteFunc() {
		return writeFunc;
	}

	public void setWriteFunc(Function writeFunc) {
		this.writeFunc.add(writeFunc);
	}

	public void addMemAccessInstr(Address instr) {
		this.memAccessInstr.add(instr);
	}

	public void addAllMemAccessInstr(HashSet<Address> instr) {
		this.memAccessInstr.addAll(instr);
	}

	public HashSet<Address> getMemAccessInstr() {
		return this.memAccessInstr;
	}

	public void setAccessDataType(DataType dt) {
		if (this.accessDataType == null) { // only record first (most recently defined)
			this.accessDataType = dt;
		}
	}

	public DataType getAccessDataType() {
		return accessDataType;
	}

	public HashSet<String> getCalleeArgLabel() {
		return calleeArgLabel;
	}

	public void clearCalleeArgLabel() {
		this.calleeArgLabel = null;
	}

	public void addCalleeArgLabel(String argLabel) {
		if (this.calleeArgLabel == null)
			this.calleeArgLabel = new HashSet<String>();
		this.calleeArgLabel.add(argLabel);
	}

	public HashSet<Integer> getStackLocs(Function func) {
		return stackLocs.get(func);
	}

	public HashMap<Function, HashSet<Integer>> getStackLocs() {
		return stackLocs;
	}

	public void addStackLocs(Function func, Integer stackLoc) {
		if (!this.stackLocs.containsKey(func))
			this.stackLocs.put(func, new HashSet<Integer>());
		HashSet<Integer> locs = this.stackLocs.get(func);
		locs.add(stackLoc);
	}

	public void setRSPOffset(Function func, Integer b) {
		this.isRSP.put(func, b);
	}

	public int getRSPOffset(Function func) {
		return this.isRSP.get(func);
	}

	public HashMap<Function, Integer> getRSPOffset() {
		return this.isRSP;
	}

	public boolean isRSP(Function func) {
		return this.isRSP.get(func) != null;
	}

	public void addInCallSite(Pair<CallSiteNode, String> cs) {
//		String index = "";
//		if (cs.getK().getLoc() != null)
//			index += cs.getK().getLoc().toString();
//		else
//			index += "null";
//		index += cs.getV();
//		if (this.allInCallSites.contains(index) && cs.getK().getLoc() != null)
////			System.out.println("duplicate");
//			return;
//		else {
		this.inCallsite.add(cs);
//			this.allInCallSites.add(index);
//		}
	}

	public HashSet<Pair<CallSiteNode, String>> getInCallSite() {
		return this.inCallsite;
	}

	public HashSet<Address> getGlobalAddrs() {
		return this.globalAddrs;
	}

	public Cell merge(Cell cell) {
		if (this == cell) {
			return this;
		}
		if (cell == null)
			return this;
		DSNode parent2 = this.parent;
		DSNode parent1 = cell.getParent();
		if (parent1 == null)
			return this;
		if (parent2 == null) {
			return cell.merge(this);
		}
		if (parent1.isTainted())
			parent2.setTainted(true);
		if (cell.isTainted())
			this.setTainted(true);
		
		// handle the merging of constants
		if (parent1.getIsConstant() || parent2.getIsConstant()) {
			if (parent1.hasStride())
				parent2.setPossibleStride(parent1.getPossibleStride());
			if (parent1.getConstants() != null && parent2.getIsConstant())
				parent2.addConstants(parent1.getConstants());
			return this;
		}
		
		if (parent1.isCharPointer() && !parent2.isCharPointer() && parent2.hasOut())
			return this;
		else if (parent2.isCharPointer() && !parent1.isCharPointer() && parent1.hasOut())
			return this;
		// TODO: handle other merge conflicts

		HashSet<DSNode> notDelete = new HashSet<DSNode>();
		HashSet<DSNode> visitedDSNode = new HashSet<DSNode>();
		HashSet<DSNode> visiteddfs = new HashSet<DSNode>();

		// conduct merging
		Cell retCell = this.mergeContent(cell, visitedDSNode, visiteddfs);
		
		// delete merged cell
		if (retCell != null && retCell.getParent() != null) {
			HashSet<DSNode> des = new HashSet<DSNode>();
			retCell.getParent().getDesendants(des);
			notDelete.addAll(des);
			HashSet<DSNode> pre = new HashSet<DSNode>();
			retCell.getParent().getPreDesendants(pre);
			notDelete.addAll(pre);
		}

		for (DSNode d : visitedDSNode) {
			if (!notDelete.contains(d)) {
				boolean isGlobal = false;
				for (Cell c : d.members.values()) {
					if (c.getGlobalAddrs().size() > 0)
						isGlobal = true;
				}
				if (isGlobal)
					continue;
				for (Cell c : d.members.values()) {
					c.removeOutEdges();
					c.getInEdges().clear();
					c.getInEvEdges().clear();
					c.getInCallSite().clear();
					c.getPossiblePointers().clear();
					c.setParent(null);
				}
				d.members.clear();
			}
		}
		return retCell;
	}


	private Varnode getOneVar(HashMap<Cell, Varnode> cellToVarMap) {
		if (cellToVarMap.containsKey(this))
			return cellToVarMap.get(this);
		Iterator<Varnode> iter = this.inEvEdges.iterator();
		Varnode v = null;
		while (iter.hasNext()) {
			v = iter.next();
			if (this.getGraph().getEv(v) == this) {
				cellToVarMap.put(this, v);
				return v;
			}
		}
		return v;
	}

	public Cell mergeContent(Cell cell, HashSet<DSNode> visitedDSNode, HashSet<DSNode> visiteddfs) {
		if (this == cell) {
			return this;
		}
		if (cell == null)
			return this;
		DSNode parent2 = this.parent;
		DSNode parent1 = cell.getParent();
		if (parent1 == null)
			return this;
		if (parent2 == null) {
			return cell;
		}

//		HashSet<DSNode> des = new HashSet<DSNode>();
//		parent2.getDirectDesendants(des);
//		if (des.contains(parent1)) // currently, we don't allow self loop TODO: handle the merging better
//			return this;
		if (visiteddfs.contains(parent1) && visiteddfs.contains(parent2)) // in case parent1 has been visited
			return this;
//		if (visiteddfs.contains(parent2))
//			return this;

		visiteddfs.add(parent2);
		visiteddfs.add(parent1);
		
		// TODO: add more complicated taints
		if (parent1.isTainted())
			parent2.setTainted(true);
				
		// check if types are compatible
		if (parent1.getIsConstant() || parent2.getIsConstant()) {
			if (parent1.hasStride())
				parent2.setPossibleStride(parent1.getPossibleStride());
			if (parent1.getConstants() != null && parent2.getIsConstant())
				parent2.addConstants(parent1.getConstants());
			return this;
		}
		if (parent1.isCharPointer() && !parent2.isCharPointer() && parent2.hasOut())
			return this;
		else if (parent2.isCharPointer() && !parent1.isCharPointer() && parent1.hasOut())
			return this;
		
		
		int field2 = this.getFieldOffset();
		int field1 = cell.getFieldOffset();

//		// TODO: handle merge conflicts
		if (parent2 == parent1) {
//			parent2.collapse(false, visitedDSNode);
//			return parent2.get(0);
			return this;
		}
		// currently, only global array supports collapse
		if (parent1.isCollapsed() && (cell.getGlobalAddrs().size() > 0 || parent1.isGlobal())) {
			parent2.collapse(false, visitedDSNode);
			field2 = 0;
		}
		else if (parent1.isCollapsed())
			return this;

		if (this.parent == null)
			return this;
		visitedDSNode.add(parent1);

		int locOff = field1 - field2 + parent2.getMinOffset() - parent1.getMinOffset();
		if (locOff == 0) {
			parent2.addAllLocations(parent1.getLocations());
			parent1.getLocations().clear();
		} else {
			for (Pair<String, Long> location : parent1.getLocations()) {
				Long v = location.getV();
				location.setV(v + locOff);
				parent2.addLocations(location);
			}
			parent1.getLocations().clear();
		}

		ArrayList<Integer> keyset = new ArrayList<Integer>();
		keyset.addAll(parent1.getMembers().keySet());
		Graph g = this.getGraph();
		Graph mergedCellG = parent1.g;
//		if (mergedCellG instanceof GlobalRegion) {
//			this.getParent().setGraph(mergedCellG);
//		}
		g.changed = true;
		Program currProg = g.getCurrentProgram();
		for (int field : keyset) {
			Cell mergedCell = parent1.get(field);
			Cell cell2 = parent2.getOrCreateCell(field + field2 - field1);
			if (mergedCell.isTainted())
				cell2.setTainted(true);
			if (cell2 == null || mergedCell == null)
				continue;

			// merge the out edges of different corresponding fields
			Cell outCell2 = cell2.getOutEdges();
			Cell outCell1 = mergedCell.getOutEdges();
			if (outCell2 != null) {
				boolean existingIsEmptyConstant = outCell2.getParent() != null && outCell2.getParent().getIsConstant()
						&& outCell2.getPossiblePointers().isEmpty() && outCell2.getOutEdges() == null;
				boolean incomingHasPointerInfo = outCell1 != null
						&& (!outCell1.getPossiblePointers().isEmpty() || outCell1.getOutEdges() != null);
				if (existingIsEmptyConstant && incomingHasPointerInfo) {
					outCell2.addAllPointers(outCell1.getPossiblePointers());
					if (outCell1.getOutEdges() != null)
						outCell2.addOutEdges(outCell1.getOutEdges());
				} else
					outCell2.mergeContent(outCell1, visitedDSNode, visiteddfs);
			} else if (outCell1 != null)
				cell2.setOutEdges(outCell1);
			if (outCell1 != null)
				outCell1.removeInEdges(mergedCell);

			// merge the in edges
			HashSet<Cell> inedges = new HashSet<Cell>();
			inedges.addAll(mergedCell.getInEdges());
			for (Cell inEdge : inedges) {
				// if inedge is collapsed, the original cell has been deleted, so we get the
				// cell 0
				if (inEdge.getParent() == null)
					continue;
				if (inEdge.getOutEdges() != mergedCell)
					continue;
				if (inEdge.getParent().isCollapsed()) {
//					mergedCell.removeInEdges(inEdge);
					inEdge.removeOutEdges();
					if (inEdge.getParent().get(0) == null)
						continue;
					inEdge.getParent().get(0).setOutEdges(cell2);
				} else
					inEdge.setOutEdges(cell2);
			}

			for (Varnode inEdge : mergedCell.getInEvEdges()) {
				if (inEdge.getHigh() == null)
					continue;
				Function inEdgeFunc = inEdge.getHigh().getHighFunction().getFunction();
				if (inEdgeFunc != null) {
					Graph inEdgeG = g.getAllLocalGraphs().get(inEdgeFunc);
					if (inEdgeG != null)
						inEdgeG.setEv(inEdge, cell2);
					continue;
				}
			}

			// merge mem access info
			// allMemAccessInstrMap is shared among all graphs
			for (Address addr : mergedCell.getMemAccessInstr()) {
				cell2.addMemAccessInstr(addr);
				parent1.getGraph().getMemAccessInstrMap(addr).remove(mergedCell);
				parent2.getGraph().addMemAccessInstrMap(addr, cell2);
			}
			mergedCell.getMemAccessInstr().clear();


			// merge the callsite info
			HashSet<Pair<CallSiteNode, String>> incallsites = new HashSet<Pair<CallSiteNode, String>>();
			incallsites.addAll(cell2.getInCallSite());
			for (Pair<CallSiteNode, String> cs : incallsites) {
				CallSiteNode csn = cs.getK();
				String s = cs.getV();
				if (s == "func" && mergedCell.getPossiblePointersWithLoading(visitedDSNode).size() > 0
						&& csn.isIndirect) {
					HashSet<Address> fps = IndirectCallTargetResolving
							.getPossibleFuncPointer(mergedCell.getPossiblePointers(), currProg);
					if (fps.size() > 0) {
						Instruction instr = currProg.getListing().getInstructionAt(csn.getLoc());
						if (instr != null) {
							boolean resolvedNew = false;
							HashSet<Address> existingTargets = new HashSet<Address>();
							CallSiteNode existCsn = g.getCallNodes(csn.getLoc());
							if (existCsn != null && existCsn.getFunc() != null)
								existingTargets.addAll(existCsn.getFunc().getPossiblePointers());
							if (g.getTmpCallNodes(csn.getLoc()) != null)
								for (CallSiteNode n : g.getTmpCallNodes(csn.getLoc())) {
									if (n.getFunc() != null)
										existingTargets.addAll(n.getFunc().getPossiblePointers());
								}
//							for (Reference r : instr.getOperandReferences(0)) {
//								existingTargets.add(r.getToAddress());
//							}
							String fpstr = "";
							for (Address address : fps) {
								if (!existingTargets.contains(address)) {
									resolvedNew = true;
									int as = currProg.getAddressFactory().getAddressSpace("ram").getSpaceID();
									address = currProg.getAddressFactory().getAddress(as, address.getOffset());
									Function fp = currProg.getFunctionManager().getFunctionAt(address);
									fpstr += fp.getName() + ", ";
									instr.addOperandReference(0, address, RefType.COMPUTED_CALL,
											SourceType.USER_DEFINED);
								}
							}

							if (resolvedNew) {
								csn.getGraph().resolvedNewCallSite = true;
								DebugUtil.print("Solved1 " + csn.toString() + " -> " + fps.toString());
								BufferedWriter out;
								try {
									out = new BufferedWriter(new OutputStreamWriter(
											new FileOutputStream(IndirectCallTargetResolving.outPath, true)));
									out.write(csn.toString() + "@" + String.valueOf(fps.size()) + "@" + fpstr);
									out.newLine();
									out.close();
								} catch (Exception e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
						}

					}
				}
			}

			for (Pair<CallSiteNode, String> cs : mergedCell.getInCallSite()) {
				CallSiteNode csn = cs.getK();
				String s = cs.getV();
				if (s == "ret") {
					csn.setMember(0, cell2);
				} else if (s == "func") {
					csn.setMember(1, cell2);
					if (cell2.getPossiblePointersWithLoading(visitedDSNode).size() > 0 && csn.isIndirect) {
						HashSet<Address> fps2 = IndirectCallTargetResolving
								.getPossibleFuncPointer(cell2.getPossiblePointers(), currProg);
						if (fps2.size() > 0) {
							Instruction instr = currProg.getListing().getInstructionAt(csn.getLoc());
							if (instr != null) {
								boolean resolvedNew = false;
								HashSet<Address> existingTargets = new HashSet<Address>();
								CallSiteNode existCsn2 = g.getCallNodes(csn.getLoc());
								if (existCsn2 != null && existCsn2.getFunc() != null)
									existingTargets.addAll(existCsn2.getFunc().getPossiblePointers());
								if (g.getTmpCallNodes(csn.getLoc()) != null)
									for (CallSiteNode n : g.getTmpCallNodes(csn.getLoc())) {
										if (n.getFunc() != null)
											existingTargets.addAll(n.getFunc().getPossiblePointers());
									}
//								for (Reference r : instr.getOperandReferences(0)) {
//									existingTargets.add(r.getToAddress());
//								}
								String fpstr = "";
								for (Address address : fps2) {
									if (!existingTargets.contains(address)) {
										resolvedNew = true;
										int as = currProg.getAddressFactory().getAddressSpace("ram").getSpaceID();
										address = currProg.getAddressFactory().getAddress(as, address.getOffset());
										Function fp = currProg.getFunctionManager().getFunctionAt(address);
										fpstr += fp.getName() + ", ";
										instr.addOperandReference(0, address, RefType.COMPUTED_CALL,
												SourceType.USER_DEFINED);
									}
								}
								if (resolvedNew) {
									csn.getGraph().resolvedNewCallSite = true;
									DebugUtil.print("Solved2 " + csn.toString() + " -> " + fps2.toString());
									BufferedWriter out;
									try {
										out = new BufferedWriter(new OutputStreamWriter(
												new FileOutputStream(IndirectCallTargetResolving.outPath, true)));
										out.write(csn.toString() + "@" + String.valueOf(fps2.size()) + "@" + fpstr);
										out.newLine();
										out.close();
									} catch (Exception e) {
										// TODO Auto-generated catch block
										e.printStackTrace();
									}

								}
							}
						}
					}

				} else {
					int argind = Integer.valueOf(s);
					csn.setMember(argind + 1, cell2);
				}
				cell2.addInCallSite(cs);
			}

			if (cell2 != null && mergedCell != null && mergedCell.getPossiblePointers().size() > 0) {
				cell2.addAllPointers(mergedCell.getPossiblePointers());
			}

			HashSet<Address> bindedGlobals = new HashSet<Address>();
			bindedGlobals.addAll(mergedCell.getGlobalAddrs());
			for (Address bindedGlobal : bindedGlobals) {
				if (g.getAllGlobals().contains(bindedGlobal) && g.getAllGlobals().getGlobalPtr(bindedGlobal) == mergedCell) {
					g.getAllGlobals().setGlobalPtr(bindedGlobal, cell2);
					cell2.getGlobalAddrs().add(bindedGlobal);
					cell2.getParent().setGlobal(true, bindedGlobal);
					mergedCell.getGlobalAddrs().remove(bindedGlobal);
				}
			}

			if (mergedCell.getCalleeArgLabel() != null && mergedCell.getCalleeArgLabel().size() > 0) {
				for (String label : mergedCell.getCalleeArgLabel()) {
					mergedCellG.getCalleeargs().put(label, cell2);
					cell2.addCalleeArgLabel(label);
				}
				mergedCell.calleeArgLabel = null;
				if (g != mergedCellG)
					parent2.g = mergedCellG;
			}

			for (Function key : mergedCell.getStackLocs().keySet()) {
				HashSet<Integer> stackLocSet = new HashSet<Integer>();
				stackLocSet.addAll(mergedCell.getStackLocs(key));
				if (stackLocSet.size() > 0) {
					for (Integer stackLoc : stackLocSet) {
						mergedCell.getStackLocs(key).remove(stackLoc);
						cell2.addStackLocs(key, stackLoc);
						Graph curg = g.getAllLocalGraphs().get(key);
						curg.stackObj.put(stackLoc, cell2);
					}
				}
			}

			for (Function key : mergedCell.getRSPOffset().keySet()) {
				if (mergedCell.isRSP(key)) {
					int offset = mergedCell.getRSPOffset(key);
					mergedCell.setRSPOffset(key, null);
					cell2.setRSPOffset(key, offset);
				}
			}

			cell2.getReadFunc().addAll(mergedCell.getReadFunc());
			cell2.getWriteFunc().addAll(mergedCell.getWriteFunc());

		}

		if (parent1.getGraph() == parent2.getGraph()) {
			parent2.getStackObjPtrOffset().addAll(parent1.getStackObjPtrOffset());
			for (int offset : parent1.getStackObjPtrOffset())
				g.getStackObjPtr().put(offset, parent2);
			parent1.getStackObjPtrOffset().clear();
		}

		parent2.addMergedWith(parent1.getLoc());

		if (parent1.getConstants() != null)
			parent2.addConstants(parent1.getConstants());
		if (parent1.isArray())
			parent2.setArray(true);
		if (parent1.isOnStack()) {
			parent1.setOnStack(false);
			parent2.setOnStack(true);
		}
		if (parent1.getSize() > parent2.getSize())
			parent2.setSize(parent1.getSize());
		if (parent1.getPossibleStride() != null)
			parent2.setPossibleStride(parent1.getPossibleStride());
		if (parent1.getOnHeap()) {
			parent2.setOnHeap(true);
		}
		if (parent2.isCollapsed())
			return parent2.get(0);

		return this;
	}

	

	public Graph getGraph() {
		return this.getParent().getGraph();
	}

	public void addOutEdges(Cell dst) {
		if (dst == null || this.parent == null)
			return;
		if (this.getParent().getIsConstant() && this.getParent().getConstants() != null) {
			Address newGlobalAddr = this.getParent().getLoc().getNewAddress(this.getParent().getConstants());
			this.addPointersWithLoading(newGlobalAddr);
		} else if (this.getParent().getIsConstant())
			this.getParent().setCharPointer(true);
		this.getParent().setIsConstant(false);
		if (outEdge == dst)
			return;
		if (dst.getParent() == this.getParent())
			return;
		this.getGraph().changed = true;
		dst.addInEdges(this);
		if (this.getParent().getOnHeap() && dst.getParent() != null)
			dst.getParent().setOnHeap(true);
		if (this.getParent().getIsArg() && dst.getParent() != null)
			dst.getParent().setIsArg(true);
		if (outEdge == null || outEdge.getParent() == null)
			outEdge = dst;
		else
			outEdge.merge(dst);
	}

	public void setOutEdges(Cell dst) {
		if (dst == null || dst.getParent() == null || this.parent == null)
			return;
		if (dst.getParent() == this.getParent())
			return;
		if (this.getParent().getIsConstant() && this.getParent().getConstants() != null) {
			Address newGlobalAddr = this.getParent().getLoc().getNewAddress(this.getParent().getConstants());
			this.addPointersWithLoading(newGlobalAddr);
		} else if (this.getParent().getIsConstant())
			this.getParent().setCharPointer(true);
		this.getParent().setIsConstant(false);

		// it is possible that a pointer is stored into a global variable when merging
		// also, we only merge with global variable if it stores a pointer
//		if (dst.getParent() != null && dst.getParent().getPossiblePointers().size() > 0) {
//			HashMap<Address, Cell> allGlobals = this.getGraph().getAllGlobals();
//			for (Address maddr : this.getParent().getPossiblePointers()) {
//				if (!allGlobals.containsKey(maddr))
//					allGlobals.put(maddr, dst);
//				else {
//					Cell origin = allGlobals.get(maddr);
//					origin.merge(dst);
//				}
//				dst.getParent().setGlobal(true);
//			}
//		}

		// TODO: if this cell is pointer, need to handle the new outedge, read its
		// content from the pointer addr
		dst.addInEdges(this);
		if (this.getParent().getOnHeap() && dst.getParent() != null)
			dst.getParent().setOnHeap(true);
		if (this.getParent().getIsArg() && dst.getParent() != null)
			dst.getParent().setIsArg(true);

		if (outEdge == null)
			outEdge = dst;
		else if (outEdge == dst)
			return;
		else {
			// delete the original link
			outEdge.removeInEdges(this);
			outEdge = dst;
		}
		if (this.isTainted())
			outEdge.setTainted(true);
	}

	public Cell getOutEdges() {
		return outEdge;
	}

	public void addAccessMode(String access) {
		this.accessMode.add(access);
	}

	public void addInEvEdges(Varnode v) {
		this.inEvEdges.add(v);
	}

	public HashSet<Varnode> getInEvEdges() {
		return inEvEdges;
	}

	public void addInEdges(Cell c) {
		if (c == null)
			return;
		if (c.getParent().isGlobal() && this.getParent() != null)
			this.getParent().setGlobal(true, null);
		this.inEdges.add(c);
	}

	public HashSet<Cell> getInEdges() {
		return inEdges;
	}

	public void removeInEdges(Cell dst) {
		inEdges.remove(dst);
	}

	public void removeOutEdges() {
		outEdge = null;
	}

	public int getFieldOffset() {
		return fieldOffset;
	}

	public void setFieldOffset(int fieldOffset) {
		this.fieldOffset = fieldOffset;
	}

	public DSNode getParent() {
		return parent;
	}

	public void setParent(DSNode parent) {
		this.parent = parent;
	}

	/*
	 * This is called when we know f is a function pointer, so there is no need to
	 * load its content
	 */
	public void addPointers(Address f) {
		this.getParent().setIsConstant(false);
		if (this.possiblePointers.contains(f))
			return;
		this.possiblePointers.add(f);
		HashSet<Address> fp = new HashSet<Address>();
		fp.addAll(this.possiblePointers);
		Program currProg = this.getGraph().getCurrentProgram();
		HashSet<Address> fps = IndirectCallTargetResolving.getPossibleFuncPointer(fp, currProg);

		// if this node is global, when adding new pointer values, need to check its
		// related callsites
		if (this.getParent() != null) {
			for (Pair<CallSiteNode, String> cs : this.getInCallSite()) {
				CallSiteNode csn = cs.getK();
				String s = cs.getV();
				if (s == "func" && f != null && csn.isIndirect) {
					if (fps.size() > 0 && fps.size() < 200) {
						Instruction instr = currProg.getListing().getInstructionAt(csn.getLoc());
						String fpstr = "";
						if (instr != null) {
							for (Address address : fps) {
								csn.getGraph().resolvedNewCallSite = true;
								int as = currProg.getAddressFactory().getAddressSpace("ram").getSpaceID();
								address = currProg.getAddressFactory().getAddress(as, address.getOffset());
								Function func = currProg.getFunctionManager().getFunctionAt(address);
								fpstr += func.getName() + ", ";
								instr.addOperandReference(0, address, RefType.COMPUTED_CALL, SourceType.USER_DEFINED);
							}
						}
//						DebugUtil.print("Solved " + csn.toString() + " -> " + fps.toString());

						BufferedWriter out;
						try {
							out = new BufferedWriter(new OutputStreamWriter(
									new FileOutputStream(IndirectCallTargetResolving.outPath, true)));
							out.write(csn.toString() + "@" + String.valueOf(fps.size()) + "@" + fpstr);
							out.newLine();
							out.close();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				}
			}
		}
	}

	public boolean addPointersWithLoading(Address f) {
		if (this.getParent() == null)
			return false;
		if (this.possiblePointers.contains(f))
			return false;
		
		this.addPointers(f);
		
		HashSet<Address> fp = new HashSet<Address>();
		fp.add(f);
		Program currProg = this.getGraph().getCurrentProgram();
		HashSet<Address> fps = IndirectCallTargetResolving.getPossibleFuncPointer(fp, currProg);
		boolean ret = false;
		
		// during merging, if a pointer of global is added to this cell, need to load
		// and check the content in global

		// load the content from f, store it into outedges's possible pointer, set the
		// outedge to global variable
		if (fps.contains(f)) {
			return ret;
		} else if (this.getParent() != null) {
			Graph thisgraph = this.getGraph();
			Cell origin = thisgraph.getAllGlobals().findPtr(f);
			if (origin != null) {
				this.merge(origin);
				ret |= true;
			} else {
				this.getPossiblePointers().remove(f);
			}
		}
		return ret;

	}

	public void addAllPointers(HashSet<Address> f) {
		if (this.getParent() == null  || f.size() == 0)
			return;
		this.getParent().setIsConstant(false);
		for (Address addr : f) {
			this.addPointers(addr);
		}
	}

	public HashSet<Address> getPossiblePointers() {
		if (this.getParent() == null)
			return new HashSet<Address>();

		return this.possiblePointers;
	}

	public HashSet<Address> getPossiblePointersWithLoading(HashSet<DSNode> visitedDSNode) {
		if (this.getParent() == null)
			return new HashSet<Address>();
		int minkey = this.getParent().getMinOffset();
//		if (this.possiblePointers.size() > 0 || this.getFieldOffset() == minkey)
		return this.possiblePointers;

//		if (this.getParent().get(minkey) != null) {
//			HashSet<Address> ptrs = new HashSet<Address>();
//			ptrs.addAll(this.getParent().get(minkey).possiblePointers);
//			if (ptrs.size() == 0)
//				return ptrs;
//
//			for (Address ptr : ptrs) {
//				try {
//					this.addPointersWithLoading(ptr.add(this.getFieldOffset() - minkey), visitedDSNode);
//				} catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
//					DebugUtil.print("Address out of bounds");
//				}
//			}
//			return this.possiblePointers;
//		}
//		return new HashSet<Address>();
	}

	public String toString() {
		String s = "Cell@offset" + String.valueOf(fieldOffset) + "\n";
		if (this.getGlobalAddrs().size() > 0)
			s += this.getGlobalAddrs().toString() + "\n";
		if (this.parent != null)
			s += this.parent.toString();
		return s;
	}

}
