import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;


public class GlobalRegion extends Graph{
	private HashMap<Address, Cell> regionPtrMap;
	private HashMap<Address, Integer> regionSize;
	private Program currentProgram;
	public static String dumpPath = System.getProperty("user.home") + "/spec2006x86/O2_g3_out/globalregion.txt";	

	public GlobalRegion(Program currentProgram, HashMap<Function, Graph> allLocalGraphs, HashMap<Address, HashSet<Cell>> allMemAccessInstrMap) {
		this.regionPtrMap = new HashMap<Address, Cell>();
		this.regionSize = new HashMap<Address, Integer>();
		this.allLocalGraphs = allLocalGraphs;
		this.memAccessInstrMap = allMemAccessInstrMap;
		this.currentProgram = currentProgram;
		this.initRegionPtr();
		this.dumpGlobalRegion();
	}
	
	public Program getCurrentProgram() {
		return currentProgram;
	}

	public void setCurrentProgram(Program currentProgram) {
		this.currentProgram = currentProgram;
	}
	
	public GlobalRegion getAllGlobals() {
		return this;
	}
	
	private void dumpGlobalRegion() {
		BufferedWriter out;
		try {
			out = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(GlobalRegion.dumpPath)));
			for (Address addr : regionPtrMap.keySet()) {
				int size = regionSize.get(addr);
				out.write(Long.toHexString(addr.getOffset()) + ", " + Integer.toString(size));
				out.newLine();
			}
			out.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Init the global region using Ghidra's global symbols
	 */
	private void initRegionPtr() {
		SymbolTable symtab = currentProgram.getSymbolTable();
		MemoryBlock mem = currentProgram.getMemory().getBlock(".data");
		MemoryBlock romem = currentProgram.getMemory().getBlock(".rodata");
		MemoryBlock bssmem = currentProgram.getMemory().getBlock(".bss");
        SymbolIterator symiter = symtab.getAllSymbols(true);
        
        while (symiter.hasNext()) {
        	Symbol sym = symiter.next();
            Address addr = sym.getAddress();
            if (!mem.contains(addr) && !bssmem.contains(addr) && !romem.contains(addr))
                continue;
            Data data = this.currentProgram.getListing().getDataAt(addr);
            if (data == null)
                continue;
            if (regionPtrMap.containsKey(addr))
            	continue;
            DSNode baseNode = new DSNode(addr, this);
			Cell baseCell = new Cell(baseNode, 0);
			HashSet<Address> visited = new HashSet<Address>();
			if (loadGlobalVariableToMem(addr, baseCell, visited)) {
				baseCell.addPointers(addr);
				baseNode.addLocations(new Pair<String, Long>("G", addr.getOffset()));
				regionPtrMap.put(addr, baseCell);
				baseCell.getGlobalAddrs().add(addr);
			}
        }
	}
	
	public boolean contains(Address s) {
		if (regionPtrMap.containsKey(s))
			return true;
		return false;
	}
	
	public boolean containsMem(Address s) {
		if (!regionPtrMap.containsKey(s))
			return false;
		if (regionPtrMap.get(s).getOutEdges() == null)
			return false;
		return true;
	}

	public Cell getGlobalPtr(Address s) {
		return regionPtrMap.get(s);
	}
	
	public HashMap<Address, Cell> getGlobalPtr() {
		return regionPtrMap;
	}

	public void setGlobalPtr(Address s, Cell c) {
		this.regionPtrMap.put(s, c);
	}
	
	public Cell findPtr(Address s) {
		if (contains(s))
			return regionPtrMap.get(s);
		for (Address start : regionSize.keySet()) {
			int size = regionSize.get(start);
			int a = s.compareTo(start);
			int b = s.compareTo(start.add(size));
			if (a >= 0 && b < 0) {
				DSNode regionStart = regionPtrMap.get(start).getParent();
				if (regionStart.getPossibleStride() != null)
					return regionStart.getOrCreateCell(IndirectCallTargetResolving.mod((int) s.subtract(start), regionStart.getPossibleStride()));
				return regionStart.getOrCreateCell((int) s.subtract(start));
			}
		}
		return null;
	}
	
	public Cell getGlobalMem(Address s) {
		Cell regionPtr = regionPtrMap.get(s);
		if (regionPtr != null && regionPtr.getOutEdges() != null)
			return regionPtr.getOutEdges();
		
		regionPtr = findPtr(s);
		if (regionPtr == null)
			return null;
		if (regionPtr.getOutEdges() != null)
			return regionPtr.getOutEdges();
		
		// if it is not loaded in the regionPtrMap, means it is a constant value currently
		// can be assigned as a pointer later
		DSNode nnode = new DSNode(s, this);
		Cell ncell = new Cell(nnode, 0);
		regionPtr.setOutEdges(ncell);
		return ncell;
	}
	
	/**
	 * load the value from maddr (only when it is not loaded before), and add it to
	 * GlobalRegion it will be called recursively since the loaded value could points
	 * to another data section it returns true if the current call loads some
	 * pointers, false if it does not we will not add the corresponding
	 * field if it does not load any pointers. We skipped the non-pointer field to save space.
	 * If such a field is used later, it will be created in getGlobalMem
	 * 
	 * @param maddr
	 * @param mem
	 * @param curProgram
	 * @param global
	 * @param graph
	 * @return
	 */
	public boolean loadGlobalVariableToMem(Address maddr, Cell mem, HashSet<Address> visited) {
		try {
			if (visited.contains(maddr))
				return true;
			
			visited.add(maddr);
			Data data = currentProgram.getListing().getDataAt(maddr);

			if (data == null || mem == null) {
				return false;
			}
			int dataSize = data.getDataType().getLength();
			mem.getParent().setSize(dataSize);
			regionSize.put(maddr, dataSize);
			if (data.hasStringValue() || data.isConstant()) {
				Cell out = mem.getOutEdges();
				if (out == null) {
					out = new Cell(new DSNode(maddr, this), 0);
					mem.setOutEdges(out);
				}
				out.getParent().setGlobal(true, maddr);
				
				if (data.hasStringValue()) {
					mem.getParent().setCharPointer(true);
					mem.getParent().setPossibleStride(1);
				} else {
					byte[] memcont = data.getBytes();
					String hex = bytesToHex(memcont);
					if (new BigInteger(hex, 16).longValue() != 0)
						out.getParent().setIsConstant(true);
				}
				
				return true;
			}
			MemoryBlock mb = currentProgram.getMemory().getBlock(".text");
			Address textBegin = mb.getStart();
			Address textEnd = mb.getEnd();

			if (dataSize > 4) {
				int datatypesize = data.getDataType().getLength();
				if (data.isArray()) {
					mem.getParent().setArray(true);
					Array arr = (Array) data.getDataType();
					if (arr.getDataType() instanceof Array) {
						datatypesize = ((Array) arr.getDataType()).getElementLength();
					} else		
						datatypesize = arr.getElementLength();
					// collapse and merge all cells into one, only global array has collapse
					if (datatypesize <= 4) {
						mem.getParent().setCollapsed(true);
						datatypesize = 4;
					}
					mem.getParent().setPossibleStride(datatypesize);
				}
				byte[] memcont = data.getBytes();
				for (int i = 0; i < memcont.length && i + 3 < memcont.length; i += 4) {
					byte[] submemcont = new byte[] { memcont[i], memcont[i + 1], memcont[i + 2], memcont[i + 3] };
					String hex = bytesToHex(submemcont);
					Address newAddr = currentProgram.getAddressFactory().getAddress(
							currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
							new BigInteger(hex, 16).longValue());
					if (newAddr == null)
						continue;
					Instruction instr = currentProgram.getListing().getInstructionAt(newAddr);

					boolean isText;
					if (newAddr.getOffset() <= textEnd.getOffset() && newAddr.getOffset() >= textBegin.getOffset())
						isText = true;
					else
						isText = false;
					// if the stored pointer points to an valid instruction
					if (instr != null) {
						IndirectCallTargetResolving.isFuncPointer(newAddr, currentProgram);
						Address curMAddr = maddr.add(i);
						Cell out = null;
						Cell memwithoffset = null;
						if (mem != null) {
							if (data.isArray()) {
								memwithoffset = mem.getParent()
										.getOrCreateCell(mem.getFieldOffset() + i % datatypesize);
								
							} else
								memwithoffset = mem.getParent().getOrCreateCell(mem.getFieldOffset() + i);
							out = memwithoffset.getOutEdges();
						}
						if (out == null) {
							out = new Cell(new DSNode(curMAddr, this), 0);
							if (memwithoffset != null)
								memwithoffset.setOutEdges(out);
						}
						out.getParent().setGlobal(true, curMAddr);
						out.getPossiblePointers().add(newAddr);

					} // if the stored pointer points to the data section
					else if (currentProgram.getListing().getDataAt(newAddr) != null && !isText) {
						Address curMAddr = maddr.add(i);
						Cell out = null;
						Cell memwithoffset = null;
						if (mem != null) {
							if (data.isArray()) {								
								memwithoffset = mem.getParent()
										.getOrCreateCell(mem.getFieldOffset() + i % datatypesize);

							} else
								memwithoffset = mem.getParent().getOrCreateCell(mem.getFieldOffset() + i);
							out = memwithoffset.getOutEdges();
						}

						if (regionPtrMap.containsKey(newAddr)) {
							Cell origin = regionPtrMap.get(newAddr);
							if (out != null) {
								origin.merge(out);
							}
							out = origin;
							out.getParent().setGlobal(true, curMAddr);
						} else {
							if (out == null || out.getParent() == null) {
								out = new Cell(new DSNode(curMAddr, this), 0);
								if (memwithoffset != null)
									memwithoffset.setOutEdges(out);
							}
							out.getParent().setGlobal(true, curMAddr);
							// load mem recursively	
							if (loadGlobalVariableToMem(newAddr, out, visited)) {
								out.addPointers(newAddr);
								out.getParent().addLocations(new Pair<String, Long>("G", newAddr.getOffset()));
								regionPtrMap.put(newAddr, out);
								out.getGlobalAddrs().add(newAddr);
							}
						}
					}
				}
				return true;
			}

			// the size is smaller than 4
			byte[] memcont = data.getBytes();
			String hex = bytesToHex(memcont);
			Address newAddr = currentProgram.getAddressFactory().getAddress(
					currentProgram.getAddressFactory().getAddressSpace("ram").getSpaceID(),
					new BigInteger(hex, 16).longValue());
			if (newAddr == null)
				return false;
			Instruction instr = currentProgram.getListing().getInstructionAt(newAddr);
			boolean isText;
			if (newAddr.getOffset() <= textEnd.getOffset() && newAddr.getOffset() >= textBegin.getOffset())
				isText = true;
			else
				isText = false;
			if (instr != null) {
				IndirectCallTargetResolving.isFuncPointer(newAddr, currentProgram);
				Cell out = null;
				if (mem != null)
					out = mem.getOutEdges();
				if (out == null) {
					out = new Cell(new DSNode(maddr, this), 0);
					if (mem != null)
						mem.setOutEdges(out);
				}
				
				out.addPointers(newAddr);
				return true;
			}
			if (isText)
				return false;
			Cell out = null;
			if (mem != null) {
				out = mem.getOutEdges();
			}
			
			if (currentProgram.getListing().getDataAt(newAddr) != null) {
				if (regionPtrMap.containsKey(newAddr)) {
					Cell origin = regionPtrMap.get(newAddr);
					if (out != null) {
						origin.merge(out);
					}
					out = origin;
				} else {
					if (out == null || out.getParent() == null) {
						out = new Cell(new DSNode(maddr, this), 0);
						if (mem != null)
							mem.setOutEdges(out);
					}
					// load mem recursively	
					if (loadGlobalVariableToMem(newAddr, out, visited)) {
						out.addPointers(newAddr);
						out.getParent().addLocations(new Pair<String, Long>("G", newAddr.getOffset()));
						regionPtrMap.put(newAddr, out);
						out.getGlobalAddrs().add(newAddr);
					}
				}
			}

			return true;

		} catch (MemoryAccessException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
		}
		return true;
	}
	
	public String bytesToHex(byte[] bytes) {
		char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		// the bytes array is in the reverse order
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			int i = bytes.length - j - 1;
			hexChars[i * 2] = HEX_ARRAY[v >>> 4];
			hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0f];
		}

		return new String(hexChars);
	}
	
}
