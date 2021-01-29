package ghidra.rl78.elf.relocation;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.rl78.elf.RL78Constants;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NotFoundException;

import static ghidra.rl78.elf.relocation.RL78RelocationConstants.*;

public class RL78ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == RL78Constants.MACHINE_TYPE;
	}

	@Override
	public void relocate(ElfRelocationContext context, ElfRelocation reloc, Address addr)
			throws MemoryAccessException, NotFoundException {

		HowTo howTo = new HowTo(context, reloc, addr);

		Program program = context.getProgram();
		BookmarkManager bMan = program.getBookmarkManager();
		int offset = (int) addr.getOffset();

		switch (reloc.getType()) {
			case R_RL78_NONE:
				return;
			case R_RL78_DIR32:
				howTo.relocate(2, 32, 0);
				break;
			case R_RL78_DIR24S:
				howTo.relocate(2, 24, 0);
				break;
			case R_RL78_DIR16:
			case R_RL78_DIR16U:
			case R_RL78_DIR16S:
				howTo.relocate(1, 16, 0);
				break;
			case R_RL78_DIR8:
			case R_RL78_DIR8U:
			case R_RL78_DIR8S:
				howTo.relocate(0, 8, 0);
				break;
			case R_RL78_DIR24S_PCREL:
				howTo.relocate(2, 24, 0, offset);
				break;
			case R_RL78_DIR16S_PCREL:
				howTo.relocate(1, 16, 0, offset);
				break;
			case R_RL78_DIR8S_PCREL:
				howTo.relocate(0, 8, 0, offset);
				break;
			case R_RL78_DIR16UL:
				howTo.relocate(1, 16, 2);
				break;
			case R_RL78_DIR16UW:
				howTo.relocate(1, 16, 1);
				break;
			case R_RL78_DIR8UL:
				howTo.relocate(0, 8, 2);
				break;
			case R_RL78_DIR8UW:
				howTo.relocate(0, 8, 1);
				break;
			case R_RL78_DIR32_REV:
			case R_RL78_DIR16_REV:
				howTo.relocate(1, 16, 0);
				break;
			case R_RL78_DIR3U_PCREL:
				howTo.relocate(0, 3, 0, offset);
				break;
			case R_RL78_RH_RELAX:
			case R_RL78_RH_SFR:
			case R_RL78_RH_SADDR:
			case R_RL78_ABS32:
			case R_RL78_ABS24S:
			case R_RL78_ABS16:
			case R_RL78_ABS16U:
			case R_RL78_ABS16S:
			case R_RL78_ABS8:
			case R_RL78_ABS8U:
			case R_RL78_ABS8S:
			case R_RL78_ABS24S_PCREL:
			case R_RL78_ABS16S_PCREL:
			case R_RL78_ABS8S_PCREL:
			case R_RL78_ABS16UL:
			case R_RL78_ABS16UW:
			case R_RL78_ABS8UL:
			case R_RL78_ABS8UW:
			case R_RL78_ABS32_REV:
			case R_RL78_ABS16_REV:
			case R_RL78_SYM:
			case R_RL78_OPneg:
			case R_RL78_OPadd:
			case R_RL78_OPsub:
			case R_RL78_OPmul:
			case R_RL78_OPdiv:
			case R_RL78_OPshla:
			case R_RL78_OPshra:
			case R_RL78_OPsctsize:
			case R_RL78_OPscttop:
			case R_RL78_OPand:
			case R_RL78_OPor:
			case R_RL78_OPxor:
			case R_RL78_OPnot:
			case R_RL78_OPmod:
			case R_RL78_OPromtop:
			case R_RL78_OPramtop:
			default:
				String msg = String.format("Unsupported relocation type %d", reloc.getType());
				bMan.setBookmark(addr, BookmarkType.ERROR, BookmarkType.ERROR, msg);
				break;
		}
	}

	private static class HowTo {

		private final ElfRelocationContext context;
		private final Address addr;
		private final int symbolValue;

		HowTo(ElfRelocationContext context, ElfRelocation reloc, Address addr) {
			this.context = context;
			this.addr = addr;

			ElfSymbol sym = null;
			int symbolIndex = reloc.getSymbolIndex();
			if (symbolIndex != 0) {
				sym = context.getSymbol(symbolIndex);
			}

			this.symbolValue = sym != null ? (int) context.getSymbolValue(sym) : 0;
		}

		Memory getMemory() {
			return context.getProgram().getMemory();
		}

		boolean isLittleEndian() {
			return !getMemory().isBigEndian();
		}

		void relocate(int size, int bit, int shift) {
			relocate(size, bit, shift, 0);
		}

		void relocate(int size, int bit, int shift, int offset) {
			if (symbolValue == 0) {
				return;
			}
			try {
				size++;
				int oldValue = readInt(size);
				int newValue = ((oldValue << bit) >> shift) - offset;
				setInt(newValue | symbolValue, size);
			} catch (MemoryAccessException e) {
				// do nothing
			}
		}

		int readInt(int len) {
			MemoryByteProvider provider = new MemoryByteProvider(getMemory(), addr);
			BinaryReader reader = new BinaryReader(provider, isLittleEndian());
			try {
				return (int) reader.readValue(0, len);
			} catch (IOException e) {
				throw new AssertException(e);
			}
		}

		void setInt(int v, int len) throws MemoryAccessException {
			ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
			buf.order(isLittleEndian() ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN).putInt(v);
			getMemory().setBytes(addr, buf.array(), 0, len);
		}
	}

}
