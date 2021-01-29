package ghidra.rl78.elf;

import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.app.util.bin.format.elf.extend.ElfExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.classfinder.ExtensionPointProperties;
import ghidra.util.task.TaskMonitor;

@ExtensionPointProperties(priority = 2)
public class RL78ElfExtension extends ElfExtension {

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == RL78Constants.MACHINE_TYPE;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		return canHandle(elfLoadHelper.getElfHeader());
	}

	@Override
	public String getDataTypeSuffix() {
		return "rl78";
	}

	@Override
	public void processElf(ElfLoadHelper helper, TaskMonitor monitor) {
		Program program = helper.getProgram();
		Memory mem = program.getMemory();
		Address ram = helper.getDefaultAddress(0);
		Address start = helper.getDefaultAddress(0xF0000);
		try {
			mem.createByteMappedBlock("MIRROR", start, ram, 0x10000, false);
		} catch (Exception e) {
			helper.getLog().appendException(e);
		}
	}

}
