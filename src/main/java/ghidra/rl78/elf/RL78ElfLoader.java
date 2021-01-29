package ghidra.rl78.elf;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.app.util.Option;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.lang.Endian;

import generic.continues.RethrowContinuesFactory;

public class RL78ElfLoader extends ElfLoader {

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		try {
			ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			if (elf.e_machine() == RL78Constants.MACHINE_TYPE) {
				return getLoadSpecs(provider);
			}
		} catch (ElfException e) {
			// do nothing
		}
		return Collections.emptyList();
	}

	private Collection<LoadSpec> getLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		try {
			ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			List<QueryResult> results =
				QueryOpinionService.query(super.getName(), elf.getMachineName(), elf.getFlags());
			for (QueryResult result : results) {
				boolean add = true;
				// Some languages are defined with sizes smaller than 32
				if (elf.is32Bit() && result.pair.getLanguageDescription().getSize() > 32) {
					add = false;
				}
				if (elf.is64Bit() && result.pair.getLanguageDescription().getSize() <= 32) {
					add = false;
				}
				if (elf.isLittleEndian() &&
					result.pair.getLanguageDescription().getEndian() != Endian.LITTLE) {
					add = false;
				}
				if (elf.isBigEndian() &&
					result.pair.getLanguageDescription().getEndian() != Endian.BIG) {
					add = false;
				}
				if (add) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}
		catch (ElfException e) {
			// not a problem, it's not an elf
		}

		return loadSpecs;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {
		List<Option> options =
			super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram);
		options.removeIf(o -> o.getName().equals("Image Base"));
		return options;
	}

	@Override
	public String getName() {
		return "RL78 " + super.getName();
	}

}
