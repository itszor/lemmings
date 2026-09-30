// Apply code/data classification produced by export_ghidra.py to a raw RISC OS
// absolute image.  Run as a pre-script (before auto-analysis).
// Script argument: path to the JSON file.
//@category RISCOS

import java.io.FileReader;
import java.util.*;

import com.google.gson.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.docking.settings.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;

public class ApplyRiscOSAnnotations extends GhidraScript {

	private Address addr(JsonElement e) {
		return toAddr(e.getAsLong());
	}

	@Override
	public void run() throws Exception {
		String path = getScriptArgs()[0];
		JsonObject j = JsonParser.parseReader(new FileReader(path)).getAsJsonObject();
		Listing listing = currentProgram.getListing();

		// 0. The image is writable (inline variables, self-modifying code).
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			b.setWrite(true);
		}

		// 1. Data first, so nothing later disassembles over it.
		int nstr = 0, ndw = 0;
		for (JsonElement e : j.getAsJsonArray("strings")) {
			JsonArray s = e.getAsJsonArray();
			Address a = addr(s.get(0));
			int len = s.get(1).getAsInt();
			boolean term = s.get(2).getAsBoolean();
			try {
				if (term) {
					listing.createData(a, TerminatedStringDataType.dataType, len);
				}
				else {
					listing.createData(a, new ArrayDataType(CharDataType.dataType, len, 1));
				}
				nstr++;
			}
			catch (CodeUnitInsertionException ex) {
				// overlapping / conflicting: skip
			}
		}
		for (JsonElement e : j.getAsJsonArray("dwords")) {
			Address a = addr(e);
			try {
				listing.createData(a, DWordDataType.dataType);
				ndw++;
			}
			catch (CodeUnitInsertionException ex) {
			}
		}

		// Literal-pool words are never written: let the decompiler fold them.
		for (JsonElement e : j.getAsJsonArray("const_dwords")) {
			Data d = listing.getDataAt(addr(e));
			if (d != null) {
				MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
			}
		}

		// 2. Disassemble exactly the classified code.
		AddressSet firm = new AddressSet(), spec = new AddressSet();
		for (JsonElement e : j.getAsJsonArray("code_ranges")) {
			JsonArray r = e.getAsJsonArray();
			Address s = addr(r.get(0)), en = toAddr(r.get(1).getAsLong() - 1);
			(r.get(2).getAsBoolean() ? spec : firm).add(s, en);
		}
		AddressSet all = firm.union(spec);
		DisassembleCommand dis = new DisassembleCommand(all, all, false);
		dis.applyTo(currentProgram, monitor);

		// 3. Flow overrides for the non-standard call/return idioms.
		int nov = 0;
		for (JsonElement e : j.getAsJsonArray("overrides")) {
			JsonArray o = e.getAsJsonArray();
			Instruction ins = listing.getInstructionAt(addr(o.get(0)));
			if (ins != null) {
				ins.setFlowOverride(FlowOverride.valueOf(o.get(1).getAsString()));
				nov++;
			}
		}

		// OS_WriteS: execution resumes after the inline string.
		for (JsonElement e : j.getAsJsonArray("fallthrough")) {
			JsonArray f = e.getAsJsonArray();
			Instruction ins = listing.getInstructionAt(addr(f.get(0)));
			if (ins != null) {
				ins.setFallThrough(addr(f.get(1)));
			}
		}

		// SWIs become calls to register-prototyped pseudo-functions in a SWI block.
		JsonArray swis = j.getAsJsonArray("swis");
		Address swiBase = toAddr(0x10000000L);
		currentProgram.getMemory().createUninitializedBlock("SWI", swiBase, 4L * swis.size(), false);
		FunctionManager fm = currentProgram.getFunctionManager();
		ReferenceManager rm = currentProgram.getReferenceManager();
		Map<Long, Address> swiAddr = new HashMap<>();
		for (int i = 0; i < swis.size(); i++) {
			JsonArray sw = swis.get(i).getAsJsonArray();
			Address fa = swiBase.add(4L * i);
			String name = sw.get(1).getAsString().replaceAll("[^A-Za-z0-9_+]", "_").replace('+', '_');
			Function f = fm.createFunction(name, fa, new AddressSet(fa), SourceType.USER_DEFINED);
			List<Variable> params = new ArrayList<>();
			for (int r = 0; r < sw.get(2).getAsInt(); r++) {
				Register reg = currentProgram.getRegister("r" + r);
				params.add(new ParameterImpl("r" + r, Undefined4DataType.dataType, reg,
					currentProgram));
			}
			f.updateFunction(null,
				new ReturnParameterImpl(Undefined4DataType.dataType,
					new VariableStorage(currentProgram, currentProgram.getRegister("r0")),
					currentProgram),
				params, Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
			f.setNoReturn(sw.get(3).getAsBoolean());
			swiAddr.put(sw.get(0).getAsLong(), fa);
		}
		int nswi = 0;
		for (Instruction ins : listing.getInstructions(all, true)) {
			if (!ins.getMnemonicString().startsWith("swi") &&
				!ins.getMnemonicString().startsWith("svc")) {
				continue;
			}
			long n = ins.getInt(0) & 0xFFFFFFL;
			Address to = swiAddr.get(n);
			if (to != null) {
				Reference r = rm.addMemoryReference(ins.getAddress(), to,
					RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, Reference.MNEMONIC);
				rm.setPrimary(r, true);
				nswi++;
			}
		}
		println("SWI call sites linked: " + nswi);

		// 4. Labels and comments.
		for (JsonElement e : j.getAsJsonArray("labels")) {
			JsonArray l = e.getAsJsonArray();
			createLabel(addr(l.get(0)), l.get(1).getAsString(), true, SourceType.USER_DEFINED);
		}
		for (JsonElement e : j.getAsJsonArray("comments")) {
			JsonArray c = e.getAsJsonArray();
			Address a = addr(c.get(0));
			String kind = c.get(1).getAsString(), text = c.get(2).getAsString();
			switch (kind) {
				case "EOL": setEOLComment(a, text); break;
				case "PLATE": setPlateComment(a, text); break;
				default: setPreComment(a, text); break;
			}
		}
		for (AddressRange r : spec) {
			createBookmark(r.getMinAddress(), "RISCOS",
				"speculative code (not reached from entry point)");
		}

		// 5. Functions.
		int nf = 0;
		for (JsonElement e : j.getAsJsonArray("functions")) {
			JsonArray f = e.getAsJsonArray();
			Address a = addr(f.get(0));
			boolean sp = f.get(1).getAsBoolean();
			String name = (a.getOffset() == j.get("base").getAsLong()) ? "_start"
					: String.format("%s_%x", sp ? "spec" : "sub", a.getOffset());
			if (listing.getInstructionAt(a) == null) {
				continue;
			}
			CreateFunctionCmd cmd = new CreateFunctionCmd(name, a, null, SourceType.USER_DEFINED);
			if (cmd.applyTo(currentProgram, monitor)) {
				nf++;
			}
		}
		println(String.format("applied: %d strings, %d dwords, %d overrides, %d functions, " +
			"%d firm + %d speculative code bytes", nstr, ndw, nov, nf,
			firm.getNumAddresses(), spec.getNumAddresses()));
	}
}
