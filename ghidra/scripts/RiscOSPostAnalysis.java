// Post-analysis for RISC OS absolutes: install jump-table overrides for the
// computed "add pc,pc,X" jumps into unrolled code, decompile every function
// and report what Ghidra made of it.
// Script arguments: JSON path, output directory.
//@category RISCOS

import java.io.*;
import java.util.*;

import com.google.gson.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.*;

public class RiscOSPostAnalysis extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		JsonObject j = JsonParser.parseReader(new FileReader(args[0])).getAsJsonObject();
		File outDir = new File(args[1]);
		outDir.mkdirs();
		Listing listing = currentProgram.getListing();
		FunctionManager fm = currentProgram.getFunctionManager();

		// Restore the spider's names where auto-analysis left defaults.
		for (JsonElement e : j.getAsJsonArray("functions")) {
			JsonArray fa = e.getAsJsonArray();
			Function f = fm.getFunctionAt(toAddr(fa.get(0).getAsLong()));
			if (f != null && f.getName().startsWith("FUN_")) {
				f.setName(String.format("%s_%x", fa.get(1).getAsBoolean() ? "spec" : "sub",
					fa.get(0).getAsLong()), SourceType.USER_DEFINED);
			}
		}
		for (Function f : fm.getFunctions(true)) {
			if (f.getName().startsWith("FUN_")) {
				f.setName("sub_" + f.getEntryPoint().toString().replaceFirst("^0+", ""),
					SourceType.ANALYSIS);
			}
		}

		// Duff's-device jump tables.
		int nduff = 0;
		for (JsonElement e : j.getAsJsonArray("duff")) {
			JsonArray d = e.getAsJsonArray();
			Address br = toAddr(d.get(0).getAsLong());
			Instruction ins = listing.getInstructionAt(br);
			Function f = fm.getFunctionContaining(br);
			if (ins == null || f == null) {
				println("duff site not in a function: " + br);
				continue;
			}
			ArrayList<Address> dests = new ArrayList<>();
			for (JsonElement t : d.get(1).getAsJsonArray()) {
				Address a = toAddr(t.getAsLong());
				if (listing.getInstructionAt(a) == null) {
					continue;
				}
				dests.add(a);
				ins.addOperandReference(0, a, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED);
			}
			new JumpTable(br, dests, true, 0).writeOverride(f);
			CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
			nduff++;
		}
		println("duff jump tables installed: " + nduff);

		// Compare Ghidra's code with the spider's classification.
		AddressSet ours = new AddressSet();
		for (JsonElement e : j.getAsJsonArray("code_ranges")) {
			JsonArray r = e.getAsJsonArray();
			ours.add(toAddr(r.get(0).getAsLong()), toAddr(r.get(1).getAsLong() - 1));
		}
		AddressSet ghidraCode = new AddressSet();
		for (Instruction i : listing.getInstructions(true)) {
			ghidraCode.add(i.getMinAddress(), i.getMaxAddress());
		}
		AddressSet extra = ghidraCode.subtract(ours);
		println(String.format("instructions: ghidra %d bytes, spider %d bytes, ghidra-only %d bytes",
			ghidraCode.getNumAddresses(), ours.getNumAddresses(), extra.getNumAddresses()));
		try (PrintWriter pw = new PrintWriter(new File(outDir, "ghidra_only_code.txt"))) {
			for (AddressRange r : extra) {
				pw.println(r.getMinAddress() + "-" + r.getMaxAddress());
			}
		}

		// Decompile everything.
		DecompInterface di = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		di.setOptions(opts);
		di.toggleCCode(true);
		di.openProgram(currentProgram);
		int nfun = 0, nok = 0, nwarn = 0;
		Map<String, Integer> warnKinds = new TreeMap<>();
		try (PrintWriter c = new PrintWriter(new File(outDir, "galdan.c"));
				PrintWriter idx = new PrintWriter(new File(outDir, "functions.tsv"))) {
			idx.println("entry\tname\tbody_bytes\tcallers\tcallees\tparams\treturn\tstatus");
			for (Function f : fm.getFunctions(true)) {
				if (f.getBody().getNumAddresses() <= 1 && f.getEntryPoint().getOffset() >= 0x10000000L) {
					continue;
				}
				nfun++;
				DecompileResults res = di.decompileFunction(f, 60, monitor);
				String status;
				if (res != null && res.decompileCompleted()) {
					nok++;
					String code = res.getDecompiledFunction().getC();
					c.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() + " ==== */");
					c.println(code);
					boolean w = false;
					for (String line : code.split("\n")) {
						int k = line.indexOf("WARNING:");
						if (k >= 0) {
							w = true;
							String kind = line.substring(k + 8).trim()
									.replaceAll("0x[0-9a-fA-F]+", "X")
									.replaceAll("[0-9a-fA-F]{8}", "X")
									.replaceAll("\\*/$", "").trim();
							warnKinds.merge(kind, 1, Integer::sum);
						}
					}
					if (w) {
						nwarn++;
					}
					status = w ? "warnings" : "ok";
				}
				else {
					status = "FAILED: " + (res == null ? "null" : res.getErrorMessage().trim());
					c.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() + " FAILED: " +
						status + " */");
				}
				idx.println(String.format("%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s", f.getEntryPoint(),
					f.getName(), f.getBody().getNumAddresses(),
					f.getCallingFunctions(monitor).size(), f.getCalledFunctions(monitor).size(),
					f.getParameterCount(), f.getReturnType().getName(), status.replace('\n', ' ')));
			}
		}
		di.dispose();
		println(String.format("functions %d, decompiled %d, with warnings %d", nfun, nok, nwarn));
		for (Map.Entry<String, Integer> e : warnKinds.entrySet()) {
			println(String.format("  %5d  %s", e.getValue(), e.getKey()));
		}
	}
}
