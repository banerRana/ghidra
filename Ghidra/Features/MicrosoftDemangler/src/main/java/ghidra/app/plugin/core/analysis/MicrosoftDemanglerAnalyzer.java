/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.microsoft.*;
import ghidra.app.util.demangler.microsoft.options.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * A version of the demangler analyzer to handle microsoft symbols
 */
public class MicrosoftDemanglerAnalyzer extends AbstractDemanglerAnalyzer {

	public static final String NAME = "Demangler Microsoft";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	public static final String OPTION_NAME_APPLY_SIGNATURE = "Apply Function Signatures";
	private static final String OPTION_DESCRIPTION_APPLY_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";

	public static final String OPTION_NAME_APPLY_CALLING_CONVENTION =
		"Apply Function Calling Conventions";
	private static final String OPTION_DESCRIPTION_APPLY_CALLING_CONVENTION =
		"Apply any recovered function signature calling convention";

	private static final String OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS =
		"Demangle Only Known Mangled Symbols";
	private static final String OPTION_DESCRIPTION_USE_KNOWN_PATTERNS =
		"Only demangle symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.";

	public static final String OPTION_NAME_MS_C_INTERPRETATION =
		"C-Style Symbol Interpretation";
	private static final String OPTION_DESCRIPTION_MS_C_INTERPRETATION =
		"When ambiguous, treat C-Style mangled symbol as: function, variable," +
			" or function if a function exists";

	private boolean applyFunctionSignature = true;
	private boolean applyCallingConvention = true;
	private boolean demangleOnlyKnownPatterns = false;
	private MsCInterpretation interpretation = MsCInterpretation.FUNCTION_IF_EXISTS;

	private static final String APPLY_OPTIONS_LABEL = "msdApplyOptions";
	private static final String OUTPUT_OPTIONS_LABEL = "msdOutputOptions";

	private MsdApplyOption applyOption;
	private MsdOutputOption outputOption;

	public MicrosoftDemanglerAnalyzer() {
		super(NAME, DESCRIPTION);
		demangler = new MicrosoftDemangler();
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return demangler.canDemangle(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation help = new HelpLocation("AutoAnalysisPlugin", "Demangler_Analyzer");

		options.registerOption(APPLY_OPTIONS_LABEL, OptionType.CUSTOM_TYPE,
			new MsdApplyOption(), help, "Configures how demangling is applied",
			() -> new MsdApplyOptionsEditor());
		applyOption =
			(MsdApplyOption) options.getCustomOption(APPLY_OPTIONS_LABEL, null);

		options.registerOption(OUTPUT_OPTIONS_LABEL, OptionType.CUSTOM_TYPE,
			new MsdOutputOption(), help, "Controls demangled output",
			() -> new MsdOutputOptionsEditor());
		outputOption = (MsdOutputOption) options.getCustomOption(OUTPUT_OPTIONS_LABEL, null);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		applyOption = (MsdApplyOption) options.getCustomOption(APPLY_OPTIONS_LABEL, applyOption);
		outputOption =
			(MsdOutputOption) options.getCustomOption(OUTPUT_OPTIONS_LABEL, outputOption);
	}

	@Override
	protected DemanglerOptions getOptions() {
		MicrosoftDemanglerOptions options = new MicrosoftDemanglerOptions();
		options.setApplySignature(applyOption.applySignature());
		options.setApplyCallingConvention(applyOption.applyCallingConvention());
		options.setDemangleOnlyKnownPatterns(applyOption.demangleOnlyKnownPatterns());
		options.setInterpretation(applyOption.getInterpretation());
		options.setUseEncodedAnonymousNamespace(outputOption.getUseEncodedAnonymousNamespace());
		options.setApplyUdtArgumentTypeTag(outputOption.getApplyUdtArgumentTypeTag());
		options.setErrorOnRemainingChars(true);
		return options;
	}

	@Override
	protected DemangledObject doDemangle(MangledContext context, MessageLog log)
			throws DemangledException {
		DemangledObject demangled = demangler.demangle(context);
		return demangled;
	}
}
