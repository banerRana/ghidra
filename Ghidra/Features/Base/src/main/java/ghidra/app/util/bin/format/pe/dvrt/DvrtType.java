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
package ghidra.app.util.bin.format.pe.dvrt;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Defined symbol dynamic relocation entries
 */
public enum DvrtType implements StructConverter {

	IMAGE_DYNAMIC_RELOCATION_GUARD_RF_PROLOGUE(0x1),
	IMAGE_DYNAMIC_RELOCATION_GUARD_RF_EPILOGUE(0x2),
	IMAGE_DYNAMIC_RELOCATION_IMPORT_CONTROL_TRANSFER(0x3),
	IMAGE_DYNAMIC_RELOCATION_INDIR_CONTROL_TRANSFER(0x4),
	IMAGE_DYNAMIC_RELOCATION_SWITCHABLE_BRANCH(0x5),
	IMAGE_DYNAMIC_RELOCATION_ARM64X(0x6),
	IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE(0x7),
	IMAGE_DYNAMIC_RELOCATION_ARM64_KERNEL_IMPORT_CALL_TRANSFER(0x8);
	
	private long value;

	/**
	 * Creates a new {@link DvrtType}
	 * 
	 * @param value The defined value of the type
	 */
	private DvrtType(int value) {
		this.value = value;
	}

	/**
	 * {@return the type's defined value}
	 */
	public long getValue() {
		return value;
	}
	
	/**
	 * Reads a {@link DvrtType}
	 * 
	 * @param reader A {@link BinaryReader} that points to the start of the type value
	 * @return The type that was read, or {@code null} if the value read does not correspond to a
	 *   valid type
	 * @throws IOException if there was an IO-related error
	 */
	public static DvrtType type(BinaryReader reader) throws IOException {
		long value = reader.readNextLong();
		return Arrays.stream(DvrtType.values())
				.filter(e -> value == e.getValue())
				.findFirst()
				.orElse(null);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		EnumDataType enumDt = new EnumDataType("DvrtType", 8);
		Arrays.stream(values()).forEach(e -> enumDt.add(e.name(), e.getValue()));
		enumDt.setCategoryPath(new CategoryPath("/PE"));
		return enumDt;
	}
}
