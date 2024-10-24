import os
import pefile
import magic
import r2pipe
import lief
import csv

# Function to extract PE metadata
def extract_pe_metadata(file_path):
    try:
        pe = pefile.PE(file_path)
        metadata = {
            'file_size': os.path.getsize(file_path),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'machine': pe.FILE_HEADER.Machine,
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'image_base': pe.OPTIONAL_HEADER.ImageBase
        }
        return metadata
    except Exception as e:
        print(f"Error extracting PE metadata: {e}")
        return None

# Function to extract ELF metadata using lief
def extract_elf_metadata(file_path):
    try:
        elf = lief.parse(file_path)
        metadata = {
            'file_size': os.path.getsize(file_path),
            'entry_point': elf.header.entrypoint,
            'number_of_sections': len(elf.sections),
            'interpreter': elf.interpreter,
            'architecture': elf.header.machine_type.name
        }
        return metadata
    except Exception as e:
        print(f"Error extracting ELF metadata: {e}")
        return None

# Function to extract strings
def extract_strings(file_path):
    try:
        strings = os.popen(f"strings {file_path}").read().splitlines()
        return strings
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return None

# Function to extract imported functions from PE files
def extract_pe_imports(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imports.append(imp.name)
        return imports
    except Exception as e:
        print(f"Error extracting PE imports: {e}")
        return None

# Function to extract imported functions (Dynamic Symbols) from ELF
def extract_elf_imports(file_path):
    try:
        elf = lief.parse(file_path)
        imports = [symbol.name for symbol in elf.dynamic_symbols if symbol.imported]
        return imports
    except Exception as e:
        print(f"Error extracting ELF imports: {e}")
        return None

# Function to extract sections for PE files
def extract_pe_sections(file_path):
    try:
        pe = pefile.PE(file_path)
        sections = {section.Name.decode().strip(): section.SizeOfRawData for section in pe.sections}
        return sections
    except Exception as e:
        print(f"Error extracting PE sections: {e}")
        return None

# Function to extract sections for ELF files
def extract_elf_sections(file_path):
    try:
        elf = lief.parse(file_path)
        sections = {section.name: section.size for section in elf.sections}
        return sections
    except Exception as e:
        print(f"Error extracting ELF sections: {e}")
        return None

# Function to extract control flow graphs using Radare2
def extract_cfg(file_path):
    try:
        r2 = r2pipe.open(file_path)
        r2.cmd('aaa')  # Analyze all
        cfg = r2.cmdj('agj')  # Get control flow graph in JSON
        r2.quit()
        return cfg
    except Exception as e:
        print(f"Error extracting control flow graph: {e}")
        return None

# Function to extract resources (e.g., icons, dialogs) for PE and ELF files
def extract_resources(file_path):
    try:
        binary = lief.parse(file_path)
        resources = binary.resources
        return resources if resources else None
    except Exception as e:
        print(f"Error extracting resources: {e}")
        return None

# Function to save extracted features to a CSV
def save_to_csv(features, output_file):
    keys = features.keys()
    with open(output_file, 'w', newline='') as output_csv:
        dict_writer = csv.DictWriter(output_csv, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerow(features)

# Main function to analyze a single file and handle ELF or PE formats
def analyze_file(file_path):
    file_features = {}

    # Identify file type
    try:
        file_type = magic.from_file(file_path)
        file_features['file_type'] = file_type
        print(f"File type: {file_type}")
    except Exception as e:
        print(f"Error identifying file type: {e}")
        return None

    # Check if it's an ELF file
    if "ELF" in file_type:
        print("ELF file detected, extracting ELF-specific metadata.")
        elf_metadata = extract_elf_metadata(file_path)
        if elf_metadata:
            file_features.update(elf_metadata)
            print(f"ELF Metadata: {elf_metadata}")

        elf_sections = extract_elf_sections(file_path)
        if elf_sections:
            file_features['sections'] = elf_sections
            print(f"Sections: {elf_sections}")

        elf_imports = extract_elf_imports(file_path)
        if elf_imports:
            file_features['imports'] = ";".join(elf_imports)
            print(f"Imports: {elf_imports}")

    # Add PE extraction logic for PE files
    elif "PE32" in file_type or "PE32+" in file_type:
        print("PE file detected, extracting PE-specific metadata.")
        pe_metadata = extract_pe_metadata(file_path)
        if pe_metadata:
            file_features.update(pe_metadata)
            print(f"PE Metadata: {pe_metadata}")

        pe_sections = extract_pe_sections(file_path)
        if pe_sections:
            file_features['sections'] = pe_sections
            print(f"Sections: {pe_sections}")

        pe_imports = extract_pe_imports(file_path)
        if pe_imports:
            file_features['imports'] = ";".join(pe_imports)
            print(f"Imports: {pe_imports}")

    # Extract common features
    strings = extract_strings(file_path)
    if strings:
        file_features['strings'] = ";".join(strings[:10])  # First 10 strings for testing
        print(f"Strings: {strings[:10]}")

    cfg = extract_cfg(file_path)
    if cfg:
        file_features['cfg'] = cfg
        print(f"Control Flow Graph: {cfg}")

    resources = extract_resources(file_path)
    if resources:
        file_features['resources'] = resources
        print(f"Resources: {resources}")

    return file_features

# Example usage
file_path = r"C:\Users\ukasha\Desktop\static analysis\01.exe"
output_file = "file_features.csv"
features = analyze_file(file_path)

if features:
    save_to_csv(features, output_file)
    print(f"Features saved to {output_file}")
else:
    print("No features to save.")
