package main

const (
	ENTRY_EXPORT      = 0
	ENTRY_IMPORT      = 1
	PE_SIGNATURE      = 0x00004550
	DIRECTORY_ENTRIES = 16
)

type (
	ImgSectionHeader struct {
		Name                                       [8]byte
		VirtualSize, VirtualAddress                uint32
		SizeOfRawData, PointerToRawData            uint32
		PointerToRelocations, PointerToLinenumbers uint32

		NumberOfRelocations uint16
		NumberOfLinenumbers uint16
		Characteristics     uint32
	}

	ImgFileHeader struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	ImgDataDirectory struct {
		VirtualAddress uint32
		Size           uint32
	}

	ImgOptionalHeader64 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		ImageBase                   uint64
		SectionAlignment            uint32
		FileAlignment               uint32
		MajorOperatingSystemVersion uint16
		MinorOperatingSystemVersion uint16
		MajorImageVersion           uint16
		MinorImageVersion           uint16
		MajorSubsystemVersion       uint16
		MinorSubsystemVersion       uint16
		Win32VersionValue           uint32
		SizeOfImage                 uint32
		SizeOfHeaders               uint32
		CheckSum                    uint32
		Subsystem                   uint16
		DllCharacteristics          uint16
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               [DIRECTORY_ENTRIES]ImgDataDirectory
	}

	ImgNTHeaderS64 struct {
		Signature      uint32
		FileHeader     ImgFileHeader
		OptionalHeader ImgOptionalHeader64
	}

	ImgImportDescriptor struct {
		OriginalFirstThunk uint32
		TimeDateStamp      uint32
		ForwarderChain     uint32
		Name               uint32
		FirstThunk         uint32
	}

	ImgExportDirectory struct {
		Characteristics       uint32
		TimeDateStamp         uint32
		MajorVersion          uint16
		MinorVersion          uint16
		Name                  uint32
		Base                  uint32
		NumberOfFunctions     uint32
		NumberOfNames         uint32
		AddressOfFunctions    uint32
		AddressOfNames        uint32
		AddressOfNameOrdinals uint32
	}

	ImgThunkData64 struct {
		AddressOfData uint64 // variant of ForwarderString | Function | Ordinal | AddressOfData
	}
)
