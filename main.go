package main

import (
	"bytes"
	bin "encoding/binary"
	"errors"
	"fmt"
	"os"
)

func usage() {
	err := fmt.Errorf("Usage: pe-parser <is-pe | (import|export)-functions> <file.exe>")
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

func tellg(f *os.File) int64 {
	p, _ := f.Seek(0, 1)
	return p
}

func readInt(f *os.File) uint32 {
	var res uint32
	bin.Read(f, bin.NativeEndian, &res)
	return res
}

func checkPE(pe *os.File) bool {
	pe.Seek(0x3c, 0)
	ptr := int64(readInt(pe))
	pe.Seek(ptr, 0)
	return readInt(pe) == PE_SIGNATURE
}

func nextString(pe *os.File) string {
	var char = make([]byte, 1)
	var buffer bytes.Buffer
	for {
		if n, e := pe.Read(char); n != 1 || e != nil || char[0] == 0 {
			break
		}
		buffer.WriteByte(char[0])
	}
	return buffer.String()
}

// kind = ENTRY_IMPORT | ENTRY_EXPORT
func portTable(pe *os.File, kind int) (*ImgSectionHeader, error) {
	if kind != ENTRY_EXPORT && kind != ENTRY_IMPORT {
		return nil, errors.New("Wrong table tag")
	}

	var ntOffset uint32
	pe.Seek(0x3C, 0)
	bin.Read(pe, bin.NativeEndian, &ntOffset)
	pe.Seek(int64(ntOffset), 0)

	var ntHeaders64 ImgNTHeaderS64
	bin.Read(pe, bin.NativeEndian, &ntHeaders64)

	var importRVA uint32 = ntHeaders64.OptionalHeader.DataDirectory[kind].VirtualAddress
	var section ImgSectionHeader
	var importTable *ImgSectionHeader = nil

	bin.Read(pe, bin.NativeEndian, &section)

	for i := 0; i < int(ntHeaders64.FileHeader.NumberOfSections); i++ {
		if section.VirtualAddress <= importRVA &&
			importRVA < section.VirtualAddress+section.VirtualSize {
			importTable = &section
			break
		}
		bin.Read(pe, bin.NativeEndian, &section)
	}

	if importTable == nil {
		if kind == ENTRY_EXPORT {
			return nil, errors.New("export table not found (maybe not a .dll)")
		} else {
			return nil, errors.New("import table not found")
		}
	}

	pe.Seek(int64(importTable.PointerToRawData+
		ntHeaders64.OptionalHeader.DataDirectory[kind].VirtualAddress-importTable.VirtualAddress), 0)
	return importTable, nil
}

func importFuncs(pe *os.File) {
	importTable, e := portTable(pe, ENTRY_IMPORT)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}

	var impDesc ImgImportDescriptor
	bin.Read(pe, bin.NativeEndian, &impDesc)

	for impDesc.Name != 0 {
		posRec := tellg(pe)
		pe.Seek(int64(importTable.PointerToRawData+uint32(impDesc.Name)-importTable.VirtualAddress), 0)
		fmt.Println(nextString(pe))

		pe.Seek(int64(importTable.PointerToRawData+impDesc.OriginalFirstThunk-
			importTable.VirtualAddress), 0)
		var thunkData64 ImgThunkData64

		for bin.Read(pe, bin.NativeEndian, &thunkData64); thunkData64.AddressOfData != 0; bin.Read(pe, bin.NativeEndian, &thunkData64) {
			posThunk := tellg(pe)
			pe.Seek(int64(importTable.PointerToRawData)+
				int64(thunkData64.AddressOfData)-
				int64(importTable.VirtualAddress)+2, 0)

			fmt.Println("    " + nextString(pe))
			pe.Seek(posThunk, 0)
		}

		pe.Seek(posRec, 0)
		bin.Read(pe, bin.NativeEndian, &impDesc)
	}
}

func exportFuncs(pe *os.File) {
	exportTable, e := portTable(pe, ENTRY_EXPORT)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}

	var exportDir ImgExportDirectory
	bin.Read(pe, bin.NativeEndian, &exportDir)
	var name int32

	pe.Seek(int64(exportTable.PointerToRawData+exportDir.AddressOfNames-exportTable.VirtualAddress), 0)
	bin.Read(pe, bin.NativeEndian, &name)
	posRec := tellg(pe)

	for i := 0; i < int(exportDir.NumberOfNames); i++ {
		pe.Seek(int64(exportTable.PointerToRawData+uint32(name)-exportTable.VirtualAddress), 0)
		fmt.Println(nextString(pe))

		pe.Seek(posRec, 0)
		bin.Read(pe, bin.NativeEndian, &name)
		posRec = tellg(pe)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		usage()
		return
	}

	f, err := os.Open(args[1])
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer f.Close()

	switch args[0] {
	case "is-pe":
		if checkPE(f) {
			fmt.Println("PE")
		} else {
			fmt.Println("Not PE")
			os.Exit(1)
		}
	case "import-functions":
		importFuncs(f)
	case "export-functions":
		exportFuncs(f)
	default:
		usage()
	}
}
