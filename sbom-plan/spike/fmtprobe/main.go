package main

import (
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
)

func main() {
	bom := cdx.NewBOM()
	_ = cdx.NewBOMEncoder(os.Stdout, cdx.BOMFileFormatJSON).Encode(bom)
	_ = spdxjson.Write(&spdx.Document{}, os.Stdout)
}
