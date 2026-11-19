package main

import (
	"context"
	"os"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/source/directorysource"
	_ "modernc.org/sqlite"
)

func main() {
	src, err := directorysource.NewFromPath(os.Args[1])
	if err != nil {
		panic(err)
	}
	s, err := syft.CreateSBOM(context.Background(), src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		panic(err)
	}
	enc, _ := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
	b, err := format.Encode(*s, enc)
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(b)
}
