package protocols

import (
	"image"
	"image/color"
	"os"
	"path/filepath"
	"testing"
)

func TestRDPDesktopJPEGReferencePixels(t *testing.T) {
	data, err := os.ReadFile("fixtures/rdp-jpeg-5x2.jpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.Mkdir(rdpUploadDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	const name = "rdp-test.jpg"
	if err := os.WriteFile(filepath.Join(rdpUploadDirectory, name), data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := loadRDPDesktop(name)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Bounds() != image.Rect(0, 0, 5, 2) {
		t.Fatal("could not load the 5 by 2 desktop image")
	}
	want := color.NRGBA{R: 0xb5, G: 0x14, B: 0x10, A: 0xff}
	if got := result.NRGBAAt(4, 0); got != want {
		t.Fatalf("JPEG pixel (4, 0) = %v, want reference %v", got, want)
	}
}

func TestRDPDesktopImageDecodeFailure(t *testing.T) {
	jpeg, err := os.ReadFile("fixtures/rdp-jpeg-5x2.jpg")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.Mkdir(rdpUploadDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if result, err := loadRDPDesktop("missing.jpg"); result != nil || err != nil {
		t.Fatalf("missing desktop should use the default canvas, got %v, %v", result, err)
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"unknown-format.jpg", []byte("invalid fixture image")},
		{"truncated.jpg", jpeg[:len(jpeg)-32]},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(rdpUploadDirectory, test.name), test.data, 0600); err != nil {
				t.Fatal(err)
			}
			if result, err := loadRDPDesktop(test.name); result != nil || err == nil {
				t.Fatalf("expected a desktop decode error, got %v, %v", result, err)
			}
		})
	}
}
