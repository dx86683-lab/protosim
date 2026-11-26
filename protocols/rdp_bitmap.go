package protocols

import (
	"bytes"
	"encoding/binary"
	"image"
	"io"
	"os"
	"path/filepath"

	"github.com/disintegration/imaging"

	"github.com/dx86683-lab/protosim/protocols/internal/rdpjpeg"
)

const (
	rdpDefaultImage    = "rdp.jpg"
	rdpUploadDirectory = "upload"
	rdpImageByteLimit  = 16 << 20
	rdpImagePixelLimit = 32 << 20

	rdpDesktopWidth      = 1024
	rdpDesktopHeight     = 800
	rdpMaxImageWidth     = 1280
	rdpMaxImageHeight    = 1024
	rdpBitmapStripBudget = 8192

	rdpDataUpdate   = 2
	rdpUpdateBitmap = 1
)

// loadRDPDesktop returns a nil image without an error when the caller should
// send the default canvas. A decoding error suppresses the bitmap update.
func loadRDPDesktop(name string) (*image.NRGBA, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name {
		return nil, nil
	}
	root, err := os.OpenRoot(rdpUploadDirectory)
	if err != nil {
		return nil, nil
	}
	defer root.Close()
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > rdpImageByteLimit {
		return nil, nil
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, rdpImageByteLimit+1))
	if err != nil || len(data) > rdpImageByteLimit {
		return nil, nil
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if config.Width == 0 || config.Height == 0 || config.Width > rdpImagePixelLimit/config.Height {
		return nil, nil
	}
	var picture image.Image
	if format == "jpeg" {
		picture, err = rdpjpeg.Decode(bytes.NewReader(data))
	} else {
		picture, _, err = image.Decode(bytes.NewReader(data))
	}
	if err != nil {
		return nil, err
	}
	return imaging.Fit(picture, rdpMaxImageWidth, rdpMaxImageHeight, imaging.Lanczos), nil
}

func writeRDPDesktop(conn io.Writer, user uint16, keys *rdpStandardKeys, picture *image.NRGBA) error {
	width, height := rdpDesktopWidth, rdpDesktopHeight
	if picture != nil {
		width, height = picture.Bounds().Dx(), picture.Bounds().Dy()
	}
	// The destination describes only real pixels. The encoded row is
	// padded to four pixels and uses bottom-up 24-bit BGR.
	paddedWidth := (width + 3) &^ 3
	stride := 3 * paddedWidth
	rowsPerStrip := max(1, rdpBitmapStripBudget/(3*width))
	for top := 0; top < height; top += rowsPerStrip {
		rows := min(rowsPerStrip, height-top)
		pixels := make([]byte, stride*rows)
		if picture != nil {
			for row := 0; row < rows; row++ {
				sourceY := top + rows - 1 - row
				target := row * stride
				for x := 0; x < width; x++ {
					r, g, b, _ := picture.NRGBAAt(x, sourceY).RGBA()
					bgr := pixels[target+x*3:]
					bgr[0], bgr[1], bgr[2] = byte(b>>8), byte(g>>8), byte(r>>8)
				}
			}
		}
		fields := [...]uint16{
			rdpUpdateBitmap, 1, 0, uint16(top), uint16(width - 1), uint16(top + rows - 1),
			uint16(paddedWidth), uint16(rows), 24, 0, uint16(len(pixels)),
		}
		packet := make([]byte, 0, 2*len(fields)+len(pixels))
		for _, field := range fields {
			packet = binary.LittleEndian.AppendUint16(packet, field)
		}
		if err := writeRDPShareData(conn, user, keys, rdpDataUpdate, append(packet, pixels...)); err != nil {
			return err
		}
	}
	return nil
}
