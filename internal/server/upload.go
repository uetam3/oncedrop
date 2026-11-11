package server

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
)

var errTooLarge = errors.New("file exceeds -max-size")

type upload struct {
	Name, Type string
	Data       []byte
	TTLSec     string
}

// readUpload parses a multipart body entirely in memory. It deliberately
// avoids ParseMultipartForm, which spills large parts to temp files and would
// put the plaintext on disk.
func readUpload(r *http.Request, maxSize int64) (upload, error) {
	var u upload
	mr, err := r.MultipartReader()
	if err != nil {
		return u, err
	}
	gotFile := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return u, errTooLarge
			}
			return u, err
		}
		switch part.FormName() {
		case "file":
			if gotFile {
				return u, errors.New("more than one file field")
			}
			gotFile = true
			data, err := io.ReadAll(io.LimitReader(part, maxSize+1))
			if err != nil {
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					return u, errTooLarge
				}
				return u, err
			}
			if int64(len(data)) > maxSize {
				return u, errTooLarge
			}
			u.Data = data
			u.Name = filepath.Base(part.FileName())
			u.Type = part.Header.Get("Content-Type")
			if u.Type == "" || u.Type == "application/octet-stream" {
				if guess := mime.TypeByExtension(filepath.Ext(u.Name)); guess != "" {
					u.Type = guess
				}
			}
		case "ttlSec":
			b, _ := io.ReadAll(io.LimitReader(part, 32))
			u.TTLSec = string(b)
		default:
			_, _ = io.Copy(io.Discard, part)
		}
	}
	if !gotFile {
		return u, errors.New("missing file field")
	}
	return u, nil
}
