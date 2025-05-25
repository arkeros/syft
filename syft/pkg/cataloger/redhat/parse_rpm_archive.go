package redhat

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pgpSig struct {
	_          [3]byte
	Date       int32
	KeyID      [8]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
}

type textSig struct {
	_          [2]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
	_          [4]byte
	Date       int32
	_          [4]byte
	KeyID      [8]byte
}

type pgp4Sig struct {
	_          [2]byte
	PubKeyAlgo uint8
	HashAlgo   uint8
	_          [17]byte
	KeyID      [8]byte
	_          [2]byte
	Date       int32
}

var pubKeyLookup = map[uint8]string{
	0x01: "RSA",
}
var hashLookup = map[uint8]string{
	0x02: "SHA1",
	0x08: "SHA256",
}

// parseRpmArchive parses a single RPM
func parseRpmArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, fmt.Errorf("RPM archive parsing is disabled: go-rpmutils dependency removed from %s", reader.RealPath)
}

func parseSignatureHeaders(data [][]byte) ([]pkg.RpmSignature, error) {
	sigMap := make(map[string]pkg.RpmSignature)
	var keys []string
	for _, sig := range data {
		if len(sig) == 0 {
			continue
		}
		s, err := parsePGP(sig)
		if err != nil {
			log.WithFields("error", err).Trace("unable to parse RPM archive signature")
			return nil, err
		}
		k := s.String()
		if _, ok := sigMap[k]; ok {
			// if we have a duplicate signature, just skip it
			continue
		}
		sigMap[k] = *s
		keys = append(keys, k)
	}
	var signatures []pkg.RpmSignature
	sort.Strings(keys)
	for _, k := range keys {
		signatures = append(signatures, sigMap[k])
	}

	return signatures, nil
}

func parsePGP(data []byte) (*pkg.RpmSignature, error) {
	var tag, signatureType, version uint8

	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, &tag)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &signatureType)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.BigEndian, &version)
	if err != nil {
		return nil, err
	}

	switch signatureType {
	case 0x01:
		switch version {
		case 0x1c:
			sig := textSig{}
			err = binary.Read(r, binary.BigEndian, &sig)
			if err != nil {
				return nil, fmt.Errorf("invalid PGP signature on decode: %w", err)
			}
			return &pkg.RpmSignature{
				PublicKeyAlgorithm: pubKeyLookup[sig.PubKeyAlgo],
				HashAlgorithm:      hashLookup[sig.HashAlgo],
				Created:            time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006"),
				IssuerKeyID:        fmt.Sprintf("%x", sig.KeyID),
			}, nil
		default:
			return decodePGPSig(version, r)
		}
	case 0x02:
		return decodePGPSig(version, r)
	}

	return nil, fmt.Errorf("unknown signature type: %d", signatureType)
}

func decodePGPSig(version uint8, r io.Reader) (*pkg.RpmSignature, error) {
	var pubKeyAlgo, hashAlgo, pkgDate string
	var keyID [8]byte

	switch {
	case version > 0x15:
		sig := pgp4Sig{}
		err := binary.Read(r, binary.BigEndian, &sig)
		if err != nil {
			return nil, fmt.Errorf("invalid PGP v4 signature on decode: %w", err)
		}
		pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
		hashAlgo = hashLookup[sig.HashAlgo]
		pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
		keyID = sig.KeyID

	default:
		sig := pgpSig{}
		err := binary.Read(r, binary.BigEndian, &sig)
		if err != nil {
			return nil, fmt.Errorf("invalid PGP signature on decode: %w", err)
		}
		pubKeyAlgo = pubKeyLookup[sig.PubKeyAlgo]
		hashAlgo = hashLookup[sig.HashAlgo]
		pkgDate = time.Unix(int64(sig.Date), 0).UTC().Format("Mon Jan _2 15:04:05 2006")
		keyID = sig.KeyID
	}
	return &pkg.RpmSignature{
		PublicKeyAlgorithm: pubKeyAlgo,
		HashAlgorithm:      hashAlgo,
		Created:            pkgDate,
		IssuerKeyID:        fmt.Sprintf("%x", keyID),
	}, nil
}

func getDigestAlgorithm(location file.Location, header interface{}) string {
	// RPM archive parsing disabled - go-rpmutils dependency removed
	return ""
}

func mapFiles(files interface{}, digestAlgorithm string) []pkg.RpmFileRecord {
	// RPM archive parsing disabled - go-rpmutils dependency removed
	return nil
}

func parseEpoch(epoch string) *int {
	i, err := strconv.Atoi(epoch)
	if err != nil {
		return nil
	}
	return &i
}

func logRpmArchiveErr(location file.Location, operation string, err error) {
	if err != nil {
		log.WithFields("error", err, "operation", operation, "path", location.RealPath).Trace("unable to parse RPM archive")
	}
}
