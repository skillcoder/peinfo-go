package peinfo

import (
	// "bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	// "github.com/fullsailor/pkcs7"
	"go.mozilla.org/pkcs7"
	// Альтернативный источник пула корневых сертификатов для Windows
	"github.com/TheThingsNetwork/go-utils/roots"
)

const (
	WIN_CERT_REVISION_1_0 = 0x0100
	WIN_CERT_REVISION_2_0 = 0x0200

	WIN_CERT_TYPE_X509             = 0x0001
	WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
	WIN_CERT_TYPE_RESERVED_1       = 0x0003
	WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x0004
)

func readCert(fh *os.File, offset int64, size int64) (cert CertDetails, err error) {
	_, err = fh.Seek(int64(offset), os.SEEK_SET)
	if nil != err {
		return cert, err
	}

	var dwLength uint32
	err = binary.Read(fh, binary.LittleEndian, &dwLength)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("dwLength: %d\n", dwLength)

	var wRevision uint16
	err = binary.Read(fh, binary.LittleEndian, &wRevision)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("wRevision: %x\n", wRevision)

	var wCertificateType uint16
	err = binary.Read(fh, binary.LittleEndian, &wCertificateType)
	if nil != err {
		return cert, err
	}
	// fmt.Printf("wCertificateType: %x\n", wCertificateType)

	data := make([]byte, dwLength)
	_, err = fh.Read(data)
	if nil != err {
		return cert, err
	}

	c := CertDetails{
		Length:          dwLength,
		Revision:        wRevision,
		CertificateType: wCertificateType,
		DER:             data,
	}

	return c, nil
}

func (f *FileT) VerifyCert() (cert *x509.Certificate, verified bool, err error) {
	idd := f.FindDataDirectory(pe.IMAGE_DIRECTORY_ENTRY_SECURITY)
	if f.Verbose {
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY virtual address: %d\n", idd.VirtualAddress)
		fmt.Printf("IMAGE_DIRECTORY_ENTRY_SECURITY size: %d\n", idd.Size)
	}

	c, err := readCert(f.OSFile, int64(idd.VirtualAddress), int64(idd.Size))
	if nil != err {
		err = fmt.Errorf("readCert failed: %s", err)
		return nil, false, err
	}

	if c.CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
		return nil, false, fmt.Errorf("only pkcs certificates supported (cert type = %d)", c.CertificateType)
	}

	if f.ExtractCert {
		f, _ := os.Create(fmt.Sprintf("%s.cer", f.FileName))
		defer f.Close()
		_, _ = f.Write(c.DER)
	}

	p7, err := pkcs7.Parse(c.DER)
	if nil != err {
		return nil, false, err
	}

	cert = p7.GetOnlySigner()

	// cp := x509.NewCertPool()
	var cp *x509.CertPool
	if runtime.GOOS == "windows" {
		cp = roots.MozillaRootCAs
	} else {
		cp, err = x509.SystemCertPool()
		if nil != err {
			return nil, false, err
		}
	}

	err = p7.VerifyWithChain(cp)
	if err == nil {
		verified = true
	}

	return cert, verified, err
}

// https://golang.org/src/crypto/x509/root_windows.go:244
// SystemCertPool загружает сертификаты из виндового хранилища (вероятно) Не возвращает сейчас.
func SystemCertPool() {
	storeHandle, err := syscall.CertOpenSystemStore(0, syscall.StringToUTF16Ptr("Root"))
	if err != nil {
		fmt.Println(syscall.GetLastError())
	}

	const CRYPT_E_NOT_FOUND = 0x80092004

	var certs []*x509.Certificate
	var cert *syscall.CertContext
	for {
		cert, err = syscall.CertEnumCertificatesInStore(storeHandle, cert)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok {
				if errno == CRYPT_E_NOT_FOUND {
					break
				}
			}
			fmt.Println(syscall.GetLastError())
		}
		if cert == nil {
			break
		}
		// Copy the buf, since ParseCertificate does not create its own copy.
		buf := (*[1 << 20]byte)(unsafe.Pointer(cert.EncodedCert))[:]
		buf2 := make([]byte, cert.Length)
		copy(buf2, buf)
		if c, err := x509.ParseCertificate(buf2); err == nil {
			certs = append(certs, c)
		}
	}
}
