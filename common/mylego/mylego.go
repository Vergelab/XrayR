package mylego

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

var defaultPath string

func New(certConf *CertConfig) (*LegoCMD, error) {
	// Set default path to configPath/cert
	var p = ""
	configPath := os.Getenv("XRAY_LOCATION_CONFIG")
	if configPath != "" {
		p = configPath
	} else if cwd, err := os.Getwd(); err == nil {
		p = cwd
	} else {
		p = "."
	}

	defaultPath = filepath.Join(p, "cert")
	lego := &LegoCMD{
		C:    certConf,
		path: defaultPath,
	}

	return lego, nil
}

func recoverAsError(r any) error {
	switch x := r.(type) {
	case string:
		return errors.New(x)
	case error:
		return x
	case *log.Entry:
		if x != nil && x.Message != "" {
			return errors.New(x.Message)
		}
		return errors.New("panic")
	default:
		return fmt.Errorf("unknown panic: %v", r)
	}
}

// setDNSEnv exports the provider variables and returns a function that
// removes them. A value that was already set is restored instead of deleted.
func (l *LegoCMD) setDNSEnv() func() {
	if l == nil || l.C == nil || len(l.C.DNSEnv) == 0 {
		return func() {}
	}
	type previous struct {
		key     string
		val     string
		existed bool
	}
	saved := make([]previous, 0, len(l.C.DNSEnv))
	for key, value := range l.C.DNSEnv {
		k := strings.ToUpper(key)
		old, existed := os.LookupEnv(k)
		saved = append(saved, previous{key: k, val: old, existed: existed})
		_ = os.Setenv(k, value)
	}
	return func() {
		for _, item := range saved {
			if item.existed {
				_ = os.Setenv(item.key, item.val)
			} else {
				_ = os.Unsetenv(item.key)
			}
		}
	}
}

// DNSCert cert a domain using DNS API
func (l *LegoCMD) DNSCert() (CertPath string, KeyPath string, err error) {
	defer func() {
		if r := recover(); r != nil {
			CertPath, KeyPath = "", ""
			err = recoverAsError(r)
		}
	}()
	cleanup := l.setDNSEnv()
	defer cleanup()

	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return CertPath, KeyPath, err
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}
	return CertPath, KeyPath, nil
}

// HTTPCert cert a domain using http methods
func (l *LegoCMD) HTTPCert() (CertPath string, KeyPath string, err error) {
	defer func() {
		if r := recover(); r != nil {
			CertPath, KeyPath = "", ""
			err = recoverAsError(r)
		}
	}()

	// First check if the certificate exists
	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err == nil {
		return CertPath, KeyPath, err
	}

	err = l.Run()
	if err != nil {
		return "", "", err
	}

	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return "", "", err
	}

	return CertPath, KeyPath, nil
}

// RenewCert renew a domain cert
func (l *LegoCMD) RenewCert() (CertPath string, KeyPath string, ok bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			CertPath, KeyPath, ok = "", "", false
			err = recoverAsError(r)
		}
	}()

	ok, err = l.Renew()
	if err != nil {
		return
	}

	CertPath, KeyPath, err = checkCertFile(l.C.CertDomain)
	if err != nil {
		return
	}

	return
}

func checkCertFile(domain string) (string, string, error) {
	keyPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.key", domain))
	certPath := path.Join(defaultPath, "certificates", fmt.Sprintf("%s.crt", domain))
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert key failed: %s", domain)
	}
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("cert cert failed: %s", domain)
	}
	absKeyPath, _ := filepath.Abs(keyPath)
	absCertPath, _ := filepath.Abs(certPath)
	return absCertPath, absKeyPath, nil
}
