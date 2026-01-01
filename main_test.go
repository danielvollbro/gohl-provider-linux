package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyze_SecureSystem(t *testing.T) {
	tempDir := t.TempDir()

	secureSSH := `
# This is a test config
PermitRootLogin no
PasswordAuthentication no
`
	secureIPFwd := "0"

	sshPath := filepath.Join(tempDir, "sshd_config")
	ipPath := filepath.Join(tempDir, "ip_forward")

	if err := os.WriteFile(sshPath, []byte(secureSSH), 0644); err != nil {
		t.Fatalf("Failed to create temp ssh file: %v", err)
	}
	if err := os.WriteFile(ipPath, []byte(secureIPFwd), 0644); err != nil {
		t.Fatalf("Failed to create temp ip file: %v", err)
	}

	p := &LinuxProvider{
		SSHConfigPath: sshPath,
		IPForwardPath: ipPath,
	}

	report, err := p.Analyze(context.Background(), nil)
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}

	if len(report.Checks) != 3 {
		t.Errorf("Expected 3 checks, got %d", len(report.Checks))
	}

	for _, check := range report.Checks {
		if !check.Passed {
			t.Errorf("Check %s failed unexpectedly (Score: %d/%d)", check.ID, check.Score, check.MaxScore)
		}
		if check.Score != check.MaxScore {
			t.Errorf("Check %s did not give max score", check.ID)
		}
	}
}

func TestAnalyze_InsecureSystem(t *testing.T) {
	tempDir := t.TempDir()

	insecureSSH := `
PermitRootLogin yes
PasswordAuthentication yes
`
	insecureIPFwd := "1"

	sshPath := filepath.Join(tempDir, "sshd_config")
	ipPath := filepath.Join(tempDir, "ip_forward")

	os.WriteFile(sshPath, []byte(insecureSSH), 0644)
	os.WriteFile(ipPath, []byte(insecureIPFwd), 0644)

	p := &LinuxProvider{
		SSHConfigPath: sshPath,
		IPForwardPath: ipPath,
	}

	report, _ := p.Analyze(context.Background(), nil)

	for _, check := range report.Checks {
		if check.Passed {
			t.Errorf("Check %s passed unexpectedly on insecure config", check.ID)
		}
		if check.Score != 0 {
			t.Errorf("Check %s gave score %d, expected 0", check.ID, check.Score)
		}
	}
}

func TestAnalyze_MissingFiles(t *testing.T) {
	p := &LinuxProvider{
		SSHConfigPath: "/path/to/nowhere/config",
		IPForwardPath: "/path/to/nowhere/ip",
	}

	report, _ := p.Analyze(context.Background(), nil)

	foundReadError := false
	for _, check := range report.Checks {
		if check.ID == "LNX-SSH-READ" {
			foundReadError = true
			if check.Passed {
				t.Error("Read check passed, but file should be missing")
			}
		}
	}

	if !foundReadError {
		t.Error("Did not find LNX-SSH-READ check when file was missing")
	}
}
