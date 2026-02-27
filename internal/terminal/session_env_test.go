package terminal

import (
	"os"
	"strings"
	"testing"
)

func TestFilteredEnvRemovesSensitiveVars(t *testing.T) {
	// Set some sensitive vars for testing
	os.Setenv("TB_TOKEN", "secret")
	os.Setenv("AWS_SECRET_KEY", "secret")
	os.Setenv("DB_PASSWORD", "secret")
	os.Setenv("SAFE_VAR", "ok")
	defer func() {
		os.Unsetenv("TB_TOKEN")
		os.Unsetenv("AWS_SECRET_KEY")
		os.Unsetenv("DB_PASSWORD")
		os.Unsetenv("SAFE_VAR")
	}()

	env := filteredEnv()
	envMap := make(map[string]string)
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		envMap[k] = v
	}

	if _, ok := envMap["TB_TOKEN"]; ok {
		t.Error("TB_TOKEN should be filtered out")
	}
	if _, ok := envMap["AWS_SECRET_KEY"]; ok {
		t.Error("AWS_SECRET_KEY should be filtered out")
	}
	if _, ok := envMap["DB_PASSWORD"]; ok {
		t.Error("DB_PASSWORD should be filtered out")
	}
	if v, ok := envMap["SAFE_VAR"]; !ok || v != "ok" {
		t.Error("SAFE_VAR should be preserved")
	}
}
