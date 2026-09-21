package winrm

import (
	"strings"
	"testing"
)

// A script that ran perfectly should not come back with stderr full of XML.
//
// PowerShell remoting serialises the progress stream as CLIXML and emits progress
// records for ordinary things — "Preparing modules for first use" fires on the first
// Get-CimInstance in a fresh session. Those arrive on stderr, so a successful run
// reported several hundred bytes of
//
//	#< CLIXML
//	<Objs Version="1.1.0.1" ...><Obj S="progress">...
//
// under a "[stderr]" heading. Observed on a real Windows Server 2025 host: the script
// exited 0, returned exactly the seven lines it was meant to, and every run still
// carried that block. An operator reading it cannot tell a clean run from a broken
// one, and a genuine warning would be buried in it.
func TestScriptsSilenceTheProgressStream(t *testing.T) {
	got := quietProgress("Get-CimInstance Win32_OperatingSystem")
	if !strings.HasPrefix(got, "$ProgressPreference = 'SilentlyContinue'\n") {
		t.Errorf("the progress stream is not silenced, so an ordinary run reports CLIXML "+
			"progress records as stderr:\n%s", got)
	}
	// The caller's script must survive intact — it is the thing being run.
	if !strings.HasSuffix(got, "Get-CimInstance Win32_OperatingSystem") {
		t.Errorf("the script was altered beyond the prefix:\n%s", got)
	}
	// One line added, so a reported error line number is off by exactly one and
	// predictably so.
	if n := strings.Count(got, "\n"); n != 1 {
		t.Errorf("expected exactly one added line, got %d", n)
	}
}
