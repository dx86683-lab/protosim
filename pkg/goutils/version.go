package goutils

import (
	"github.com/hashicorp/go-version"
	"strings"
)

/*
VersionBetween("5.2.2", ">= 5.1.0, < 5.1.63; >= 5.5.0, < 5.5.24")
多个用分号分割
*/
func VersionBetween(versionStr string, compareVersions string) bool {
	versionForTest, err := version.NewVersion(versionStr)
	if err != nil {
		return false
	}
	versions := strings.Split(compareVersions, ";")
	for _, ver := range versions {
		if len(ver) == 0 {
			continue
		}
		constraints, err := version.NewConstraint(ver)
		if err != nil {
			continue
		}
		if constraints.Check(versionForTest) {
			return true
		}
	}

	return false
}
