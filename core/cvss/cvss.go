package cvss

import "strings"

func RemoteExploitable(vector string) bool {
	if vector == "" {
		return false
	}
	parts := strings.Split(vector, "/")
	var av, pr string
	for _, p := range parts {
		if strings.HasPrefix(p, "AV:") {
			av = strings.TrimPrefix(p, "AV:")
		}
		if strings.HasPrefix(p, "PR:") {
			pr = strings.TrimPrefix(p, "PR:")
		}
	}
	return av == "N" && pr == "N"
}

func Severity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Unknown"
	}
}

func SeverityRank(sev string) int {
	switch sev {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}
