package version

// Version, GitCommit, and BuildTime are set via
// ldflags at build time.
//
// Example:
//
//	go build -ldflags "\
//	  -X github.com/oodle-ai/oodle-agent/pkg/version.Version=v0.1.0 \
//	  -X github.com/oodle-ai/oodle-agent/pkg/version.GitCommit=$(git rev-parse HEAD) \
//	  -X github.com/oodle-ai/oodle-agent/pkg/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	// Version is the semantic version of the agent.
	Version = "dev"
	// GitCommit is the git commit hash.
	GitCommit = "unknown"
	// BuildTime is the UTC build timestamp.
	BuildTime = "unknown"
)
