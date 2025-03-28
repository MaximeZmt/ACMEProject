package logger

import (
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// logOutput is the logger configuration
	logOutput = zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		FormatCaller: func(i interface{}) string {
			return filepath.Base(fmt.Sprintf("%s", i))
		},
	}
)

// Logger method to unify logging in the whole project.
func Logger() *zerolog.Logger {
	// De
	defaultLogLevel := zerolog.TraceLevel

	// If GOLOG env variable is set to no, it disables the log
	if strings.TrimSpace(os.Getenv("GOLOG")) == "no" {
		defaultLogLevel = zerolog.Disabled
	}

	logger := zerolog.New(logOutput).
		Level(defaultLogLevel).
		With().Timestamp().Logger().
		With().Caller().Logger()
	return &logger
}
