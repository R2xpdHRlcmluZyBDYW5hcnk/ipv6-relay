package relay

import (
	"fmt"
	"log/syslog"
	"os"
)

// syslog priority levels (subset of RFC 5424 / <syslog.h>)
const (
	LogEmerg   = 0
	LogAlert   = 1
	LogCrit    = 2
	LogErr     = 3
	LogWarning = 4
	LogNotice  = 5
	LogInfo    = 6
	LogDebug   = 7
)

var (
	logLevel  = LogWarning
	logSyslog = true
	sysWriter *syslog.Writer
)

// SetLogLevel sets the minimum priority (0-7) that gets logged.
func SetLogLevel(level int) {
	logLevel = level & 0x7
}

func LogLevel() int { return logLevel }

// SetLogSyslog switches logging to syslog (true) or stderr (false).
func SetLogSyslog(toSyslog bool, tag string) error {
	logSyslog = toSyslog

	if !toSyslog {
		return nil
	}

	w, err := syslog.New(syslog.LOG_DAEMON, tag)
	if err != nil {
		return err
	}

	sysWriter = w
	return nil
}

func logf(level int, format string, args ...interface{}) {
	if level > logLevel {
		return
	}

	msg := fmt.Sprintf(format, args...)

	if logSyslog && sysWriter != nil {
		switch level {
		case LogEmerg:
			_ = sysWriter.Emerg(msg)
		case LogAlert:
			_ = sysWriter.Alert(msg)
		case LogCrit:
			_ = sysWriter.Crit(msg)
		case LogErr:
			_ = sysWriter.Err(msg)
		case LogWarning:
			_ = sysWriter.Warning(msg)
		case LogNotice:
			_ = sysWriter.Notice(msg)
		case LogInfo:
			_ = sysWriter.Info(msg)
		default:
			_ = sysWriter.Debug(msg)
		}
		return
	}

	fmt.Fprintln(os.Stderr, msg)
}

func Debugf(format string, args ...interface{})  { logf(LogDebug, format, args...) }
func Infof(format string, args ...interface{})   { logf(LogInfo, format, args...) }
func Noticef(format string, args ...interface{}) { logf(LogNotice, format, args...) }
func Warnf(format string, args ...interface{})   { logf(LogWarning, format, args...) }
func Errorf(format string, args ...interface{})  { logf(LogErr, format, args...) }
