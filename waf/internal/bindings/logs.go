// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build !sqreen_nowaf
// +build !windows
// +build amd64
// +build linux darwin

package bindings

// #include "waf.h"
// extern void goOnLogMessage(PW_LOG_LEVEL level, const char *function, const char *file, int line, const char *message, size_t message_len);
// void onLogMessage(PW_LOG_LEVEL level, const char *function, const char *file, int line, const char *message, size_t message_len) {
//	 	goOnLogMessage(level, function, file, line, message, message_len);
// }
import "C"
