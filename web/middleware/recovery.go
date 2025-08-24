package middleware

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// RecoveryJSON перехватывает панику, логирует всё нужное и отдаёт JSON 500.
// Ничего лишнего клиенту не раскрывает.
func RecoveryJSON() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		defer func() {
			if rec := recover(); rec != nil {
				// Нормализуем recovered в error
				var err error
				switch v := rec.(type) {
				case error:
					err = v
				default:
					err = fmt.Errorf("%v", v)
				}

				// Определим "сломанное соединение": писать ответ уже нельзя
				brokenPipe := isBrokenPipe(err)

				// Безопасный дамп запроса (без body, с редактированием секретов)
				reqDump := dumpRequestSafe(c.Request)

				// Стек для логов
				stack := debug.Stack()

				log.Printf("[PANIC] %s | %s %s | brokenPipe=%t | err=%v\nRequest:\n%s\nStack:\n%s",
					time.Since(start), c.Request.Method, c.Request.URL.String(),
					brokenPipe, err, reqDump, stack,
				)

				if brokenPipe {
					// Ничего не пишем в ответ — соединение уже мёртвое
					_ = c.Error(err)
					c.Abort()
					return
				}

				// Коррелируем по X-Request-ID, если есть
				reqID := c.GetHeader("X-Request-ID")

				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":     "internal_error",
					"message":   "Something went wrong",
					"requestId": reqID,
				})
			}
		}()

		c.Next()
	}
}

func dumpRequestSafe(r *http.Request) string {
	// Клонируем заголовки и редактируем чувствительные
	redacted := r.Header.Clone()
	for _, h := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Api-Key", "X-Auth-Token",
	} {
		if redacted.Get(h) != "" {
			redacted.Set(h, "***REDACTED***")
		}
	}

	// Поверхностная копия запроса с отредактированными заголовками
	r2 := new(http.Request)
	*r2 = *r
	r2.Header = redacted

	// Body намеренно не читаем — это может сломать хендлеры ниже по цепочке
	dump, err := httputil.DumpRequest(r2, false)
	if err != nil {
		return fmt.Sprintf("could not dump request: %v", err)
	}
	return strings.TrimSpace(string(dump))
}

func isBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	// Чаще всего прячется внутри *net.OpError; универсальная проверка по сообщению
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Err != nil {
			s := strings.ToLower(ne.Err.Error())
			return strings.Contains(s, "broken pipe") ||
				strings.Contains(s, "connection reset by peer")
		}
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset by peer")
}
