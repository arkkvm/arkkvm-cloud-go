// Package handler holds the per-domain HTTP handlers. BaseResult helpers
// live here alongside them (the router layer stays free of response shaping).
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BaseResult is the response envelope of every JSON endpoint. Field names and
// the unusual code semantics (1 = success, 0 = business failure, 500 =
// unhandled error; business failures ride on HTTP 200) replicate the legacy
// vo.BaseResult exactly.
type BaseResult[T any] struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    T      `json:"data"`
}

func OK[T any](c *gin.Context, data T) {
	c.JSON(http.StatusOK, BaseResult[T]{Success: true, Message: "", Code: 1, Data: data})
}

func OKEmpty(c *gin.Context) {
	c.JSON(http.StatusOK, BaseResult[any]{Success: true, Message: "", Code: 1})
}

func Fail(c *gin.Context, message string) {
	c.JSON(http.StatusOK, BaseResult[any]{Success: false, Message: message, Code: 0})
}

// FailCode is the global-exception-handler equivalent: HTTP 200 with a
// non-zero error code (500 for unhandled errors, matching the legacy advice
// handler that mapped Exception -> BaseResult.fail(500, ex.getMessage)).
func FailCode(c *gin.Context, code int, message string) {
	c.JSON(http.StatusOK, BaseResult[any]{Success: false, Message: message, Code: code})
}

// exposeSensitive toggles sensitive-field stripping (config wiring).
var exposeSensitive = false

// SetExposeSensitive configures sensitive-field stripping globally.
func SetExposeSensitive(v bool) { exposeSensitive = v }
