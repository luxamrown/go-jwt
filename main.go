package main

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

type Credential struct {
	Username string
	Password string
}

func AuthTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/login" {
			c.Next()
		} else {
			h := AuthHeader{}
			err := c.ShouldBindHeader(&h)
			if err != nil {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}

			if h.AuthorizationHeader == "112233" {
				c.Next()
			} else {
				c.JSON(401, gin.H{
					"message": "Unauthorized",
				})
				c.Abort()
			}
		}
	}
}

func main() {
	r := gin.Default()
	r.Use(AuthTokenMiddleware())
	r.POST("/login", func(c *gin.Context) {
		var user Credential
		err := c.BindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "cant bind json",
			})
			return
		}

		if user.Username == "test" && user.Password == "testadmin" {
			c.JSON(200, gin.H{
				"token": "123",
			})
		} else {
			c.JSON(401, gin.H{
				"message": "Unauthorized",
			})
			c.AbortWithStatus(401)
		}
	})

	r.GET("/customer", func(c *gin.Context) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		body := buf.String()
		if body != "" {
			c.AbortWithStatus(401)
			c.JSON(401, gin.H{
				"message": "cannot with body",
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "customer",
		})
	})

	r.GET("/product", func(c *gin.Context) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		body := buf.String()
		if body != "" {
			c.AbortWithStatus(401)
			c.JSON(401, gin.H{
				"message": "cannot with body",
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "product",
		})
	})

	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
