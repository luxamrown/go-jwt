package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()

	type AuthHeader struct {
		AuthorizationHeader string `header:"Authorization"`
	}
	r.GET("/customer", func(c *gin.Context) {
		h := AuthHeader{}
		err := c.ShouldBindHeader(&h)
		if err != nil {
			c.JSON(401, gin.H{
				"message": "unauthorized",
			})
			return
		}
		if h.AuthorizationHeader == "112233" {
			c.JSON(200, gin.H{
				"message": "customer",
			})
			return
		}
		c.JSON(401, gin.H{
			"message": "unauthorized",
		})
	})
	err := r.Run("localhost:8888")
	if err != nil {
		panic(err)
	}
}
