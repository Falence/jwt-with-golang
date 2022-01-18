package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

var (
	router = gin.Default()
)

func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}