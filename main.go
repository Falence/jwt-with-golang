package main

import (
	"log"
	"encoding/json"

	"github.com/gin-gonic/gin"
)

var (
	router = gin.Default()
)

type User struct {
	ID uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Creating a sample user for use
var user = User{
	ID: 1,
	Username: "username",
	Password: "password",
}


func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}