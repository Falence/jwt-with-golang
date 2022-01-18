package main

import (
	// "encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var (
	router = gin.Default()
)

type User struct {
	ID uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Phone string `json:"phone"`
}

// Creating a sample user for use
var user = User{
	ID: 1,
	Username: "username",
	Password: "password",
	Phone: "680429978",
}


func Login(c *gin.Context) {
	var u User
	// Get JSON body and store in u
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	// Compare the user from the request with the one we defined
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}

	token, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func CreateToken(userid uint64) (string, error) {
	var err error
	// Set claims and secret
	os.Setenv("ACCESS_SECRET", "my_super_secret")	// this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	// Create the Access Token
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}


func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}