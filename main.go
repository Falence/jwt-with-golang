package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"github.com/twinj/uuid"
)

var (
	router = gin.Default()
	client *redis.Client
)

type User struct {
	ID uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Phone string `json:"phone"`
}

type TokenDetails struct {
	AccessToken string
	RefreshToken string
	AccessUuid string
	RefreshUuid string
	AtExpires int64
	RtExpires int64
}

type Todo struct {
	UserID uint64 `json:"user_id"`
	Title string `json:"title"`
}

type AccessDetails struct {
	AccessUuid string
	UserId uint64
}


// Creating a sample user for use
var user = User{
	ID: 1,
	Username: "username",
	Password: "password",
	Phone: "680429978",
}


func main() {
	router.POST("/login", Login)
	router.POST("/todo", CreateTodo)
	router.POST("/logout", Logout)

	log.Fatal(router.Run(":8080"))
}

// HANDLERS
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

	ts, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	saveErr := CreateAuth(user.ID, ts)	// cache with redis
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	tokens := map[string]string{
		"access_token": ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)
}

func CreateTodo(c *gin.Context) {
	var td *Todo
	if err := c.ShouldBindJSON(&td); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json")
		return
	}

	tokenAuth, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "unauthorized")
		return
	}

	userId, err := FetchAuth(tokenAuth)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, "unauthorized")
		return
	}
	td.UserID = userId

	// You can proceed to save the Todo to a DB
	// but we will return it to the caller her:
	c.JSON(http.StatusCreated, td)
}

func Logout(c *gin.Context) {
	au, err := ExtractTokenMetadata(c.Request)
	if err != nil {
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	deleted, delErr := DeleteAuth(au.AccessUuid)
	if delErr != nil || deleted == 0 { // if any goes wrong
		c.JSON(http.StatusUnauthorized, "unauthorized")
		return
	}
	c.JSON(http.StatusOK, "Sucessfully logged out")
}


// Initializing Redis
func init() {
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn, // redis port
	})
	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

// Create Access Token and Refresh Token
func CreateToken(userid uint64) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = uuid.NewV4().String()

	var err error
	// Create the Access Token
	os.Setenv("ACCESS_SECRET", "my_super_secret")	// this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires	
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	// Creating the Refresh Token
	os.Setenv("REFRESH_SECRET", "my_super_refresh_secret")	// this should be in an env file
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}

	return td, nil
}

// Save JWTs metadata to Redis
func CreateAuth(userid uint64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0)	// converts Unix to UTC
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(td.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(td.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Make sure that the token method conforms to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

// Extract metadata from token so as to look it up in Redis
func ExtractTokenMetadata(r *http.Request) (*AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails {
			AccessUuid: accessUuid,
			UserId: userId,
		}, nil
	}
	return nil, err
}

// Lookup the token metadata in Redis and fetch the data
func FetchAuth(authD *AccessDetails) (uint64, error) {
	userid, err := client.Get(authD.AccessUuid).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseUint(userid, 10, 64)
	return userID, nil
}

// Delete JWT metadata from redis store
func DeleteAuth(givenUuid string) (int64, error) {
	deleted, err := client.Del(givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}


