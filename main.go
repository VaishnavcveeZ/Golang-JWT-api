package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var jwtKey = []byte("myJWTkeYfOraUTh")
var key = []byte("jwtEncryptionKey") //16 charector string

type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name     string             `json:"Name,omitempty" bson:"Name,omitempty"`
	Email    string             `json:"Email,omitempty" bson:"Email,omitempty"`
	Password string             `json:"Password,omitempty" bson:"Password,omitempty"`
}

type UserStatus struct {
	User
	Status string `json:"Status,omitempty" bson:"Status,omitempty"`
}

func main() {
	fmt.Println("Server Started--=>")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))

	router := mux.NewRouter()

	router.HandleFunc("/api/getTest", loginCheck).Methods("GET")
	router.HandleFunc("/api/login", login).Methods("POST")
	router.HandleFunc("/api/signup", signup).Methods("POST")
	router.HandleFunc("/api/logout", logout).Methods("POST")
	corsDomain := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
	})

	handler := corsDomain.Handler(router)

	http.Handle("/", router)
	http.ListenAndServe(":2000", handler)
}

func encrypt(text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.URLEncoding.EncodeToString(ciphertext)
}
func decrypt(cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func test(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	response.Header().Add("content-type", "application/json")
	var test UserStatus
	test.Email = "abc@m.c"
	test.Name = "ABCD"
	test.Password = "12345"
	test.Status = "ok"
	json.NewEncoder(response).Encode(test)
	return
}

type Claims struct {
	User
	jwt.StandardClaims
}

func loginCheck(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	response.Header().Add("content-type", "application/json")
	cookie, err := request.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("no cookie")
			fmt.Fprint(response, "No Cookie")
			return
		} else {
			fmt.Println("diff err")
			fmt.Fprint(response, "Diff err")
			return
		}
	}
	tokenString := decrypt(cookie.Value)
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		response.WriteHeader(http.StatusUnauthorized)
		return
	}

	json.NewEncoder(response).Encode(claims)
	return
}

func login(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	response.Header().Add("content-type", "application/json")
	var user User
	var data UserStatus
	json.NewDecoder(request.Body).Decode(&data)

	collectionUser := client.Database("GoReact").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err := collectionUser.FindOne(ctx, User{Email: data.Email}).Decode(&user)
	if err != nil {
		data.Status = "nil"
	} else {
		data.ID = user.ID
		data.Name = user.Name
		data.Status = "ok"
	}
	//fmt.Println("user = ", user)
	//fmt.Println("data = ", data)
	expireTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		User: user,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expireTime.Unix()},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	fmt.Println(tokenString)

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name:     "token",
		Value:    encrypt(tokenString),
		Expires:  expireTime,
		HttpOnly: true,
	})

	json.NewEncoder(response).Encode("login Susccesful & cookie is set")
	return
}
func logout(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	response.Header().Add("content-type", "application/json")
	http.SetCookie(response, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Minute * 5),
		HttpOnly: true,
	})
	return
}
func signup(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Access-Control-Allow-Origin", "*")
	response.Header().Add("content-type", "application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	collectionUser := client.Database("GoReact").Collection("user")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	status, err := collectionUser.InsertOne(ctx, user)
	fmt.Println("status= ", status, "err = ", err)
	return

}
