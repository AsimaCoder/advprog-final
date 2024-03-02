package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type MockDB struct{}

func (mdb *MockDB) InsertOne(ctx context.Context, user User) (*mongo.InsertOneResult, error) {
	return &mongo.InsertOneResult{InsertedID: primitive.NewObjectID()}, nil
}

func TestRegisterUserIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/register", registerUser)

	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password",
	}

	userJSON, _ := json.Marshal(user)
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, "User registered successfully", response["message"])
	assert.NotEmpty(t, response["userID"])
}
