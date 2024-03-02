package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//  integration tests

func TestUpdateUserIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/user", updateUser)

	testUserID := primitive.NewObjectID().Hex()

	updateData := map[string]string{
		"id":    testUserID,
		"name":  "Updated Name",
		"email": "updated@example.com",
	}
	updateDataJSON, _ := json.Marshal(updateData)
	req, _ := http.NewRequest("PUT", "/user", bytes.NewBuffer(updateDataJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "User updated successfully", response["message"])
}
