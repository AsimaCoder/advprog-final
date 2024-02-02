package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	mongoURI        = "mongodb://localhost:27017"
	databaseName    = "furnitureShopDB"
	collectionName  = "users"
	collectionName2 = "furniture"
)

var client *mongo.Client
var database *mongo.Database
var logger = logrus.New()
var limiter = rate.NewLimiter(1, 3)

type Picture struct {
	Large  string `json:"large" bson:"large"`
	Big    string `json:"big" bson:"big"`
	Medium string `json:"medium" bson:"medium"`
	Small  string `json:"small" bson:"small"`
}

type Furniture struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	Price       float64            `json:"price" bson:"price"`
	Pictures    []Picture          `json:"pictures" bson:"pictures"`
}

type User struct {
	ID       primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name     string             `json:"Name"`
	Email    string             `json:"Email"`
	Password string             `json:"Password"`
}

func init() {
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	var err error
	client, err = mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		fmt.Println("Error creating MongoDB client:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		fmt.Println("Error connecting to MongoDB:", err)
		return
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		fmt.Println("Error pinging MongoDB:", err)
		return
	}

	fmt.Println("Connected to MongoDB successfully!")

	database = client.Database(databaseName)
}

func registerUser(c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	usersCollection := client.Database(databaseName).Collection(collectionName)
	result, err := usersCollection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully", "userID": result.InsertedID})
}
func updateUser(c *gin.Context) {
	var updateData struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	objID, err := primitive.ObjectIDFromHex(updateData.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	usersCollection := database.Collection(collectionName)
	_, err = usersCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{"name": updateData.Name, "email": updateData.Email}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func deleteUser(c *gin.Context) {
	userID := c.Query("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	usersCollection := database.Collection(collectionName)
	_, err = usersCollection.DeleteOne(context.Background(), bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func getAllUsers(c *gin.Context) {
	var users []User
	usersCollection := database.Collection(collectionName)
	cursor, err := usersCollection.Find(context.Background(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching users"})
		return
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var user User
		cursor.Decode(&user)
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}
func getOrderValues(order string) int {
	switch order {
	case "asc":
		return 1
	case "desc":
		return -1
	default:
		return 1
	}
}

func getFurnitures(c *gin.Context) {
	var furniture []Furniture

	collectionName2 := client.Database(databaseName).Collection(collectionName2)

	sortParam := c.Query("sort")
	sortOrder := c.Query("order")
	minPrice := c.Query("minPrice")
	maxPrice := c.Query("maxPrice")

	page, err := strconv.Atoi(c.Query("page"))
	if err != nil || page < 1 {
		page = 1
	}

	itemsPerPage, err := strconv.Atoi(c.Query("itemsPerPage"))
	if err != nil || itemsPerPage < 1 {
		itemsPerPage = 10
	}

	options := options.Find()

	switch sortParam {
	case "title":
		options.SetSort(bson.D{{"title", getOrderValues(sortOrder)}})
	case "price":
		options.SetSort(bson.D{{"price", getOrderValues(sortOrder)}})

	}

	filter := bson.M{}
	if minPrice != "" {
		minPriceFloat, err := strconv.ParseFloat(minPrice, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid minPrice value"})
			return
		}
		filter["price"] = bson.M{"$gte": minPriceFloat}
	}
	if maxPrice != "" {
		maxPriceFloat, err := strconv.ParseFloat(maxPrice, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid maxPrice value"})
			return
		}
		if _, exists := filter["price"]; exists {
			filter["price"].(bson.M)["$lte"] = maxPriceFloat
		} else {
			filter["price"] = bson.M{"$lte": maxPriceFloat}
		}
	}

	skip := (page - 1) * itemsPerPage
	options.SetSkip(int64(skip))
	options.SetLimit(int64(itemsPerPage))

	cursor, err := collectionName2.Find(context.TODO(), filter, options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while getting furniture data"})
		return
	}

	for cursor.Next(context.TODO()) {
		var furnitureItem Furniture
		cursor.Decode(&furnitureItem)
		furniture = append(furniture, furnitureItem)
	}

	if err := cursor.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error while getting furniture data"})
		return
	}

	c.JSON(http.StatusOK, furniture)
}

func getOrderValue(sortOrder string) {
	panic("unimplemented")
}

func handlePostOrder(w http.ResponseWriter, r *http.Request) {
	var order map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&order)
	if err != nil {
		response := map[string]string{"status": "400", "message": "Invalid JSON-message"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	fmt.Printf("Received order data: %+v\n", order)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{"status": "200", "message": "Order received successfully"}
	json.NewEncoder(w).Encode(response)
}

func handleHTML(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func createUsersCollection() error {
	usersCollection := database.Collection(collectionName)

	_, err := usersCollection.InsertOne(context.TODO(), User{
		Name:  "John Doe",
		Email: "john.doe@example.com",
	})

	return err
}

func addAgeField() error {
	usersCollection := database.Collection(collectionName)

	_, err := usersCollection.UpdateMany(
		context.TODO(),
		bson.D{},
		bson.M{"$set": bson.M{"age": 0}},
	)

	return err
}

func logUserAction(c *gin.Context, action string, userID string) {
	logData := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"action":    action,
		"userID":    userID,
	}

	logJSON, err := json.Marshal(logData)
	if err != nil {
		fmt.Println("Error marshaling log data:", err)
		return
	}
	file, err := os.OpenFile("C:\\Users\\anana\\OneDrive\\Рабочий стол\\advprog-final-main\\user_actions.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		return
	}
	defer file.Close()

	if _, err := io.WriteString(file, string(logJSON)+"\n"); err != nil {
		fmt.Println("Error writing log entry:", err)
		return
	}

	logger.WithFields(logrus.Fields{
		"timestamp": logData["timestamp"],
		"action":    logData["action"],
		"userID":    logData["userID"],
	}).Info("User action logged successfully")
}
func getUsernameFromContext(c *gin.Context) string {
	username, exists := c.Get("username")
	if !exists {
		return ""
	}
	return username.(string)
}
func logUserActionEndpoint(c *gin.Context) {
	var logData map[string]interface{}
	if err := c.ShouldBindJSON(&logData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := getUsernameFromContext(c)

	action, ok := logData["action"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing or invalid 'action' field"})
		return
	}
	logUserAction(c, action, userID)

	c.JSON(http.StatusOK, gin.H{"message": "User action logged successfully"})
}
func rateLimiter(limiter *rate.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {

			resetTime := limiter.Reserve().DelayFrom(time.Now()).Round(time.Second)
			c.Header("Retry-After", fmt.Sprintf("%d", resetTime.Seconds()))
			c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limiter.Limit()))
			c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", 0))
			c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(resetTime).Unix()))
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}
func main() {

	logger := logrus.New()

	r := gin.Default()

	config := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	config.AllowOrigins = []string{"http://localhost:8080"}
	r.Use(cors.New(config))
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output: logger.Out,
		Formatter: func(params gin.LogFormatterParams) string {
			return fmt.Sprintf("{\"timestamp\":\"%s\",\"status\":%d,\"method\":\"%s\",\"path\":\"%s\"}\n",
				params.TimeStamp.Format(time.RFC3339),
				params.StatusCode,
				params.Method,
				params.Path,
			)
		},
	}))

	r.MaxMultipartMemory = 1024
	r.Use(rateLimiter(limiter))

	r.GET("/2", func(c *gin.Context) {
		c.String(http.StatusOK, "Request processed successfully")
	})

	r.POST("/logUserAction", logUserActionEndpoint)
	r.POST("/register", registerUser)
	r.POST("/login", loginUser)
	r.GET("/furniture", getFurnitures)
	r.GET("/getUser", getUserByID)

	r.POST("/submitOrder", submitOrder)
	r.PUT("/updateUser", updateUser)
	r.DELETE("/deleteUser", deleteUser)
	r.GET("/getAllUsers", getAllUsers)

	r.Static("/static", "./static/")
	r.StaticFS("/auth", http.Dir("auth"))
	r.StaticFile("/", "index.html")

	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
	if err != nil {
		logger.WithError(err).Fatal("Error creating MongoDB client")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		logger.WithError(err).Fatal("Error connecting to MongoDB")
		return
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		logger.WithError(err).Fatal("Error pinging MongoDB")
		return
	}

	logger.Info("Connected to MongoDB successfully!")

	defer client.Disconnect(ctx)

	database := client.Database(databaseName)

	if err := createUsersCollection(); err != nil {
		logger.WithError(err).Fatal("Error creating users collection")
		return
	}

	if err := addAgeField(); err != nil {
		logger.WithError(err).Fatal("Error adding age field")
		return
	}
	exampleUser := User{
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}

	usersCollection := database.Collection(collectionName)
	insertResult, err := usersCollection.InsertOne(ctx, exampleUser)
	if err != nil {
		logger.WithError(err).Fatal("Error inserting user")
		return
	}

	logger.Info("Inserted user with ID:", insertResult.InsertedID)
	logger.Info("Server is running on :8080...")

	if err := r.Run(":8080"); err != nil {
		logger.WithError(err).Fatal("Error starting the server")
	}
}

// CRUD
func createUser(w http.ResponseWriter, r *http.Request) {
	var newUser User
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usersCollection := database.Collection(collectionName)
	insertResult, err := usersCollection.InsertOne(context.Background(), newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(insertResult)
}

// crud
func getUserByID(c *gin.Context) {
	userID := c.Query("id")
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var user User
	usersCollection := database.Collection(collectionName)
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// login_page
func loginUser(c *gin.Context) {
	var loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	usersCollection := client.Database(databaseName).Collection(collectionName)
	var user User
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": loginRequest.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// ind_page
func submitOrder(c *gin.Context) {
	var order map[string]interface{}
	err := c.ShouldBindJSON(&order)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON-message"})
		return
	}

	fmt.Printf("Received order data: %+v\n", order)

	c.JSON(http.StatusOK, gin.H{"status": "200", "message": "Order received successfully"})
}
