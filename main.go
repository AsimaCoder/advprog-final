func getFurniture(c *gin.Context) {
    // Setup MongoDB client and context
    client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("your-mongodb-uri"))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer client.Disconnect(context.TODO())

    // Select the furniture collection
    collection := client.Database("your-database-name").Collection("furniture")

    // Query the collection
    cursor, err := collection.Find(context.TODO(), bson.D{{}})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer cursor.Close(context.TODO())

    var furnitures []Furniture
    if err = cursor.All(context.TODO(), &furnitures); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Send response as JSON
    c.JSON(http.StatusOK, furnitures)
}
