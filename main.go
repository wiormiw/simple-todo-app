package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID       uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Username string    `gorm:"unique;not null"`
	Password string    `gorm:"not null"`
	Email    string    `gorm:"unique;not null"`
}

type Checklist struct {
	ID   uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Name string    `gorm:"not null"`
}

type Item struct {
	ID          uuid.UUID `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	ItemName    string    `gorm:"not null"`
	ChecklistID uuid.UUID `gorm:"not null"`
	Checklist   Checklist `gorm:"foreignKey:ChecklistID"`
	Status      string    `gorm:"default:'in-progress'"`
	UpdatedAt   time.Time
}

var db *gorm.DB

func connectDB() {
	var err error
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	dbPort := os.Getenv("DB_PORT")
	dbSslmode := os.Getenv("DB_SSLMODE")

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		dbHost, dbUser, dbPassword, dbName, dbPort, dbSslmode)

	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to the database")
	}

	db.AutoMigrate(&User{})
	db.AutoMigrate(&Checklist{})
	db.AutoMigrate(&Item{})
}

func register(c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}
	user.Password = string(hashedPassword)

	user.ID = uuid.New()

	err = db.Create(&user).Error
	if err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func login(c *fiber.Ctx) error {
	var input User
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	var user User
	err := db.Where("username = ?", input.Username).First(&user).Error
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	token, err := createJWT(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not log in"})
	}

	return c.JSON(fiber.Map{"token": token})
}

func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "default_secret"
	}
	return secret
}

func createJWT(userID uuid.UUID) (string, error) {
	jwtSecretKey := getJWTSecret()
	claims := jwt.MapClaims{}
	claims["user_id"] = userID.String()
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func authMiddleware(ctx *fiber.Ctx) error {
	jwtSecretKey := getJWTSecret()

	tokenString := ctx.Get("Authorization")
	if tokenString == "" {
		return jwtError(ctx, fmt.Errorf("missing token"))
	}

	if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
		tokenString = tokenString[7:]
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecretKey), nil
	})

	if err != nil {
		return jwtError(ctx, err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID := claims["user_id"].(string)
		ctx.Locals("user_id", userID)
	} else {
		return jwtError(ctx, fmt.Errorf("invalid token"))
	}

	return ctx.Next()
}

func jwtError(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
}

func createChecklist(c *fiber.Ctx) error {
	var checklist Checklist
	if err := c.BodyParser(&checklist); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if err := db.Create(&checklist).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create checklist"})
	}

	return c.Status(fiber.StatusCreated).JSON(checklist)
}

func getChecklists(c *fiber.Ctx) error {
	var checklists []Checklist
	if err := db.Find(&checklists).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch checklists"})
	}

	return c.JSON(checklists)
}

func deleteChecklist(c *fiber.Ctx) error {
	id := c.Params("id")
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid checklist ID"})
	}

	var checklist Checklist
	if err := db.First(&checklist, parsedID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Checklist not found"})
	}

	if err := db.Delete(&checklist).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete checklist"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func addItem(c *fiber.Ctx) error {
	checklistID := c.Params("checklist_id")

	parsedChecklistID, err := uuid.Parse(checklistID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid checklist ID"})
	}

	var checklist Checklist
	if err := db.First(&checklist, parsedChecklistID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Checklist not found"})
	}

	var item Item
	if err := c.BodyParser(&item); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	item.ChecklistID = parsedChecklistID

	if err := db.Create(&item).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create item"})
	}

	return c.Status(fiber.StatusCreated).JSON(item)
}

func getItem(c *fiber.Ctx) error {
	checklistID := c.Params("checklist_id")
	itemID := c.Params("item_id")

	parsedChecklistID, err := uuid.Parse(checklistID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid checklist ID"})
	}

	parsedItemID, err := uuid.Parse(itemID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid item ID"})
	}

	var checklist Checklist
	if err := db.First(&checklist, parsedChecklistID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Checklist not found"})
	}

	var item Item
	if err := db.Where("id = ? AND checklist_id = ?", parsedItemID, parsedChecklistID).First(&item).Error; err != nil {
		return c.JSON(fiber.Map{})
	}

	return c.JSON(item)
}

func updateItem(c *fiber.Ctx) error {
	checklistID := c.Params("checklist_id")
	itemID := c.Params("item_id")

	parsedChecklistID, err := uuid.Parse(checklistID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid checklist ID"})
	}

	parsedItemID, err := uuid.Parse(itemID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid item ID"})
	}

	var checklist Checklist
	if err := db.First(&checklist, parsedChecklistID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Checklist not found"})
	}

	var item Item
	if err := db.Where("id = ? AND checklist_id = ?", parsedItemID, parsedChecklistID).First(&item).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found under this checklist"})
	}
	body := c.Body()
	if len(body) > 0 {
		var input struct {
			ItemName string `json:"itemName"`
		}
		if err := json.Unmarshal(body, &input); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
		}
		if input.ItemName != "" {
			item.ItemName = input.ItemName
		}
	} else {
		item.Status = "done"
	}

	if err := db.Save(&item).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update item"})
	}

	return c.JSON(item)
}

func deleteItem(c *fiber.Ctx) error {
	checklistID := c.Params("checklist_id")
	itemID := c.Params("item_id")

	parsedChecklistID, err := uuid.Parse(checklistID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid checklist ID"})
	}

	parsedItemID, err := uuid.Parse(itemID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid item ID"})
	}

	var checklist Checklist
	if err := db.First(&checklist, parsedChecklistID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Checklist not found"})
	}

	var item Item
	if err := db.Where("id = ? AND checklist_id = ?", parsedItemID, parsedChecklistID).First(&item).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Item not found under this checklist"})
	}

	if err := db.Delete(&item).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to delete item"})
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func main() {
	err := godotenv.Load()

	if err != nil {
		log.Println(err)
	}

	app := fiber.New()
	app.Use(logger.New())

	connectDB()

	app.Post("/register", register)
	app.Post("/login", login)

	checklistGroup := app.Group("/checklist", authMiddleware)
	checklistGroup.Post("/", createChecklist)
	checklistGroup.Get("/", getChecklists)
	checklistGroup.Delete("/:id", deleteChecklist)

	checklistGroup.Route("/:checklist_id/item", func(itemGroup fiber.Router) {
		itemGroup.Get("/:item_id", getItem)
		itemGroup.Post("/", addItem)
		itemGroup.Put("/:item_id", updateItem)
		itemGroup.Delete("/:item_id", deleteItem)
	})

	app.Listen(":" + os.Getenv("APP_PORT"))
}
