package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/golang-jwt/jwt/v4"
	"github.com/schmentle/swagger-auth-example/middleware"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/schmentle/go-swagger-auth-form/swagger"
	_ "github.com/schmentle/swagger-auth-example/docs"
	"log"
)

// @title Fiber Swagger Example API
// @version 2.0
// @description This is a sample server.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description "Enter your Bearer token in the format: `Bearer {token}`"
func main() {
	// Fiber instance
	app := fiber.New()

	// Middleware
	app.Use(recover.New())
	app.Use(cors.New())

	// Routes
	app.Get("/", HealthCheck)

	swaggerDocURL := os.Getenv("SWAGGER_DOC_URL")
	if swaggerDocURL == "" {
		swaggerDocURL = "/swagger/doc.json"
	}

	authApiUrl := os.Getenv("AUTH_URL")
	if authApiUrl == "" {
		authApiUrl = "/auth"
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your_secret_key"
	}

	app.Get("/config", func(c *fiber.Ctx) error {
		return Config(c, swaggerDocURL, authApiUrl)
	})

	app.Post("/auth", func(c *fiber.Ctx) error {
		return Auth(c, secret)
	})

	// Protected routes
	protected := app.Group("/api", middleware.JWTAuth(secret))

	protected.Get("/profile", Profile)

	app.Get("/swagger/doc.json", func(c *fiber.Ctx) error {
		return c.SendFile("./docs/swagger.json")
	})

	app.Get("/swagger/*", adaptor.HTTPHandler(http.StripPrefix("/swagger/", swagger.ServeSwaggerUI())))

	// Start Server
	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}

// Profile godoc
// @Summary Get user profile
// @Description Retrieve profile details of the authenticated user
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Security BearerAuth
// @Router /api/profile [get]
func Profile(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"message": "This is a protected route!"})
}

// Auth godoc
// @Summary Authenticate a user
// @Description Generate a JWT token for the user
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /auth [post]
func Auth(c *fiber.Ctx, secret string) error {
	type AuthRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	if req.Username != "admin" || req.Password != "password" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": req.Username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Token generation failed"})
	}

	return c.JSON(fiber.Map{"access_token": tokenString})
}

// Config godoc
// @Summary Config endpoint
// @Description Get the config for server
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /config [get]
func Config(c *fiber.Ctx, swaggerDocURL string, authApiUrl string) error {
	res := map[string]interface{}{
		"data":          "Server is up and running",
		"swaggerDocURL": swaggerDocURL,
		"authApiUrl":    authApiUrl,
	}

	if err := c.JSON(res); err != nil {
		return err
	}

	return nil
}

// HealthCheck godoc
// @Summary Show the status of server
// @Description Get the status of server
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func HealthCheck(c *fiber.Ctx) error {
	res := map[string]interface{}{
		"data": "Server is up and running",
	}

	if err := c.JSON(res); err != nil {
		return err
	}

	return nil
}
