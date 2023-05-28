package main

import (
	"errors"
	"github.com/jumaniyozov/gobook/internal/data"
	"net/http"
	"time"
)

type jsonResponse struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type envelope map[string]any

func (app *application) Login(w http.ResponseWriter, r *http.Request) {
	type credentials struct {
		UserName string `json:"email"`
		Password string `json:"password"`
	}

	var creds credentials
	var payload jsonResponse

	err := app.readJSON(w, r, &creds)
	if err != nil {
		app.errorLog.Println(err)
		payload.Error = true
		payload.Message = "invalid json supplied, or json missing entirely"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
	}

	app.infoLog.Println(creds.UserName, creds.Password)

	user, err := app.models.User.GetByEmail(creds.UserName)
	if err != nil {
		app.errorLog.Println(err)
		app.errorJSON(w, errors.New("invalid user credentials"))
		return
	}

	validPassword, err := user.PasswordMatches(creds.Password)
	if err != nil || !validPassword {
		app.errorLog.Println(err)
		app.errorJSON(w, errors.New("invalid user credentials"))
		return
	}

	token, err := app.models.Token.GenerateToken(user.ID, 24*time.Hour)
	if err != nil {
		app.errorLog.Println(err)
		app.errorJSON(w, err)
		return
	}

	err = app.models.Token.Insert(*token, *user)
	if err != nil {
		app.errorLog.Println(err)
		app.errorJSON(w, errors.New("invalid user credentials"))
		return
	}

	user.Password = ""

	payload = jsonResponse{
		Error:   false,
		Message: "signed in",
		Data:    envelope{"token": token, "user": user},
	}

	err = app.writeJSON(w, http.StatusOK, payload)
	if err != nil {
		app.errorLog.Println(err)
	}
}

func (app *application) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	var users data.User
	all, err := users.GetAll()
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "success",
		Data:    envelope{"users": all},
	}

	app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) AddUser(w http.ResponseWriter, r *http.Request) {
	var u = data.User{
		Email:     "you@there.com",
		FirstName: "You",
		LastName:  "There",
		Password:  "password",
	}

	app.infoLog.Println("Adding user...")

	id, err := app.models.User.Insert(u)
	if err != nil {
		app.errorLog.Println(err)
		app.errorJSON(w, err, http.StatusForbidden)
		return
	}

	app.infoLog.Println("Got back id of", id)
	newUser, _ := app.models.User.GetOne(id)
	app.writeJSON(w, http.StatusOK, newUser)
}

func (app *application) GenerateToken(w http.ResponseWriter, r *http.Request) {
	token, err := app.models.User.Token.GenerateToken(1, 60*time.Minute)
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	token.Email = "admin@example.com"
	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	payload := jsonResponse{
		Error:   false,
		Message: "success",
		Data:    token,
	}

	app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) SaveToken(w http.ResponseWriter, r *http.Request) {
	token, err := app.models.User.Token.GenerateToken(2, 60*time.Minute)
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	user, err := app.models.User.GetOne(2)
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	token.UserID = user.ID
	token.CreatedAt = time.Now()
	token.UpdatedAt = time.Now()

	err = token.Insert(*token, *user)
	if err != nil {
		app.errorLog.Println(err)
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "success",
		Data:    token,
	}

	app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) ValidateToken(w http.ResponseWriter, r *http.Request) {
	tokenToValidate := r.URL.Query().Get("token")
	valid, err := app.models.Token.ValidToken(tokenToValidate)
	if err != nil {
		app.errorJSON(w, err)
		return
	}

	var payload jsonResponse
	payload.Error = false
	payload.Data = valid

	app.writeJSON(w, http.StatusOK, payload)
}

func (app *application) Logout(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Token string `json:"token"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, errors.New("invalid json"))
		return
	}

	err = app.models.Token.DeleteByToken(requestPayload.Token)
	if err != nil {
		app.errorJSON(w, errors.New("invalid json"))
		return
	}

	payload := jsonResponse{
		Error:   false,
		Message: "logged out",
	}

	_ = app.writeJSON(w, http.StatusOK, payload)
}
