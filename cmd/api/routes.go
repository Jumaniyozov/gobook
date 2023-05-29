package main

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"net/http"
)

func (app *application) routes() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	mux.Post("/users/login", app.Login)
	mux.Post("/users/logout", app.Logout)
	mux.Post("/users/signup", app.EditUser)

	mux.Get("/books", app.AllBooks)
	mux.Get("/books/{slug}", app.OneBook)

	mux.Post("/validate-token", app.ValidateToken)

	mux.Route("/admin", func(mux chi.Router) {
		mux.Use(app.AuthTokenMiddleware)

		mux.Get("/users/all", app.GetAllUsers)
		mux.Post("/users/save", app.EditUser)
		mux.Get("/users/get/{id}", app.GetUser)
		mux.Post("/users/delete", app.DeleteUser)
		mux.Post("/users/log-user-out/{id}", app.LogUserOutAndSetInactive)

		mux.Get("/authors/all", app.AuthorsAll)
		mux.Post("/books/save", app.EditBok)
		mux.Get("/books/{id}", app.BookByID)
		mux.Delete("/books/{id}", app.DeleteBook)
	})

	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/*", http.StripPrefix("/static", fileServer))

	return mux
}
