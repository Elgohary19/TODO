package routes

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ichtrojan/go-todo/controllers"
)

type application struct {
	auth struct {
		username string
		password string
	}
}

func Init() *mux.Router {
	route := mux.NewRouter()
	app := new(application)

	route.HandleFunc("/", app.basicAuth(app.protectedHandler))
	route.HandleFunc("/add", controllers.Add).Methods("POST")
	route.HandleFunc("/delete/{id}", controllers.Delete)
	route.HandleFunc("/complete/{id}", controllers.Complete)
	route.HandleFunc("/unprotected", app.unprotectedHandler)

	app.auth.username = "admin"
	app.auth.password = "password"

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided")
	}

	// srv := &http.Server{
	// 	Addr:         ":8080",
	// 	Handler:      route,
	// 	IdleTimeout:  time.Minute,
	// 	ReadTimeout:  10 * time.Second,
	// 	WriteTimeout: 30 * time.Second,
	// }

	// log.Printf("starting server on %s", srv.Addr)
	// err := srv.ListenAndServeTLS("./localhost.pem", "./localhost-key.pem")
	// log.Fatal(err)
	return route
}

func (app *application) protectedHandler(w http.ResponseWriter, r *http.Request) {
	controllers.Show(w, r)
}

func (app *application) unprotectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is the unprotected handler")
}

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
			route := mux.NewRouter()
			route.HandleFunc("", controllers.Show)
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
