package routes

import (
	"crypto/sha256"
	"crypto/subtle"
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

	route.HandleFunc("/", app.basicAuth(controllers.Show))
	route.HandleFunc("/add", controllers.Add).Methods("POST")
	route.HandleFunc("/delete/{id}", controllers.Delete)
	route.HandleFunc("/complete/{id}", controllers.Complete)

	app.auth.username = "admin"
	app.auth.password = "password"

	return route
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
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
