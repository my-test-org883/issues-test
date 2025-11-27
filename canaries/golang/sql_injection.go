package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/lib/pq"
)

var db *sql.DB

// SQL Injection vulnerability #1: Direct string concatenation
func getUserByID(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// Vulnerable: Direct string concatenation
	query := "SELECT username, email FROM users WHERE id = " + userID

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var username, email string
		rows.Scan(&username, &email)
		fmt.Fprintf(w, "User: %s, Email: %s\n", username, email)
	}
}

// SQL Injection vulnerability #2: fmt.Sprintf
func searchUsers(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("search")

	// Vulnerable: Using fmt.Sprintf for query construction
	query := fmt.Sprintf("SELECT * FROM users WHERE username LIKE '%%%s%%'", searchTerm)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var username, email string
		rows.Scan(&id, &username, &email)
		fmt.Fprintf(w, "ID: %d, User: %s, Email: %s\n", id, username, email)
	}
}

// SQL Injection vulnerability #3: Dynamic ORDER BY
func listUsers(w http.ResponseWriter, r *http.Request) {
	orderBy := r.URL.Query().Get("order")
	if orderBy == "" {
		orderBy = "username"
	}

	// Vulnerable: Dynamic ORDER BY without validation
	query := "SELECT id, username, email FROM users ORDER BY " + orderBy

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var username, email string
		rows.Scan(&id, &username, &email)
		fmt.Fprintf(w, "ID: %d, User: %s, Email: %s\n", id, username, email)
	}
}

// SQL Injection vulnerability #4: Authentication bypass
func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Vulnerable: Direct concatenation in WHERE clause
	query := fmt.Sprintf("SELECT id FROM users WHERE username='%s' AND password='%s'", username, password)

	var userID int
	err := db.QueryRow(query).Scan(&userID)
	if err != nil {
		fmt.Fprintf(w, "Login failed")
		return
	}

	fmt.Fprintf(w, "Login successful! User ID: %d", userID)
}

// SQL Injection vulnerability #5: UNION-based injection
func getProductInfo(w http.ResponseWriter, r *http.Request) {
	productID := r.URL.Query().Get("product_id")

	// Vulnerable: Allows UNION attacks
	query := "SELECT name, price FROM products WHERE id = " + productID

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, price string
		rows.Scan(&name, &price)
		fmt.Fprintf(w, "Product: %s, Price: %s\n", name, price)
	}
}

// SQL Injection vulnerability #6: Batch operations
func updateUserRoles(w http.ResponseWriter, r *http.Request) {
	userIDs := r.FormValue("user_ids") // e.g., "1,2,3"
	role := r.FormValue("role")

	// Vulnerable: IN clause with direct insertion
	query := fmt.Sprintf("UPDATE users SET role = '%s' WHERE id IN (%s)", role, userIDs)

	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}

	fmt.Fprintf(w, "Users updated successfully")
}

func main() {
	// Initialize database connection (would be real in practice)
	// db, _ = sql.Open("postgres", "user=username dbname=mydb sslmode=disable")

	http.HandleFunc("/user", getUserByID)
	http.HandleFunc("/search", searchUsers)
	http.HandleFunc("/list", listUsers)
	http.HandleFunc("/login", login)
	http.HandleFunc("/product", getProductInfo)
	http.HandleFunc("/update-roles", updateUserRoles)

	fmt.Println("Starting vulnerable server on :8081")
	http.ListenAndServe(":8081", nil)
}