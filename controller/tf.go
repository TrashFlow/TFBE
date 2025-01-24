package controller

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gocroot/config"
	"github.com/gocroot/helper/atdb"
	"github.com/gocroot/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// RegisterHandler menghandle permintaan registrasi.
func RegisterTf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	var registrationData model.PdfmUsers

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&registrationData)
	if err != nil {
		http.Error(w, "Data tidak valid: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validasi field wajib
	if registrationData.Name == "" || registrationData.Email == "" || registrationData.Password == "" {
		http.Error(w, "Name, Email, dan Password wajib diisi", http.StatusBadRequest)
		return
	}

	// Hash password sebelum menyimpan ke database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registrationData.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Gagal memproses password: "+err.Error(), http.StatusInternalServerError)
		return
	}

	registrationData.Password = string(hashedPassword)

	// Set nilai default untuk field lainnya
	registrationData.ID = primitive.NewObjectID()
	registrationData.CreatedAt = time.Now()
	registrationData.UpdatedAt = time.Now()

	// Simpan data ke database
	_, err = atdb.InsertOneDoc(config.Mongoconn, "users", registrationData)
	if err != nil {
		http.Error(w, "Gagal menyimpan data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Respon sukses
	response := map[string]string{"message": "Registrasi berhasil"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Login
func LoginTf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Metode tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	// Decode data login dari request body
	var loginDetails model.TfUser
	if err := json.NewDecoder(r.Body).Decode(&loginDetails); err != nil {
		http.Error(w, "Data tidak valid: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Cari pengguna di database berdasarkan email dan password
	filter := bson.M{"email": loginDetails.Email, "password": loginDetails.Password}
	_, err := atdb.GetOneDoc[model.TfUser](config.Mongoconn, "users", filter)
	if err != nil {
		http.Error(w, "Email atau password salah", http.StatusUnauthorized)
		return
	}

	// Respon sukses
	response := map[string]string{"message": "Login berhasil"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
