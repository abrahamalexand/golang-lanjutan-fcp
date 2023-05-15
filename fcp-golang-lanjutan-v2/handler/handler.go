package handler

import (
	"a21hc3NpZ25tZW50/client"
	"a21hc3NpZ25tZW50/model"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

var UserLogin = make(map[string]model.User)

// DESC: func Auth is a middleware to check user login id, only user that already login can pass this middleware
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("user_login_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: err.Error()})
			return
		}

		if _, ok := UserLogin[c.Value]; !ok || c.Value == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, "userID", c.Value)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// DESC: func AuthAdmin is a middleware to check user login role, only admin can pass this middleware
func AuthAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieUserRole, err := r.Cookie("user_login_role")
		if err != nil || cookieUserRole.Value != "admin" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login role not Admin"})
			return
		}
	})
}
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}

	var user model.UserLogin
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if user.ID == "" || user.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID or name is empty"})
		return
	}

	users, err := readUsersFromFile()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Failed to read user data"})
		return
	}

	var found bool
	for _, u := range users {
		if u.ID == user.ID && u.Name == user.Name {
			found = true
			break
		}
	}

	if !found {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user not found"})
		return
	}

	// Set cookie
	cookieID := &http.Cookie{
		Name:  "user_login_id",
		Value: user.ID,
	}
	http.SetCookie(w, cookieID)

	cookieRole := &http.Cookie{
		Name:  "user_login_role",
		Value: getUserRole(user.ID),
	}
	http.SetCookie(w, cookieRole)

	response := model.SuccessResponse{
		Username: user.ID,
		Message:  "login success",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	UserLogin[user.ID] = model.User{
		ID:        user.ID,
		Name:      user.Name,
		Role:      getUserRole(user.ID),
		StudyCode: getUserStudyCode(user.ID),
	}
}

func readUsersFromFile() ([]model.User, error) {
	file, err := os.Open("data/users.txt")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []model.User
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "_")
		if len(fields) == 4 {
			user := model.User{
				ID:        fields[0],
				Name:      fields[1],
				StudyCode: fields[2],
				Role:      fields[3],
			}
			users = append(users, user)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func getUserRole(userID string) string {
	users, err := readUsersFromFile()
	if err != nil {
		// Handle error, misalnya dengan mencetak pesan error atau mengembalikan nilai default
		fmt.Println("Failed to read user data:", err)
		return ""
	}

	for _, user := range users {
		if user.ID == userID {
			return user.Role
		}
	}

	// Jika ID pengguna tidak ditemukan, mengembalikan nilai default
	return ""
}

func getUserStudyCode(userID string) string {
	users, err := readUsersFromFile()
	if err != nil {
		// Handle error, misalnya dengan mencetak pesan error atau mengembalikan nilai default
		fmt.Println("Failed to read user data:", err)
		return ""
	}

	for _, user := range users {
		if user.ID == userID {
			return user.StudyCode
		}
	}

	// Jika ID pengguna tidak ditemukan, mengembalikan nilai default
	return ""
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}

	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Invalid request body"})
		return
	}

	if user.ID == "" || user.Name == "" || user.Role == "" || user.StudyCode == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "ID, name, study code or role is empty"})
		return
	}

	if user.Role != "admin" && user.Role != "user" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Role must be admin or user"})
		return
	}

	studyData, err := readStudyProgramData()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}

	exist := checkUserExist(user.ID)
	if exist {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user id already exist"})
		return
	}

	validStudyCode := false
	for _, study := range studyData {
		if study.Code == user.StudyCode {
			validStudyCode = true
			break
		}
	}
	if !validStudyCode {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Study code not found"})
		return
	}

	err = saveUser(user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Internal server error"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(model.SuccessResponse{
		Username: user.ID,
		Message:  "register success",
	})
}

func readStudyProgramData() ([]model.StudyData, error) {
	filePath := "data/list-study.txt"
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var studyData []model.StudyData

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid study program data format")
		}

		code := parts[0]
		name := parts[1]
		study := model.StudyData{
			Code: code,
			Name: name,
		}
		studyData = append(studyData, study)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return studyData, nil
}

func checkUserExist(userID string) bool {
	filePath := "data/users.txt"
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "_")
		if len(parts) != 4 {
			continue
		}

		id := parts[0]
		if id == userID {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		return false
	}

	return false
}

func saveUser(user model.User) error {
	filePath := "data/users.txt"
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	userData := fmt.Sprintf("%s_%s_%s_%s\n", user.ID, user.Name, user.StudyCode, user.Role)
	_, err = file.WriteString(userData)
	if err != nil {
		return err
	}

	return nil
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}

	// Mengecek keberadaan cookie user_login_id
	cookie, err := r.Cookie("user_login_id")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "user login id not found"})
		return
	}

	// Menghapus cookie user_login_id
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)

	// Menghapus cookie user_login_role
	roleCookie, err := r.Cookie("user_login_role")
	if err == nil {
		roleCookie.MaxAge = -1
		http.SetCookie(w, roleCookie)
	}

	// Menghapus data user dari map UserLogin
	delete(UserLogin, cookie.Value)

	// Memberikan response sukses
	response := model.SuccessResponse{
		Username: cookie.Value,
		Message:  "logout success",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func GetStudyProgram(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Method is not allowed!"})
		return
	}

	cookieID, err := r.Cookie("user_login_id")
	if err != nil || cookieID.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "User login id not found"})
		return
	}

	// Mengecek cookie user_login_role
	cookieRole, err := r.Cookie("user_login_role")
	if err != nil || cookieRole.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "User login role not found"})
		return
	}

	if strings.ToLower(cookieRole.Value) != "admin" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "User login role not Admin"})
		return
	}

	// Membaca data study program dari file
	studyPrograms, err := readStudyProgramData()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.ErrorResponse{Error: "Failed to retrieve study programs"})
		return
	}

	// Mengirim response berupa list study program
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(studyPrograms)
}

func AddUser(w http.ResponseWriter, r *http.Request) {
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user model.User
	err = json.Unmarshal([]byte(requestBody), &user)
	if err != nil {
		panic(err)
	}

	// Cek apakah study code ditemukan
	if !isStudyExist(user.StudyCode) {
		w.WriteHeader(400)
		msg := model.ErrorResponse{Error: "study code not found"}
		resp, err := json.Marshal(msg)
		if err != nil {
			panic(err)
		}
		w.Write(resp)
	} else {
		w.WriteHeader(200)
		msg := model.SuccessResponse{}
		msg.Username = user.Name
		msg.Message = "add user success"
		resp, err := json.Marshal(msg)
		if err != nil {
			panic(err)
		}
		w.Write(resp)
	}

	// Simpan data pengguna ke file
	userData := fmt.Sprintf("%s_%s_%s\n", user.ID, user.Name, user.StudyCode)
	err = appendToFile("data/users.txt", userData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"Failed to write to user file"}`))
		return
	}

	// Set response code 200 dan message success
	response := model.SuccessResponse{
		Username: user.ID,
		Message:  "add user success",
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func isStudyExist(StudyCode string) bool {
	studies, err := ioutil.ReadFile("data/list-study.txt")
	if err != nil {
		return false
	}

	studyList := strings.Split(string(studies), "\n")
	for _, study := range studyList {
		if study != "" && strings.HasPrefix(study, StudyCode+"_") {
			return true
		}
	}
	return false
}

func appendToFile(filePath string, data string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	fileData := string(file) + data
	err = ioutil.WriteFile(filePath, []byte(fileData), 0644)
	if err != nil {
		return err
	}

	return nil
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	// TODO: answer here
}

// DESC: Gunakan variable ini sebagai goroutine di handler GetWeather
var GetWetherByRegionAPI = client.GetWeatherByRegion

func GetWeather(w http.ResponseWriter, r *http.Request) {
	// var listRegion = []string{"jakarta", "bandung", "surabaya", "yogyakarta", "medan", "makassar", "manado", "palembang", "semarang", "bali"}

	// DESC: dapatkan data weather dari 10 data di atas menggunakan goroutine
	// TODO: answer here
}
