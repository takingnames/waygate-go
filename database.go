package waygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"sync"
)

type ClientJsonDatabase struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	State        string `json:"state"`
	dbPath       string
	mutex        *sync.Mutex
}

func NewClientJsonDatabase() *ClientJsonDatabase {

	db := &ClientJsonDatabase{
		State:  "",
		dbPath: "waygate_client_db.json",
		mutex:  &sync.Mutex{},
	}

	dbJson, _ := ioutil.ReadFile(db.dbPath)

	err := json.Unmarshal(dbJson, &db)
	if err != nil {
		fmt.Println(err)
	}

	db.persist()

	return db
}

func (db *ClientJsonDatabase) GetAccessToken() (string, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if db.AccessToken == "" {
		return "", errors.New("No access token")
	}

	return db.AccessToken, nil
}
func (db *ClientJsonDatabase) SetAccessToken(token string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.AccessToken = token

	db.persist()
}

func (db *ClientJsonDatabase) GetRefreshToken() (string, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if db.RefreshToken == "" {
		return "", errors.New("No refresh token")
	}

	return db.RefreshToken, nil
}

func (db *ClientJsonDatabase) SetState(state string) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.State = state

	db.persist()
}

func (db *ClientJsonDatabase) GetState() string {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	return db.State
}

func (db *ClientJsonDatabase) persist() {
	saveJson(db, db.dbPath)
}

func saveJson(data interface{}, filePath string) error {
	jsonStr, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errors.New("Error serializing JSON")
	} else {
		err := ioutil.WriteFile(filePath, jsonStr, 0644)
		if err != nil {
			return errors.New("Error saving JSON")
		}
	}
	return nil
}
