package services

import (
	"github.com/plopezm/goedb"
	"os"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

type Role struct {
	ID		int `goedb:"pk,autoincrement"`
	Name 	string `goedb:"unique"`
}

type User struct {
	ID			int	`goedb:"pk,autoincrement"`
	Email		string  `goedb:"unique"`
	Password 	string
	Role		Role	`goedb:"fk=Role(ID)"`
}

const PersistenceUnit = "testing"

func checkError(err error){
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GetUserById(id int) (user *User, err error){
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = new(User)
	user.ID = id
	err = em.First(user, "", nil)
	if err != nil {
		return nil, err
	}
	return user, err
}

func FindAllUsers() (user []User, err error){
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	users := make([]User, 0)
	err = em.Find(&users, "", nil)
	return users, err
}

func GetUserByAccount(username string, pass string) (user *User, err error){
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = new(User)
	err = em.First(user, "User.Email = :email AND User.Password = :pass", map[string]interface{}{
		"email": username,
		"pass": pass,
	})
	if err != nil {
		return nil, err
	}
	return user, err
}

