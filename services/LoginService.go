package services

import (
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/plopezm/goedb"
	"os"
)

type Role struct {
	ID   int    `goedb:"pk,autoincrement"`
	Name string `goedb:"unique"`
}

type User struct {
	ID       int    `goedb:"pk,autoincrement"`
	Email    string `goedb:"unique"`
	Password string
	Role     Role `goedb:"fk=Role(ID)"`
}

const PersistenceUnit = "testing"

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func FindAllUsers() ([]User, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	users := make([]User, 0)
	err = em.Find(&users, "", nil)
	return users, err
}

func GetUserById(id int) (user User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = User{}
	user.ID = id
	err = em.First(&user, "", nil)
	if err != nil {
		return user, err
	}
	return user, err
}

func GetUserByAccount(username string, pass string) (user User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = User{}
	err = em.First(&user, "User.Email = :email AND User.Password = :pass", map[string]interface{}{
		"email": username,
		"pass":  pass,
	})
	if err != nil {
		return user, err
	}
	return user, err
}

func CreateUser(user User) (User, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Insert(&user)
	if err != nil {
		return user, err
	}

	if result.NumRecordsAffected == 0 {
		return user, errors.New("Creation failed")
	}

	return user, nil
}

func UpdateUser(user User) (User, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Update(&user)
	if err != nil {
		return user, err
	}

	if result.NumRecordsAffected == 0 {
		return user, errors.New("Update failed")
	}

	return user, nil
}

func DeleteUserById(id int) (user User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = User{}
	user.ID = id
	result, err := em.Remove(&user, "", nil)
	if err != nil {
		return user, err
	}
	if result.NumRecordsAffected == 0 {
		return user, errors.New("User not found")
	}
	return user, err
}

func FindAllRoles() ([]Role, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	roles := make([]Role, 0)
	err = em.Find(&roles, "", nil)
	return roles, err
}

func GetRoleById(id int) (role Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	role = Role{}
	role.ID = id
	err = em.First(&role, "", nil)
	if err != nil {
		return role, err
	}
	return role, err
}

func CreateRole(role Role) (Role, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Insert(&role)
	if err != nil {
		return role, err
	}

	if result.NumRecordsAffected == 0 {
		return role, errors.New("Creation failed")
	}

	return role, nil
}

func UpdateRole(role Role) (Role, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Update(&role)
	if err != nil {
		return role, err
	}

	if result.NumRecordsAffected == 0 {
		return role, errors.New("Update failed")
	}

	return role, nil
}

func DeleteRoleById(id int) (role Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	role = Role{}
	role.ID = id
	result, err := em.Remove(&role, "", nil)
	if err != nil {
		return role, err
	}
	if result.NumRecordsAffected == 0 {
		return role, errors.New("Role not found")
	}
	return role, err
}
