package tests

import (
	"log"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/plopezm/go-auth-ms/models"
	"github.com/plopezm/go-auth-ms/services"
	"github.com/plopezm/goedb"
	"github.com/stretchr/testify/assert"
)

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

func init() {
	goedb.Initialize()
	em, err := goedb.GetEntityManager("testing")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	em.Migrate(&models.Role{}, true, false)

	em.Migrate(&models.Permission{}, true, false)

	em.Migrate(&models.User{}, true, false)

	role := models.Role{
		Name:        "admin",
		Description: "Full access",
	}

	result, err := em.Insert(&role)
	//checkError(err)
	role.ID = int(result.LastInsertId)

	permission := models.Permission{
		Name:        "sysadmin",
		Description: "Full access",
		Role:        role,
	}

	_, err = em.Insert(&permission)
	//checkError(err)

	user := models.User{
		Email:    "admin",
		Role:     role,
		Password: "admin",
	}

	_, err = em.Insert(&user)
	//checkError(err)
}

func TestGetRolesWithPermissions(t *testing.T) {
	roles, err := services.GetRolesWithPermissions()
	assert.Nil(t, err)
	assert.NotNil(t, roles)
	assert.Equal(t, 1, len(roles))
	t.Log(roles)
	assert.Equal(t, 1, len(roles[0].Permissions))
}
