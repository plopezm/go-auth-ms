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
	em.Migrate(&models.Role{}, true, true)

	em.Migrate(&models.Permission{}, true, true)

	em.Migrate(&models.User{}, true, true)

	em.Migrate(&models.PermissionsGroup{}, true, true)

	role := models.Role{
		Name:        "admin",
		Description: "Full access",
	}

	result, err := em.Insert(&role)
	checkError(err)
	role.ID = int(result.LastInsertId)

	permission := models.Permission{
		Name:        "sysadmin",
		Description: "Full access",
	}

	_, err = em.Insert(&permission)
	checkError(err)
	permission.ID = int(result.LastInsertId)

	permissionGroup := models.PermissionsGroup{
		Role:       role,
		Permission: permission,
	}
	_, err = em.Insert(&permissionGroup)
	checkError(err)

	user := models.User{
		Email:    "admin",
		Role:     role,
		Password: "admin",
	}

	_, err = em.Insert(&user)
	checkError(err)
}

func TestGetRolesWithPermissions(t *testing.T) {
	roles, err := services.GetRolesWithPermissions()
	assert.Nil(t, err)
	assert.NotNil(t, roles)
	assert.Equal(t, 1, len(roles))
	t.Log(roles)
	assert.Equal(t, 1, len(roles[0].Permissions))
	assert.Equal(t, "sysadmin", roles[0].Permissions[0].Name)
}

func TestGetRolesWithPermissionsById(t *testing.T) {
	role, err := services.GetRoleWithPermissions(1)
	assert.Nil(t, err)
	assert.NotNil(t, role)
	t.Log(role)
	assert.Equal(t, 1, len(role.Permissions))
	assert.Equal(t, "sysadmin", role.Permissions[0].Name)
}
