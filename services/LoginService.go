package services

import (
	"errors"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/plopezm/go-auth-ms/models"
	"github.com/plopezm/goedb"
)

const PersistenceUnit = "testing"

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func FindAllUsers() ([]models.User, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	users := make([]models.User, 0)
	err = em.Find(&users, "", nil)
	return users, err
}

func GetUserById(id int) (user models.User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = models.User{}
	user.ID = id
	err = em.First(&user, "", nil)
	if err != nil {
		return user, err
	}
	return user, err
}

func GetUserByAccount(username string, pass string) (user models.User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = models.User{}
	err = em.First(&user, "User.Email = :email AND User.Password = :pass", map[string]interface{}{
		"email": username,
		"pass":  pass,
	})
	if err != nil {
		return user, err
	}
	return user, err
}

func CreateUser(user models.User) (models.User, error) {
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

func UpdateUser(user models.User) (models.User, error) {
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

func DeleteUserById(id int) (user models.User, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	user = models.User{}
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

func FindAllRoles() ([]models.Role, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	roles := make([]models.Role, 0)
	err = em.Find(&roles, "", nil)
	return roles, err
}

func GetRoleById(id int) (role models.Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	role = models.Role{}
	role.ID = id
	err = em.First(&role, "", nil)
	if err != nil {
		return role, err
	}
	return role, err
}

func CreateRole(role models.Role) (models.Role, error) {
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

func UpdateRole(role models.Role) (models.Role, error) {
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

func DeleteRoleById(id int) (role models.Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	role = models.Role{}
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

func GetRolesWithPermissions() (roles []models.Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	em.Find(&roles, "", nil)

	//for _, role := range roles {
	for i := 0; i < len(roles); i++ {
		em.Find(&roles[i].Permissions, "Permission.Role = :role_id", map[string]interface{}{
			"role_id": roles[i].ID,
		})
		fmt.Println(roles[i])
	}
	fmt.Println(roles)
	return roles, err
}

func GetRoleWithPermissions(id int) (role models.Role, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	role, err = GetRoleById(id)
	if err != nil {
		return role, err
	}
	em.Find(role.Permissions, "Permission.Role = :role_id", map[string]interface{}{
		"role_id": id,
	})
	return role, err
}

func ValidateUser(c *gin.Context, username, password string) bool {
	user, err := GetUserByAccount(username, password)
	if err != nil {
		return false
	}
	c.Set("username", user.Email)
	return true
}

func FindAllPermissions() ([]models.Permission, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	permissions := make([]models.Permission, 0)
	err = em.Find(&permissions, "", nil)
	return permissions, err
}

func GetPermissionById(id int) (permission models.Permission, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	permission = models.Permission{}
	permission.ID = id
	err = em.First(&permission, "", nil)
	if err != nil {
		return permission, err
	}
	return permission, err
}

func CreatePermission(permission models.Permission) (models.Permission, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Insert(&permission)
	if err != nil {
		return permission, err
	}

	if result.NumRecordsAffected == 0 {
		return permission, errors.New("Creation failed")
	}

	return permission, nil
}

func UpdatePermission(permission models.Permission) (models.Permission, error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)

	result, err := em.Update(&permission)
	if err != nil {
		return permission, err
	}

	if result.NumRecordsAffected == 0 {
		return permission, errors.New("Update failed")
	}

	return permission, nil
}

func DeletePermissionById(id int) (permission models.Permission, err error) {
	em, err := goedb.GetEntityManager(PersistenceUnit)
	checkError(err)
	permission = models.Permission{}
	permission.ID = id
	result, err := em.Remove(&permission, "", nil)
	if err != nil {
		return permission, err
	}
	if result.NumRecordsAffected == 0 {
		return permission, errors.New("Role not found")
	}
	return permission, err
}
