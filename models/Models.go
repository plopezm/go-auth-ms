package models

//TODO: Check how goedb works with multiple PKs
type PermissionsGroup struct {
	Role       Role       `goedb:"pk,fk=Role(ID)"`
	Permission Permission `goedb:"pk,fk=Permission(ID)"`
}

type Permission struct {
	ID          int    `goedb:"pk,autoincrement"`
	Name        string `goedb:"unique"`
	Description string
}

type Role struct {
	ID          int    `goedb:"pk,autoincrement"`
	Name        string `goedb:"unique"`
	Description string
	Permissions []Permission `goedb:"ignore"`
}

type User struct {
	ID       int    `goedb:"pk,autoincrement"`
	Email    string `goedb:"unique"`
	Password string
	Role     Role `goedb:"fk=Role(ID)"`
}
