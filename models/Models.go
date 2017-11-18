package models

type Permission struct {
	ID          int    `goedb:"pk,autoincrement"`
	Name        string `goedb:"unique"`
	Description string
	Role        Role `goedb:"fk=Role(ID)"`
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
