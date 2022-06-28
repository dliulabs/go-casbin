package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	_ "github.com/go-sql-driver/mysql"
)

func main() {

	// Initialize a Xorm adapter with MySQL database.
	// a, err := xormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/casbin")
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("error: adapter: %s", err)
	}

	sub := "alice" // the user that wants to access a resource.
	obj := "data1" // the resource that is going to be accessed.
	act := "read"  // the operation that the user performs on the resource.

	ok, err := e.Enforce(sub, obj, act)

	if err != nil {
		// handle err
		fmt.Printf("Alice failed to read data1: %v\n", err)
	}

	if ok == true {
		// permit alice to read data1
		fmt.Println("Alice permited read data1")
	} else {
		// deny the request, show an error
		fmt.Println("Alice denied read data1")
	}

	// You could use BatchEnforce() to enforce some requests in batches.
	// This method returns a bool slice, and this slice's index corresponds to the row index of the two-dimensional array.
	// e.g. results[0] is the result of {"alice", "data1", "read"}
	results, err := e.BatchEnforce([][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"jack", "data3", "read"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("Original policy: %v\n", results)

	var permissions = [][]string{{"data3", "read"}}
	for i := 0; i < len(permissions); i++ {
		e.AddPermissionsForUser("jack", permissions[i])
	}
	results, err = e.BatchEnforce([][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"jack", "data3", "read"},
	})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("New policy: %v\n", results)
}
