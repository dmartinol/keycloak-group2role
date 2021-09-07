package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/magiconair/properties"
	"github.com/zemirco/keycloak"
	"golang.org/x/oauth2"
)

type KeycloakSpec struct {
	server   string
	user     string
	password string
	realm    string
}

var dryRunOnly = false
var keycloakSpec KeycloakSpec
var ctx context.Context
var k *keycloak.Keycloak

var missingRoles = []string{}
var groupsWithMissingRole = map[string]string{}

func main() {
	initProps()
	connectToKeycloak()
	validateRealm()

	prepareMapper()
	printMapper()
	if !dryRunOnly {
		createRolesAndMappings()
	} else {
		fmt.Printf("\nNote: Disable or remove the %v option in %v to create the missing roles and mappings", PROPS_DRYRUN, PROPS_FILE_NAME)
	}
}

const PROPS_FILE_NAME = "mapper.properties"
const PROPS_DRYRUN = "dry.run.only"
const PROPS_URL = "keycloak.url"
const PROPS_USER = "keycloak.user"
const PROPS_PASSWORD = "keycloak.password"
const PROPS_REALM = "keycloak.realm"

func templateProps() {
	template := map[string]string{
		PROPS_DRYRUN:   "false",
		PROPS_URL:      "http://localhost:8080",
		PROPS_USER:     "admin",
		PROPS_PASSWORD: "password",
		PROPS_REALM:    "realm",
	}
	p := properties.LoadMap(template)
	f, _ := os.Create(PROPS_FILE_NAME)
	w := bufio.NewWriter(f)
	p.Write(w, properties.UTF8)
	w.Flush()
}

func initProps() {
	p, err := properties.LoadFile(PROPS_FILE_NAME, properties.UTF8)
	if err != nil {
		fmt.Printf("Missing properties file %s. Creating a default template for you\n", PROPS_FILE_NAME)
		templateProps()
		panic(err)
	}
	dryRunOnly = p.GetBool(PROPS_DRYRUN, false)
	keycloakSpec = KeycloakSpec{}
	keycloakSpec.server = p.MustGetString(PROPS_URL)
	keycloakSpec.user = p.MustGetString(PROPS_USER)
	keycloakSpec.password = p.MustGetString(PROPS_PASSWORD)
	keycloakSpec.realm = p.MustGetString(PROPS_REALM)
	fmt.Println("*** Running with ***")
	fmt.Printf("Dry run only: %v\n", dryRunOnly)
	fmt.Printf("Keycloak specs: %v\n", keycloakSpec)
}

func connectToKeycloak() {
	config := oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{
			TokenURL: keycloakSpec.server + "/auth/realms/master/protocol/openid-connect/token",
		},
	}

	ctx = context.Background()
	token, err := config.PasswordCredentialsToken(ctx, keycloakSpec.user, keycloakSpec.password)
	if err != nil {
		panic(err)
	}

	client := config.Client(ctx, token)
	k, err = keycloak.NewKeycloak(client, keycloakSpec.server+"/auth/")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Logged in to %v\n ", keycloakSpec.server)
}

func validateRealm() {
	realm, _, err := k.Realms.Get(ctx, keycloakSpec.realm)
	if err != nil {
		panic(err)
	}
	if realm.ID == nil {
		panic(fmt.Sprintf("Provided realm '%s' is not configured", keycloakSpec.realm))
	}
	fmt.Printf("Found realm: %v\n", *realm.Realm)
}

func prepareMapper() {
	groups, _, err := k.Groups.List(ctx, keycloakSpec.realm)
	if err != nil {
		panic(err)
	}
	for _, g := range groups {
		prepareMapperForGroup(g)
	}
}

func prepareMapperForGroup(group *keycloak.Group) {
	fmt.Printf("Preparing mapper for group: %v/%v\n", *group.Name, *group.ID)
	g, _, err := k.Groups.Get(ctx, keycloakSpec.realm, *group.ID)
	if err != nil {
		panic(err)
	}

	groupMapped := false
	for _, r := range g.RealmRoles {
		if r == *g.Name {
			fmt.Printf("\tRole %v is already mapped\n", *g.Name)
			groupMapped = true
			break
		}
	}

	if !groupMapped {
		fmt.Printf("\tRole mapping is missing for: %v\n", *g.Name)
		mappedRole := getRoleGyName(*g.Name)
		if mappedRole.ID == nil {
			missingRoles = append(missingRoles, *g.Name)
		} else {
			fmt.Printf("\tMapping role already exists: %v/%v\n", *mappedRole.ID, *mappedRole.Name)
		}

		groupsWithMissingRole[*g.ID] = *g.Name
	}

	for _, subGroup := range group.SubGroups {
		fmt.Printf("\tIterate on sub-group: %v\n", *subGroup.Name)
		prepareMapperForGroup(subGroup)
	}
}

func printMapper() {
	if anyConfigurationNeeded() {
		fmt.Println("*** The following missing roles will be created ***")
		for _, roleName := range missingRoles {
			fmt.Printf("Role %v\n", roleName)
		}
		fmt.Println("*** The following mappings will be created ***")
		for _, groupName := range groupsWithMissingRole {
			fmt.Printf("Group %v to Role %v\n", groupName, groupName)
		}
	} else {
		fmt.Println("*** All roles and mappings are already set, no changes needed ***")
	}
}

func anyConfigurationNeeded() bool {
	return len(missingRoles) > 0 || len(groupsWithMissingRole) > 0
}

func createRolesAndMappings() {
	if anyConfigurationNeeded() {
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Do you really want to continue? (Y/N): ")
		answer, _ := reader.ReadString('\n')

		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(answer)), "Y") {
			fmt.Println("*** Creating missing roles ***")
			for _, roleName := range missingRoles {
				createRoleByName(roleName)
			}
			fmt.Println("*** Creating missing mappings ***")
			for groupID, groupName := range groupsWithMissingRole {
				addRoleToGroup(groupID, getRoleGyName(groupName))
			}
		}
	}
}

func createRoleByName(name string) {
	role := &keycloak.Role{Name: &name}
	fmt.Printf("Creating missing role %v\n", *role.Name)
	_, err := k.RealmRoles.Create(ctx, keycloakSpec.realm, role)
	if err != nil {
		panic(err)
	}
}

func getRoleGyName(name string) *keycloak.Role {
	role, _, err := k.RealmRoles.GetByName(ctx, keycloakSpec.realm, name)
	if err != nil {
		panic(err)
	}
	return role
}

func addRoleToGroup(groupID string, role *keycloak.Role) {
	groupName := groupsWithMissingRole[groupID]
	mappedRole := getRoleGyName(groupName)
	fmt.Printf("Creating mapping between group %v and role %v/%v\n", groupName, *mappedRole.Name, *mappedRole.ID)
	var mappedRoles = []*keycloak.Role{mappedRole}
	k.Groups.AddRealmRoles(ctx, keycloakSpec.realm, groupID, mappedRoles)
}
