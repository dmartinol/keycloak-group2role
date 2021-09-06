package main

import (
	"context"
	"fmt"
	"net/http"

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

var keycloakSpec KeycloakSpec
var ctx context.Context
var k *keycloak.Keycloak

func main() {
	p := properties.MustLoadFile("mapper.properties", properties.UTF8)
	keycloakSpec = KeycloakSpec{}
	keycloakSpec.server = p.GetString("keycloak.url", "localhost:8080")
	keycloakSpec.user = p.GetString("keycloak.user", "admin")
	keycloakSpec.password = p.GetString("keycloak.password", "password")
	keycloakSpec.realm = p.GetString("keycloak.realm", "rhpam")
	fmt.Printf("Keycloak specs: %+v\n", keycloakSpec)

	// create your oauth configuration
	config := oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: oauth2.Endpoint{
			TokenURL: keycloakSpec.server + "/auth/realms/master/protocol/openid-connect/token",
		},
	}

	// get a valid token from keycloak
	ctx = context.Background()
	token, err := config.PasswordCredentialsToken(ctx, keycloakSpec.user, keycloakSpec.password)
	if err != nil {
		panic(err)
	}

	// create a new http client that uses the token on every request
	client := config.Client(ctx, token)

	// create a new keycloak instance and provide the http client
	k, err = keycloak.NewKeycloak(client, keycloakSpec.server+"/auth/")
	if err != nil {
		panic(err)
	}
	fmt.Println("Logged in as ", k)

	realm, _, err := k.Realms.Get(ctx, keycloakSpec.realm)
	if err != nil {
		panic(err)
	}
	fmt.Printf("realm: %+v\n", realm)

	groups, _, err := k.Groups.List(ctx, keycloakSpec.realm)
	if err != nil {
		panic(err)
	}
	for _, g := range groups {
		checkGroup(g)
	}
}

func checkGroup(group *keycloak.Group) {
	fmt.Printf("Checking group: %v, %v\n", *group.Name, *group.ID)
	g, _, err := k.Groups.Get(ctx, keycloakSpec.realm, *group.ID)
	if err != nil {
		panic(err)
	}

	groupMapped := false
	for _, r := range g.RealmRoles {
		if r == *g.Name {
			fmt.Printf("\tgroup-role already in for: %v\n", *g.Name)
			groupMapped = true
			break
		}
	}

	if !groupMapped {
		fmt.Printf("\tgroup-role mapping is missing for: %v\n", *g.Name)
		mappedRole, _, err := k.RealmRoles.GetByName(ctx, keycloakSpec.realm, *g.Name)
		if err != nil {
			panic(err)
		}
		if mappedRole.ID == nil {
			mappedRole = &keycloak.Role{Name: group.Name}
			fmt.Printf("\tCreate missing role %v\n", *mappedRole.Name)
			_, err := k.RealmRoles.Create(ctx, keycloakSpec.realm, mappedRole)
			if err != nil {
				panic(err)
			}
			mappedRole, _, err = k.RealmRoles.GetByName(ctx, keycloakSpec.realm, *g.Name)
			if err != nil {
				panic(err)
			}
		} else {
			fmt.Printf("\tMapping role exists: %v/%v\n", *mappedRole.ID, *mappedRole.Name)
		}

		fmt.Printf("\tCreating mapping between group %v and role %v\n", *group.Name, *mappedRole.Name)
		addRoleToGroup(group, mappedRole)
	} else {
		fmt.Printf("\tgroup-role mapping being removed: %v\n", *g.Name)
		mappedRole, _, err := k.RealmRoles.GetByName(ctx, keycloakSpec.realm, *g.Name)
		if err != nil {
			panic(err)
		}
		removeRoleFromGroup(group, mappedRole)
	}

	for _, subGroup := range group.SubGroups {
		fmt.Printf("\tIterate on sub-group: %v\n", *subGroup.Name)
		checkGroup(subGroup)
	}
}

func addRoleToGroup(group *keycloak.Group, role *keycloak.Role) (*http.Response, error) {
	u := fmt.Sprintf("admin/realms/%s/groups/%s/role-mappings/realm", keycloakSpec.realm, *group.ID)
	fmt.Println("Sending POST to", u)
	roles := [1]*keycloak.Role{role}
	req, err := k.NewRequest(http.MethodPost, u, roles)
	if err != nil {
		return nil, err
	}

	return k.Do(ctx, req, nil)
}

func removeRoleFromGroup(group *keycloak.Group, role *keycloak.Role) (*http.Response, error) {
	u := fmt.Sprintf("admin/realms/%s/groups/%s/role-mappings/realm", keycloakSpec.realm, *group.ID)
	fmt.Println("Sending DELETE to", u)
	roles := [1]*keycloak.Role{role}
	req, err := k.NewRequest(http.MethodDelete, u, roles)
	if err != nil {
		return nil, err
	}

	return k.Do(ctx, req, nil)
}
