package containerupdate

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The Nextcloud stack as it was on 2026-10-17, trimmed to what ordering reads.
const composeNextcloudStack = `services:
  db:
    image: linuxserver/mariadb:11.8.8
  redis:
    image: redis:8-alpine
  nextcloud:
    image: nextcloud:35.0.1-apache
    depends_on:
      - db
      - redis
  nextcloud-cron:
    image: nextcloud:35.0.1-apache
    depends_on:
      - db
      - redis
  onlyoffice:
    image: onlyoffice/documentserver:10.0
`

func nextcloudHost() ([]store.ContainerStack, []models.Container) {
	stacks := []store.ContainerStack{{ID: uuid.New(), Enabled: true,
		Path: "/opt/stacks/nextcloud", Compose: composeNextcloudStack}}
	containers := []models.Container{
		{Name: "nextcloud-db-1", Repository: "linuxserver/mariadb", Tag: "11.8.8",
			ComposeDir: "/opt/stacks/nextcloud", ComposeService: "db"},
		{Name: "nextcloud-nextcloud-1", Repository: "nextcloud", Tag: "35.0.1-apache",
			ComposeDir: "/opt/stacks/nextcloud", ComposeService: "nextcloud"},
		{Name: "nextcloud-nextcloud-cron-1", Repository: "nextcloud", Tag: "35.0.1-apache",
			ComposeDir: "/opt/stacks/nextcloud", ComposeService: "nextcloud-cron"},
		{Name: "OnlyOffice", Repository: "onlyoffice/documentserver", Tag: "10.0",
			ComposeDir: "/opt/stacks/nextcloud", ComposeService: "onlyoffice"},
	}
	return stacks, containers
}

func order(images []store.RolloutImage) string {
	var s []string
	for _, im := range images {
		s = append(s, im.Repository)
	}
	return strings.Join(s, " ")
}

// The incident: the rollout listed nextcloud first, and applied it first.
func TestTheDatabaseIsUpdatedBeforeTheApplicationThatDependsOnIt(t *testing.T) {
	stacks, containers := nextcloudHost()
	images := []store.RolloutImage{
		{Repository: "nextcloud", FromTag: "35.0.1-apache", ToTag: "35.0.2-apache"},
		{Repository: "linuxserver/mariadb", FromTag: "11.8.8", ToTag: "11.8.8"},
	}
	if got := order(dependencyOrder(images, stacks, containers)); got != "linuxserver/mariadb nextcloud" {
		t.Fatalf("applied in the order %q; the database has to go before the application "+
			"whose entrypoint migrates it", got)
	}
}

func TestImagesWithNoDependencyBetweenThemKeepTheirOrder(t *testing.T) {
	stacks, containers := nextcloudHost()
	images := []store.RolloutImage{
		{Repository: "onlyoffice/documentserver", FromTag: "10.0", ToTag: "10.0"},
		{Repository: "nextcloud", FromTag: "35.0.1-apache", ToTag: "35.0.2-apache"},
		{Repository: "linuxserver/mariadb", FromTag: "11.8.8", ToTag: "11.8.8"},
	}
	// onlyoffice depends on nothing and nothing depends on it, so it stays first;
	// only nextcloud moves, behind the database it needs.
	want := "onlyoffice/documentserver linuxserver/mariadb nextcloud"
	if got := order(dependencyOrder(images, stacks, containers)); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Two projects can both have a "db". One project's app does not wait on the other
// project's database.
func TestADependencyIsScopedToItsOwnProject(t *testing.T) {
	stacks := []store.ContainerStack{
		{Enabled: true, Path: "/opt/a", Compose: "services:\n  app:\n    image: app:1\n    depends_on:\n      - db\n  db:\n    image: postgres:17.1\n"},
		{Enabled: true, Path: "/opt/b", Compose: "services:\n  db:\n    image: mariadb:11.4\n"},
	}
	containers := []models.Container{
		{Repository: "app", Tag: "1", ComposeDir: "/opt/a", ComposeService: "app"},
		{Repository: "postgres", Tag: "17.1", ComposeDir: "/opt/a", ComposeService: "db"},
		{Repository: "mariadb", Tag: "11.4", ComposeDir: "/opt/b", ComposeService: "db"},
	}
	images := []store.RolloutImage{
		{Repository: "app", FromTag: "1", ToTag: "2"},
		{Repository: "mariadb", FromTag: "11.4", ToTag: "11.4"},
	}
	if got := order(dependencyOrder(images, stacks, containers)); got != "app mariadb" {
		t.Fatalf("got %q: project a's app was held behind project b's database", got)
	}
}

func TestATransitiveDependencyStillOrders(t *testing.T) {
	stacks := []store.ContainerStack{{Enabled: true, Path: "/opt/x",
		Compose: "services:\n  web:\n    image: web:1\n    depends_on: [api]\n  api:\n    image: api:1\n    depends_on: [db]\n  db:\n    image: postgres:17.1\n"}}
	images := []store.RolloutImage{
		{Repository: "web", FromTag: "1", ToTag: "2"},
		{Repository: "postgres", FromTag: "17.1", ToTag: "17.2"},
	}
	if got := order(dependencyOrder(images, stacks, nil)); got != "postgres web" {
		t.Fatalf("got %q: web needs the database through api", got)
	}
}

func TestADependencyCycleFallsBackToTheOriginalOrder(t *testing.T) {
	stacks := []store.ContainerStack{{Enabled: true, Path: "/opt/c",
		Compose: "services:\n  a:\n    image: a:1\n    depends_on: [b]\n  b:\n    image: b:1\n    depends_on: [a]\n"}}
	images := []store.RolloutImage{
		{Repository: "a", FromTag: "1", ToTag: "2"},
		{Repository: "b", FromTag: "1", ToTag: "2"},
	}
	if got := order(dependencyOrder(images, stacks, nil)); got != "a b" {
		t.Fatalf("got %q, want the original order", got)
	}
}
