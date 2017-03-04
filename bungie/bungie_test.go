package bungie_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"

	"golang.org/x/net/context"

	"github.com/zhirsch/oauth2"
	"github.com/zhirsch/oauth2/bungie"
)

func Example() {
	ctx := context.Background()

	// Create the config. The endpoint takes the authorization URL provided
	// by Bungie.  The ClientID is that API key, also provided by Bungie.
	conf := &oauth2.Config{
		Endpoint:  bungie.Endpoint("https://www.bungie.net/en/Application/Authorize/12345"),
		ClientID:  "f5058...84798",
		Exchanger: &bungie.Exchanger{},
	}

	// Display the URL for the user to visit to authorize the access.  Read
	// the code provided by the user from the redirected URL after
	// authorizing access.
	url := conf.AuthCodeURL("state")
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}

	// Get the access token.
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	// Make a request with the access token.
	client := conf.Client(ctx, tok)
	req, err := http.NewRequest("GET", "https://www.bungie.net/Platform/User/GetBungieNetUser/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("X-API-Key", conf.ClientID)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(dump))
}
