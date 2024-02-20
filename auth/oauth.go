package auth

import (
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"net/http"
	"time"
	"html/template"
)

type authCodeFn func(string) func() string

func NewFileSourceClient(clientId, clientSecret, tokenFile string, authFn authCodeFn) (*http.Client, error) {
	conf := getConfig(clientId, clientSecret)

	// Read cached token
	token, exists, err := ReadToken(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to read token: %s", err)
	}

	// Require auth code if token file does not exist
	// or refresh token is missing
	if !exists || token.RefreshToken == "" {
		authUrl := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		authCode := authFn(authUrl)()
		token, err = conf.Exchange(oauth2.NoContext, authCode)
		if err != nil {
			return nil, fmt.Errorf("Failed to exchange auth code for token: %s", err)
		}
	}

	return oauth2.NewClient(
		oauth2.NoContext,
		FileSource(tokenFile, token, conf),
	), nil
}

func NewRefreshTokenClient(clientId, clientSecret, refreshToken string) *http.Client {
	conf := getConfig(clientId, clientSecret)

	token := &oauth2.Token{
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Now(),
	}

	return oauth2.NewClient(
		oauth2.NoContext,
		conf.TokenSource(oauth2.NoContext, token),
	)
}

func NewAccessTokenClient(clientId, clientSecret, accessToken string) *http.Client {
	conf := getConfig(clientId, clientSecret)

	token := &oauth2.Token{
		TokenType:   "Bearer",
		AccessToken: accessToken,
	}

	return oauth2.NewClient(
		oauth2.NoContext,
		conf.TokenSource(oauth2.NoContext, token),
	)
}

func NewServiceAccountClient(serviceAccountFile string) (*http.Client, error) {
	content, exists, err := ReadFile(serviceAccountFile)
	if(!exists) {
		return nil, fmt.Errorf("Service account filename %q not found", serviceAccountFile)
	}

	if(err != nil) {
		return nil, err
	}

	conf, err := google.JWTConfigFromJSON(content, "https://www.googleapis.com/auth/drive")
	if(err != nil) {
		return nil, err
	}
	return conf.Client(oauth2.NoContext), nil
}

func getConfig(clientId, clientSecret string) *oauth2.Config {
    server := &http.Server{Addr: ":1988"}
    go startLocalServer(server)
	
	return &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/drive"},
		RedirectURL:  "http://localhost:1988",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}
}

func startLocalServer(server *http.Server) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		paramValue := r.URL.Query().Get("code")
		if paramValue == "" {
			fmt.Fprintln(w, "<b>No code parameter in request</b>")
		} else {
			tmpl := `
				<label for="paramInput">Verification Code:</label><br />
				<textarea id="paramTextarea" style="width: 100%; padding: 5px; font-family: monospace; color: blue" readonly>{{.}}</textarea>`
            t := template.Must(template.New("textarea").Parse(tmpl))
			t.Execute(w, paramValue)
			go shutdownServer(server)
		}
	})
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Println("Error starting or stopping server:", err)
	}
}

func shutdownServer(server *http.Server) {
	if err := server.Shutdown(oauth2.NoContext); err != nil {
		fmt.Println("Error shutting down server:", err)
	}
}
