package main

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/dgrijalva/jwt-go"
    "github.com/go-martini/martini"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
    //"go.mongodb.org/mongo-driver/mongo/readpref"
    "golang.org/x/crypto/bcrypt"

    "jwtd/mongoutils"
)

type App struct {
    M *mongoutils.Mongo
    C *Config
}

type Reply struct {
    Status  int
    Message string
    Payload SlimToken
    Extra   map[string]int64
}

type Config struct {
    Addr   string
    TTL    ttl
    Secret string
}

type ttl struct {
    Access  int64
    Refresh int64
}

type TokenPair struct {
    Access  SlimToken
    Refresh SlimToken
}

type SlimToken map[string]string

type User struct {
    UserId        string
    RefreshTokens []SlimToken
}

func BCrypt(data []byte, cost int) (string, error) {
    /* hash token */
    if cost == -1 {
        cost = bcrypt.DefaultCost
    }
    result, err := bcrypt.GenerateFromPassword(data, cost)
    return string(result), err

}

func encode_b64(data string) string {
    data = base64.StdEncoding.EncodeToString([]byte(data))
    return data
}

func decode_b64(src string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(src)
    if err == nil {
        return string(data), nil
    }
    return "", err
}

func BCryptCompare(hashedPassword, password []byte) error {
    /*  compare hash token */
    ok := bcrypt.CompareHashAndPassword(hashedPassword, password)
    return ok
}

func (app *App) GenerateToken(
    claims map[string]interface{},
) (string, string, error) {
    /* generating a token */

    var err error
    // signing the token
    token := jwt.New(jwt.SigningMethodHS512)

    tokenClaims := token.Claims.(jwt.MapClaims)
    for k, v := range claims {
        tokenClaims[k] = v
    }

    strToken, err := token.SignedString([]byte(app.C.Secret))
    if err != nil {
        return "", "", err
    }

    expires := strconv.Itoa(int(tokenClaims["exp"].(int64)))

    return strToken, expires, nil
}

func (app *App) TokenIsBind(accessToken, refreshToken string) (bool, error) {

    bindAccess := accessToken[len(accessToken)-10:]

    token, err := jwt.Parse(refreshToken,
        func(token *jwt.Token) (interface{}, error) {
            return []byte(app.C.Secret), nil
        },
    )
    if err != nil {
        return false, err
    }

    claims := token.Claims.(jwt.MapClaims)
    bindRefresh := claims["bind"].(string)
    return bindAccess == bindRefresh, nil

}

func (app *App) TokenIsValid(checkToken string) (bool, error) {

    token, err := jwt.Parse(checkToken, func(token *jwt.Token) (interface{}, error) {
        return []byte(app.C.Secret), nil
    })

    validationErrors := jwt.ValidationErrorExpired | jwt.ValidationErrorNotValidYet
    if token.Valid {
        return true, nil
    } else if ve, ok := err.(*jwt.ValidationError); ok {
        if ve.Errors&jwt.ValidationErrorMalformed != 0 {
            return false, errors.New("ValidationErrorMalformed")
        } else if ve.Errors&validationErrors != 0 {
            // Token is either expired or not active yet
            return false, errors.New("ValidationErrorExpired")
        } else {
            return false, fmt.Errorf(
                "Couldn't handle this token: %s", err.Error(),
            )
        }
    } else {
        return false, fmt.Errorf(
            "Couldn't handle this token: %s", err.Error(),
        )
    }
}

func (app *App) CreateTokenPair(userID string) (TokenPair, error) {
    /* generating a pair of tokens */

    var err error
    pairs := TokenPair{}
    expires := time.Now().Add(
        time.Second * time.Duration(app.C.TTL.Access),
    ).Unix()

    claims := map[string]interface{}{
        "userid": userID,
        "iss":    "Bill Gates",
        "exp":    expires,
    }

    accessToken, expiresAccess, err := app.GenerateToken(claims)

    expires = time.Now().Add(
        time.Second * time.Duration(app.C.TTL.Refresh),
    ).Unix()
    claims = map[string]interface{}{
        "userid": userID,
        "exp":    expires,
        "bind":   accessToken[len(accessToken)-10:],
    }
    refreshToken, expiresRefresh, err := app.GenerateToken(claims)

    if err != nil {
        return pairs, err
    }

    pairs = TokenPair{
        Access: SlimToken{
            "token":   accessToken,
            "expires": expiresAccess,
        },
        Refresh: SlimToken{
            "token":   refreshToken,
            "expires": expiresRefresh,
        },
    }

    return pairs, nil
}

func (app *App) FindTokens(
    ctx context.Context,
    userID, refreshToken string) (string, error) {
    /* See if the specified token exists in the database */

    var err error
    var foundToken string

    result := app.M.FindOne(ctx, bson.M{"id": userID})
    if result.Err() != nil {
        // user not found
        return "", result.Err()
    }

    user := User{}
    err = result.Decode(&user)

    if err != nil {
        return "", err
    }

    fmt.Printf("%d %#v\n", len(user.RefreshTokens), user.RefreshTokens)

    if len(user.RefreshTokens) == 0 {
        return "", fmt.Errorf(
            "Not found refresh tokens for user with id <%s>",
            userID)
    }

    for _, token := range user.RefreshTokens {
        errCmp := BCryptCompare(
            []byte(token["token"]),
            []byte(refreshToken))

        if errCmp != nil {
            continue
        } else {
            foundToken = token["token"]
            break
        }

    }
    if foundToken == "" {
        err = fmt.Errorf(
            "None of the tokens matched with id <%s>", userID)
    }
    return foundToken, err
}

func (app *App) UpsertTokens(
    ctx context.Context,
    userID string) (TokenPair, int, error) {
    /* inserting or updating an entry */

    var err error
    pairs := TokenPair{}
    // generating a pair of tokens
    pairs, err = app.CreateTokenPair(userID)
    if err != nil {
        return pairs, 500, err
    }
    // extracting the refresh token
    slimTokenRefresh := pairs.Refresh

    // hash the token
    hashedToken, err := BCrypt([]byte(slimTokenRefresh["token"]), -1)
    if err != nil {
        return pairs, 500, err
    }

    refreshTokens := make([]SlimToken, 0)
    refreshTokens = append(refreshTokens,
        SlimToken{
            "token":   hashedToken,
            "expires": slimTokenRefresh["expires"],
        },
    )
    filter := bson.M{"id": userID}
    update := bson.M{"$set": bson.M{"refreshTokens": refreshTokens}}
    _, err = app.M.UpsertOne(ctx, filter, update)

    if err != nil {
        return pairs, 500, err
    }

    return pairs, 200, nil
}

func (app *App) RefreshTokens(
    ctx context.Context,
    userID,
    refreshToken,
    accessToken string) (TokenPair, int, error) {
    /* Request a new token pair for a refresh token */

    var err error
    pairs := TokenPair{}

    //punching the token through the database
    _, err = app.FindTokens(ctx, userID, refreshToken)
    // token not found
    if err != nil {
        return pairs, 401, err // Unauthorized
    }

    // validation of the access token
    if ok, err := app.TokenIsValid(accessToken); !ok {
        return pairs, 401, fmt.Errorf("Access Token: %s", err.Error()) // Unauthorized
    }
    // validation of the refresh token
    if ok, err := app.TokenIsValid(refreshToken); !ok {
        return pairs, 401, fmt.Errorf("Refresh Token: %s", err.Error()) // Unauthorized
    }
    // checking access token binding to refresh token
    ok, err := app.TokenIsBind(accessToken, refreshToken)
    if err != nil {
        return pairs, 401, fmt.Errorf("Refresh Token: %s", err.Error()) // Unauthorized
    } else if !ok {
        return pairs, 401, errors.New("Refresh Token not tied") // Unauthorized
    }

    // generating a pair of tokens
    pairs, err = app.CreateTokenPair(userID)
    if err != nil {
        return pairs, 500, err
    }
    //extracting the refresh token
    slimTokenRefresh := pairs.Refresh

    // hash the token
    hashedToken, err := BCrypt([]byte(slimTokenRefresh["token"]), -1)
    if err != nil {
        return pairs, 500, err
    }

    filter := bson.M{"id": userID}
    //adding new refresh tokens to existing ones
    update := bson.M{"$push": bson.M{
        "refreshTokens": SlimToken{
            "token":   hashedToken,
            "expires": slimTokenRefresh["expires"],
        },
    },
    }

    _, err = app.M.UpdateOne(ctx, filter, update)
    if err != nil {
        return pairs, 500, err
    }

    return pairs, 200, nil
}

func (app *App) DeleteTokens(
    ctx context.Context,
    userID, refreshToken string) (*mongo.UpdateResult, int, error) {
    /* Deleting a refresh token from the user's collection */

    var err error
    var foundToken string
    var updateResult *mongo.UpdateResult
    var update bson.M

    filter := bson.M{"id": userID}

    refreshTokens := make([]SlimToken, 0)

    singleResult := app.M.FindOne(ctx, bson.M{"id": userID})
    if singleResult.Err() != nil {
        // user not found
        return nil, 401, singleResult.Err()
    }

    if refreshToken != "" {
        // punching the token through the database
        foundToken, err = app.FindTokens(ctx, userID, refreshToken)
        // token not found
        if err != nil {
            return nil, 401, err
        }

        //deleting a specific token
        pullFilter := bson.M{
            "refreshTokens": bson.M{"token": foundToken},
        }
        update = bson.M{"$pull": pullFilter}
    } else {
        // deleting all tokens by setting an empty list
        update = bson.M{"$set": bson.M{"refreshTokens": refreshTokens}}
    }

    updateResult, err = app.M.UpdateOne(ctx, filter, update)
    if err != nil {
        return nil, 500, err
    }

    if updateResult.MatchedCount == 0 {
        return nil, 401, errors.New("No matches found for filter")
    }

    return updateResult, 200, nil
}

func write_and_log_err(
    w http.ResponseWriter,
    statusCode int,
    err error, where string) {

    reply := &Reply{Message: err.Error(), Status: statusCode}
    body, errJSON := json.Marshal(reply)

    if errJSON != nil {
        w.WriteHeader(500)
        w.Write([]byte(errJSON.Error()))
    } else {

        w.WriteHeader(statusCode)
        w.Header().Set("Content-Type", "application/json")
        w.Write(body)

        fmt.Printf("[%s] %s\n", where, err.Error())
    }
}

func (app *App) TokenPairsHandler(
    w http.ResponseWriter,
    r *http.Request) {
    /*  Token request handler */

    var err error
    pairs := TokenPair{}
    var status int

    r.ParseForm()
    params := r.Form
    userID := params.Get("id")
    ctx := context.TODO()
    pairs, status, err = app.UpsertTokens(ctx, userID)

    if err != nil {
        write_and_log_err(w, status, err, "TOKEN PAIRS HANDLER")
        return
    }
    log.Printf("%#v", pairs)

    reply := &Reply{
        Message: "", Status: 200,
        Payload: pairs.Access,
    }
    body, err := json.Marshal(reply)
    if err != nil {
        write_and_log_err(w, 500, err, "TOKEN PAIRS HANDLER")
        return
    }

    cookieStore := http.Cookie{
        Name:     "refreshtoken",
        Path:     "/tokens",
        Value:    encode_b64(pairs.Refresh["token"]),
        HttpOnly: true,
        Expires:  time.Now().Add(24 * 30 * time.Hour),
    }
    // write the cookie to response
    http.SetCookie(w, &cookieStore)

    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    w.Write(body)
}

func (app *App) RefreshTokenHandler(
    w http.ResponseWriter,
    r *http.Request) {
    /*  Token update handler */

    var err error
    pairs := TokenPair{}
    var status int
    var body []byte
    var refreshToken string
    var accessToken string

    r.ParseForm()
    params := r.Form
    userID := params.Get("id")
    // Read cookie
    cookie, err := r.Cookie("refreshtoken")
    if err != nil {
        write_and_log_err(w, 401,
            fmt.Errorf("Can't find cookie"), "REFRESH TOKEN HANDLER")
        return
    }

    refreshToken, err = decode_b64(cookie.Value)
    if err != nil {
        write_and_log_err(w, 500, err, "TOKEN PAIRS HANDLER")
        return
    }

    authorization := r.Header.Get("Authorization")
    if authorization != "" {
        accessToken = strings.TrimSpace(
            strings.Join(strings.Split(authorization, "Bearer"), ""),
        )
    } else {
        write_and_log_err(w, 401,
            fmt.Errorf("Authorization header was not found"),
            "REFRESH TOKEN HANDLER")
        return
    }

    log.Printf("Old Access  Token %s\n", accessToken)
    log.Printf("Old Refresh Token %s\n", refreshToken)

    ctx := context.TODO()
    pairs, status, err = app.RefreshTokens(
        ctx, userID, refreshToken, accessToken)

    if err != nil {
        write_and_log_err(w, status, err, "REFRESH TOKEN HANDLER")
        return
    }

    log.Printf("New Access  Token %s\n", pairs.Access["token"])
    log.Printf("New Refresh Token %s\n", pairs.Refresh["token"])

    reply := &Reply{
        Message: "", Status: 200,
        Payload: pairs.Access,
    }
    body, err = json.Marshal(reply)
    if err != nil {
        write_and_log_err(w, 500, err, "REFRESH TOKEN HANDLER")
        return
    }

    cookieStore := http.Cookie{
        Name:     "refreshtoken",
        Path:     "/tokens",
        Value:    encode_b64(pairs.Refresh["token"]),
        HttpOnly: true,
        Expires:  time.Now().Add(24 * 30 * time.Hour),
    }
    // write the cookie to response
    http.SetCookie(w, &cookieStore)

    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    w.Write(body)
}

func (app *App) DeleteTokenHandler(
    w http.ResponseWriter,
    r *http.Request) {
    /* Handler for the delete token */

    var err error
    var body []byte
    var result *mongo.UpdateResult
    var status int
    var refreshToken string

    r.ParseForm()
    params := r.Form
    userID := params.Get("id")

    if r.URL.Path == "/delete" {
        // Read cookie
        cookie, err := r.Cookie("refreshtoken")
        if err == nil {
            refreshToken, err = decode_b64(cookie.Value)
            if err != nil {
                write_and_log_err(w, 500, err, "TOKEN PAIRS HANDLER")
                return
            }

        }
    }
    ctx := context.TODO()
    result, status, err = app.DeleteTokens(ctx, userID, refreshToken)
    if err != nil {
        write_and_log_err(w, status, err, "DELETE TOKEN HANDLER")
        return
    }

    extra := map[string]int64{
        "MatchedCount":  result.MatchedCount,
        "ModifiedCount": result.ModifiedCount,
        "UpsertedCount": result.UpsertedCount,
    }

    reply := &Reply{Message: "", Status: 200, Extra: extra}
    body, err = json.Marshal(reply)
    if err != nil {
        write_and_log_err(w, 500, err, "DELETE TOKEN HANDLER")
        return
    }
    // delete cookie
    cookieStore := http.Cookie{
        Name:    "refreshtoken",
        Value:   "",
        Expires: time.Now().Add(-1 * time.Hour),
        MaxAge:  -1,
    }
    // write the cookie to response
    http.SetCookie(w, &cookieStore)

    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    w.Write(body)
}

func (app *App) Serve() {
    /* Run server */

    m := martini.Classic()
    //store := sessions.NewCookieStore([]byte("secret123"))
    //store.Options.Path = "/"
    //m.Use(sessions.Sessions("jwt", store))

    m.Group(`/tokens`, func(r martini.Router) {
        r.Post(`/new`, app.TokenPairsHandler)
        r.Post(`/refresh`, app.RefreshTokenHandler)
        r.Post(`/delete`, app.DeleteTokenHandler)
        r.Post(`/delete/all`, app.DeleteTokenHandler)
    })
    m.RunOnAddr(app.C.Addr)
}
  

func main() {
    var err error
    var PORT, SERVER, ADDR string

    serverAddr := flag.String("server", "", "Адрес с которого приложение будет принимать запросы")
    portNum := flag.String("port", "", "Порт, который приложение будет слушать")
    mongoOnAddr := flag.String("mongo-on-addr", ":27017", "ip/сервер и порт запуска MongoDB")
    adminDB := flag.String("db-admin", "", "Имя администратора  БД")
    adminPwdDB := flag.String("db-admin-pwd", "", "Пароль администратора БД")
    userDB := flag.String("db-user", "test", "Имя пользователя")
    userPwdDB := flag.String("db-user-pwd", "test", "Пароль пользователя для подключения")
    defaultDB := flag.String("db", "testdb", "Имя базы данных для подключения")
    
    collectionName := flag.String("db-collection", "users", "Имя таблицы(коллекции)")
    replicaName := flag.String("replica-set", "", "Имя реплики")
    secretWord := flag.String("secret", "secret", "Cекретное слово")
    accessTTL := flag.Int("access-ttl", 1*60*60, "Время жизни (в сек.)  access токена")
    refreshTTL := flag.Int("refresh-ttl", 30*60, "Время жизни (в сек.)  refresh токена")

    flag.Parse()
    
    if *adminDB != "" && *adminPwdDB!= "" {
        *defaultDB = "admin"
    }
    
    PORT = *portNum
    SERVER = *serverAddr

    if PORT == "" {
        PORT = os.Getenv("PORT")
        if PORT == "" {
            PORT = "3001"
        }
    }

    if SERVER == "" {
        SERVER = os.Getenv("SERVER_URL")
    }

    ADDR = fmt.Sprintf("%s:%s", SERVER, PORT)

    m := &mongoutils.Mongo{
        Options:        options.Client(), // *options.ClientOptions{}
        Ctx:            context.TODO(),
        DB:             *defaultDB,
        CollectionName: *collectionName,
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    driver := "mongodb"
    if _,_, err := net.SplitHostPort(*mongoOnAddr); err != nil {
        // если адрес указан без порта, то меняем строку имени драйвера
        driver = "mongodb+srv"
    }    
    
    connectURI := os.Getenv("MONGOLAB_URI")
    if connectURI == "" {
        connectURI = fmt.Sprintf(
            "%s://%s:%s@%s/%s?retryWrites=true&w=majority", driver,
            *userDB, *userPwdDB, *mongoOnAddr, *defaultDB )
    }
    fmt.Println(connectURI)

    //credentials := options.Credential{
    //    AuthSource: *defaultDB, 
    //    Username: *userDB, 
    //    Password: *userPwdDB,
    //}
    
    err = m.Connect(ctx, connectURI, nil)
    if err != nil {
        log.Fatalf("[CONNECT] %s", err.Error())
    } else {
        fmt.Println("[CONNECT] ESTABLISHED")
    }
    
    var singleResult *mongo.SingleResult
    if *replicaName != "" {
        m.Options.SetReplicaSet(*replicaName)
        //singleResult = m.CreateReplicaSet(m.Ctx, *replicaName)
        //if err = singleResult.Err(); err != nil {
        //    log.Fatalf("[CREATE REPLICA] %s", err.Error())   
        //}
    }
    
    fmt.Println(m.Options.GetURI())

    m.GetOrCreate(m.DB, m.CollectionName)
    
    if *adminDB != "" && *adminPwdDB!= "" {
        /* создание юзера при подключении от админа;  
        не используется, так как непонятно как переключиться на другую БД
        чтобы пользователя создавался не в базе admin. db.getSiblingDB() в mongo
        driver не имплементировано
        */
        ctx = context.WithValue(m.Ctx, "db", *defaultDB)
        singleResult = m.CreateUser(ctx, *userDB, *userPwdDB)
        if err = singleResult.Err(); err != nil {
            log.Fatalf("[CREATE USER] %s", err.Error())   
        }
    }
    
    app := &App{
        C: &Config{
            Addr: ADDR, Secret: *secretWord,
            TTL: ttl{
                Access:  int64(*accessTTL),
                Refresh: int64(*refreshTTL),
            },
        },
        M: m,
    }

    app.Serve()

    m.Client.Disconnect(context.TODO())
}
