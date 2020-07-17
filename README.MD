# jwtd

Json Web Tokens authentication server

```sh
Usage of jwtd:
  -access-ttl int
        Время жизни (в сек.)  access токена (default 3600)
  -db string
        Имя базы данных для подключения (default "testdb")
  -db-admin string
        Имя администратора  БД
  -db-admin-pwd string
        Пароль администратора БД
  -db-collection string
        Имя таблицы(коллекции) (default "users")
  -db-user string
        Имя пользователя (default "test")
  -db-user-pwd string
        Пароль пользователя для подключения (default "test")
  -mongo-on-addr string
        ip/сервер и порт запуска MongoDB (default ":27017")
  -port string
        Порт, который приложение будет слушать
  -refresh-ttl int
        Время жизни (в сек.)  refresh токена (default 1800)
  -replica-set string
        Имя реплики
  -secret string
        Cекретное слово (default "secret")
  -server string
        Адрес с которого приложение будет принимать запросы

```

## Testing Locally

```sh
curl -i -X POST http://127.0.0.1:3001/tokens/new        --cookie-jar jwatapp.cookie --data "id=1"
curl -i -X POST http://127.0.0.1:3001/tokens/refresh    --cookie-jar jwatapp.cookie --cookie jwatapp.cookie --data "id=1"  -H "Authorization: Bearer $TOKEN" 
curl -i -X POST http://127.0.0.1:3001/tokens/delete     --data "id=1"  --cookie jwatapp.cookie
curl -i -X POST http://127.0.0.1:3001/tokens/delete/all --data "id=1"
```

- [jwtd on Heroku](https://jwtd.herokuapp.com)