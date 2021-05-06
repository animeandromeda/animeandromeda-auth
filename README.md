# animeandromeda-auth

![logo](https://www.animeandromeda.net/static/media/Illustration.23741024.webp)

AnimeAndromeda Auth/User REST API

*The code is from September 2020 it needs a little review but it's pretty resilient.*

## endpoints
fixed prefix: /api

##### `/`  
Index, returns nothing

##### GET `/user` 
Checks the JSON Webtoken and if authenticated responds with the **safe** user information fetched from the database

##### POST `/user`
Create an user with the specified information from the form.
The passwords are hashed with bcrypt in order to guarantee max security.
These are the parameters that are needed
```javascript
    new User({
        username: req.body.username,
        email: req.body.email,
        password: hash,
    });
```
The created user will be identified by an unique id generated by MongoDB (_id field)

##### DELETE `/user`
If authenticated gives the user the ability to wipe his account from the database.

##### POST `/login`
Provided username and password, perform the login and, if successful, create, sign and responds with the JWT.
The JWT will also bet set on the header.

##### POST `/loved`
Update, if authenticated, the Loved anime list of an user with a specified one.
post param: loved

##### DELETE `/loved`
Delete, if authenticated, from the Loved anime list of an user a specified one.

##### POST `/timestamps`
Update, if authenticated, the current timestamp of the specified anime.

##### DELETE `/timestamps`
Purge, if authenticated, the current timestamp of the last watched anime.

##### POST `/pic`
Upload, if authenticated, a picture (with the limit of 2MB), encode it in base64 and save it into the database

##### POST `/background`
Same as the /pic endpoint

##### PATCH `/changeusername`
If authenticated, gives the user the ability to change it's username.
The _id will not be modified.
post param: username (the new username)

## classic setup
- tested on Linux and Microsoft Windows
- clone this repository
- tested with node 12 and 14

`cd into the project's directory`  
`npm i`  
`npm start`  
the API is exposed on the port 5005

## enviroment variable
In order to fully function the API needs 3 **Enviroment Variables**.
Create a **.env** file with this 3 ones:
`DB_AUTH = the mongodb encoded url for the database`  
`WEB_TOKEN_SECRET = a pseudo random string for crypto uses`  
`PHOTO_DEFAULT = a base64 encoded png photo for the profile, as the default one` 
```
Contatcs:  
Twitter: @Yun_sdvx
