const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const userService = require("./user-service.js");
const jwt = require('jsonwebtoken'); // Import the jsonwebtoken module
const passport = require("passport");
const { Strategy: JwtStrategy, ExtractJwt } = require("passport-jwt");

// Configure Passport to use JWT Strategy
passport.use(
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET, // JWT secret from environment
        },
        (jwtPayload, done) => {
            // In a real app, you might query the database for the user
            if (jwtPayload) {
                return done(null, jwtPayload); // Attach the payload to req.user
            }
            return done(null, false);
        }
    )
);

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

const HTTP_PORT = process.env.PORT || 8080;


app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ "message": msg });
        }).catch((msg) => {
            res.status(422).json({ "message": msg });
        });
});

app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            // Generate the payload with _id and userName from the user object
            const payload = {
                _id: user._id,
                userName: user.userName
            };

            // Sign the payload to create a JWT token
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Return the token in the response message
            res.json({ 
                "message": "Login successful",
                "token": token 
            });
        })
        .catch((msg) => {
            // Return an error response if user validation fails
            res.status(422).json({ "message": msg });
        });
});

// Protected routes using passport.authenticate()
app.get(
    "/api/user/favourites",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.getFavourites(req.user._id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.put(
    "/api/user/favourites/:id",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.addFavourite(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.delete(
    "/api/user/favourites/:id",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.removeFavourite(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.get(
    "/api/user/history",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.getHistory(req.user._id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.put(
    "/api/user/history/:id",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.addHistory(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

app.delete(
    "/api/user/history/:id",
    passport.authenticate("jwt", { session: false }),
    (req, res) => {
        userService.removeHistory(req.user._id, req.params.id)
            .then(data => res.json(data))
            .catch(msg => res.status(422).json({ error: msg }));
    }
);

userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => { console.log("API listening on: " + HTTP_PORT) });
    })
    .catch((err) => {
        console.log("Unable to start the server: " + err);
        process.exit();
    });
