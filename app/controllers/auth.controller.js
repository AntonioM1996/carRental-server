const config = require("../config/auth.config");
const db = require("../models");
const { OAuth2Client } = require('google-auth-library');
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
const keys = require("../config/client_secret_929370134314-j43cianv66ff0kl77cqn31oiogi1ebdi.apps.googleusercontent.com.json");

exports.signup = (req, res) => {
    const user = new User({
        username: req.body.username,
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8),
        firstName: req.body.firstName,
        lastName: req.body.lastName
    });

    user.save().then(user => {
        if (req.body.roles) {
            Role.find(
                {
                    name: { $in: req.body.roles }
                }
                .then(roles => {
                    user.roles = roles.map(role => role._id);
                    user.save().then(result => {
                        res.send({ message: "User was registered successfully!" });
                    });
                })
            );
        } else {
            Role.findOne({ name: "user" }).then(role => {
                user.roles = [role._id];
                user.save().then(result => {
                    res.send({ message: "User was registered successfully!" });
                });
            });
        }
    });
};

exports.signin = (req, res) => {
    console.log(req.body);

    User.findOne({
        username: req.body.username
    })
        .populate("roles", "-__v")
        .then(user => {
            console.log(user);
            
            if (!user) {
                return res.status(401).send({ message: "Invalid username or password." });
            }

            var passwordIsValid = bcrypt.compareSync(
                req.body.password,
                user.password
            );

            if (!passwordIsValid) {
                return res.status(401).send({
                    message: "Invalid username or password."
                });
            }

            const accessToken = jwt.sign({ id: user._id },
                config.secret,
                {
                    algorithm: 'HS256',
                    allowInsecureKeySizes: true,
                    expiresIn: config.accessTokenDuration,
                }
            );

            const refreshToken = jwt.sign({ id: user._id }, config.secret); // no expiration

            var authorities = [];

            for (let i = 0; i < user.roles.length; i++) {
                authorities.push("ROLE_" + user.roles[i].name.toUpperCase());
            }
            res.status(200).send({
                id: user._id,
                username: user.username,
                email: user.email,
                roles: authorities,
                firstName: user.firstName,
                lastName: user.lastName,
                name: user.name,
                accessToken: accessToken,
                refreshToken: refreshToken
            });
        })
        .catch(err => {
            if (err) {
                res.status(500).send({ message: err });
                return;
            }
        });
};

exports.getUser = (req, res) => {
    let token = req.headers["x-access-token"];
    let userId;

    if (!token) {
        return response.status(403).send({ message: "No token provided!" });
    }

    try {
        let decodedToken = jwt.verify(token, config.secret);
        userId = decodedToken.id;
    }
    catch(error) {
        return response.status(401).send({
            message: "Unauthorized!",
        });
    }

    if(userId) {
        User.findById(userId).then(result => {
            console.log(result);

            if(!result) {
                return res.status(404).send({ message: "User Not found." });
            }

            res.status(200).send({
                id: result._id,
                username: result.username,
                email: result.email,
                firstName: result.firstName,
                lastName: result.lastName,
                name: result.name
            });
        });
    }
}

exports.googleSignIn = (req, res) => {
    console.log("googleSignIn...");
    const client = new OAuth2Client(keys.web.client_id);
    const googleIdToken = req.body.idToken;

    if(googleIdToken && client) {
        client.verifyIdToken({
            idToken: googleIdToken,
            audience: config.carRentalClientId
        }).then(loginTicket => {
            const ticketPayload = loginTicket.getPayload();

            User.findOne({
                googleId: ticketPayload.sub
            }).populate("roles", "-__v").then(user => {
                if(user) {
                    // TODO search for email: searching only for googleId, I'll end up with two users with same username if he's 
                    // already locally registered
                    // TODO update User data from Google idToken?

                    const accessToken = jwt.sign({ id: user._id },
                        config.secret,
                        {
                            algorithm: 'HS256',
                            allowInsecureKeySizes: true,
                            expiresIn: config.accessTokenDuration, 
                        }
                    );
        
                    const refreshToken = jwt.sign({ id: user._id }, config.secret); // no expiration
        
                    var authorities = [];
        
                    for (let i = 0; i < user.roles.length; i++) {
                        authorities.push("ROLE_" + user.roles[i].name.toUpperCase());
                    }
                    res.status(200).send({
                        id: user._id,
                        username: user.username,
                        email: user.email,
                        roles: authorities,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        name: user.name,
                        accessToken: accessToken,
                        refreshToken: refreshToken,
                        profilePicture: user.profilePicture
                    });
                }
                else {
                    const user = new User({
                        username: ticketPayload.email,
                        email: ticketPayload.email,
                        firstName: ticketPayload.given_name,
                        lastName: ticketPayload.family_name,
                        googleId: ticketPayload.sub,
                        profilePicture: ticketPayload.picture
                    });
                
                    user.save().then(user => {
                        if (req.body.roles) {
                            Role.find(
                                {
                                    name: { $in: req.body.roles }
                                }
                                .then(roles => {
                                    user.roles = roles.map(role => role._id);
                                    user.save().then(result => {
                                        const accessToken = jwt.sign({ id: user._id },
                                            config.secret,
                                            {
                                                algorithm: 'HS256',
                                                allowInsecureKeySizes: true,
                                                expiresIn: config.accessTokenDuration, 
                                            }
                                        );
                            
                                        const refreshToken = jwt.sign({ id: result._id }, config.secret); // no expiration
                            
                                        var authorities = [];
                            
                                        for (let i = 0; i < roles.length; i++) {
                                            authorities.push("ROLE_" + roles[i].name.toUpperCase());
                                        }
                                        res.status(200).send({
                                            id: user._id,
                                            username: user.username,
                                            email: user.email,
                                            roles: authorities,
                                            firstName: user.firstName,
                                            lastName: user.lastName,
                                            name: user.name,
                                            accessToken: accessToken,
                                            refreshToken: refreshToken,
                                            profilePicture: user.profilePicture
                                        });
                                    });
                                })
                            );
                        } 
                        else {
                            Role.findOne({ name: "user" }).then(role => {
                                user.roles = [role._id];
                                user.save().then(result => {
                                    const accessToken = jwt.sign({ id: user._id },
                                        config.secret,
                                        {
                                            algorithm: 'HS256',
                                            allowInsecureKeySizes: true,
                                            expiresIn: config.accessTokenDuration,
                                        }
                                    );
                        
                                    const refreshToken = jwt.sign({ id: result._id }, config.secret); // no expiration
                        
                                    var authorities = ["ROLE_USER"];
                                        
                                    res.status(200).send({
                                        id: user._id,
                                        username: user.username,
                                        email: user.email,
                                        roles: authorities,
                                        firstName: user.firstName,
                                        lastName: user.lastName,
                                        name: user.name,
                                        accessToken: accessToken,
                                        refreshToken: refreshToken,
                                        profilePicture: user.profilePicture
                                    });
                                });
                            });
                        }
                    });
                }
            })
        }).catch(error => {
            console.error("ERROR", error);
            console.log(error);
            res.status(500).send({ message: error });
            return;
        });
    }
    else {
        res.status(400).send("No idToken provided.");
    }
}

exports.refreshToken = (req, res) => {
    const refreshToken = req.body.refreshToken;
    let userId;

    if(!refreshToken) {
        return res.status(403).send({ message: "No refreshToken provided" });
    }
    else {
        try {
            let decodedToken = jwt.verify(refreshToken, config.secret);
            userId = decodedToken.id;
        }
        catch(error) {
            return res.status(401).send({
                message: "Unauthorized!",
            });
        }

        if(userId) {
            // TODO SHOULD ROTATE REFRESH TOKENS (DESTROY THE OLD ONE)

            const accessToken = jwt.sign({ id: userId },
                config.secret,
                {
                    algorithm: 'HS256',
                    allowInsecureKeySizes: true,
                    expiresIn: config.accessTokenDuration,
                }
            );

            const refreshToken = jwt.sign({ id: userId }, config.secret); // no expiration

            return res.status(200).send({
                accessToken: accessToken,
                refreshToken: refreshToken
            });
        }
    }
}