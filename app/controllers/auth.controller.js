const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

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
                    expiresIn: 86400, // 24 hours
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
    const client = new OAuth2Client(process.env.CLIENT_ID);
    const { authId } = req.body;

    // TODO
}