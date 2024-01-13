const config = require("../config/auth.config");
const jwt = require("jsonwebtoken");
const db = require("../models");
const Note = db.note;

exports.createNote = (req, res) => {
    let token = req.headers["x-access-token"];
    let userId;

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    try {
        let decodedToken = jwt.verify(token, config.secret);
        userId = decodedToken.id;
    }
    catch(error) {
        console.error("FAILED TO VERIFY TOKEN");

        return res.status(401).send({
            message: "Unauthorized!",
        });
    }

    if(userId && userId == req.body.user) {
        const note = new Note({
            user: req.body.user,
            localId: req.body.localId,
            body: req.body.body,
            localCreatedDate: req.body.localCreatedDate
        });

        note.save().then(result => {
            res.send(result);
        });
    }
    else {
        console.error("USER ID IN TOKEN != USER IN NOTE");

        return res.status(401).send({
            message: "Unauthorized!",
        });
    }
};

exports.getNotes = (req, res) => {
    let token = req.headers["x-access-token"];
    let userId;

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    try {
        let decodedToken = jwt.verify(token, config.secret);
        userId = decodedToken.id;
    }
    catch(error) {
        console.error("FAILED TO VERIFY TOKEN");

        return res.status(401).send({
            message: "Unauthorized!",
        });
    }

    if(req.query.user == userId) {
        Note.find({
            user: userId
        }).sort({ createdDate: 'desc' }).then(result => {
            res.status(200).send(result);
        });
    }
    else {
        return res.status(401).send({
            message: "Unauthorized!",
        });
    }
};

exports.deleteNote = (req, res) => {
    let token = req.headers["x-access-token"];
    let userId;

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    try {
        let decodedToken = jwt.verify(token, config.secret);
        userId = decodedToken.id;
    }
    catch(error) {
        console.error("FAILED TO VERIFY TOKEN");

        return res.status(401).send({
            message: "Unauthorized!",
        });
    }

    if(req.params.id) {
        Note.findById(req.params.id).then(result => {
            if(result) {
                if(result.user == userId) {
                    Note.findByIdAndDelete(result._id).then(result => {
                        if(result) {
                            res.status(200).send(result);
                        }
                    });
                }
                else {
                    return res.status(401).send({
                        message: "Unauthorized!",
                    });
                }
            }
        })
    }
    else if(req.query.user && req.query.user == userId) {
        Note.deleteMany({
            user: userId
        }).then(result => {
            if(result) {
                res.status(200).send(result);
            }
        });
    }
    else {
        return res.status(401).send({
            message: "Unauthorized!",
        });
    }
}