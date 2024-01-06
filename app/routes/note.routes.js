const { verifySignUp, authJwt } = require("../middlewares");
const controller = require("../controllers/note.controller");

module.exports = function (app) {
    app.use(function (req, res, next) {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next();
    });

    app.post("/api/note", [authJwt.verifyToken], controller.createNote);
    app.get("/api/note", [authJwt.verifyToken], controller.getNotes);
};