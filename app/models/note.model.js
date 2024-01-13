const mongoose = require("mongoose");

const Note = mongoose.model(
    "Note",
    new mongoose.Schema({
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User"
        },
        localId: String,
        body: String,
        createdDate: {
            type: Date,
            default: Date.now,
            immutable: true
        },
        localCreatedDate: Date
    })
);

module.exports = Note;