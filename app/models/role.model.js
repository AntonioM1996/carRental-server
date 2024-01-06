const mongoose = require("mongoose");

const Role = mongoose.model(
    "Role",
    new mongoose.Schema({
        name: String,
        createdDate: {
            type: Date,
            default: Date.now,
            immutable: true
        }
    })
);

module.exports = Role;