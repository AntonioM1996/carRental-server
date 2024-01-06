const mongoose = require("mongoose");

const User = mongoose.model(
    "User",
    new mongoose.Schema({
        username: String,
        email: String,
        password: String,
        roles: [
            {
                type: mongoose.Schema.Types.ObjectId,
                ref: "Role"
            }
        ],
        firstName: String,
        lastName: String,
        name: {
            type: String,
            default: function() {
                return this.firstName + ' ' + this.lastName
            }
        },
        createdDate: {
            type: Date,
            default: Date.now,
            immutable: true
        },
        googleId: String
    })
);

module.exports = User;