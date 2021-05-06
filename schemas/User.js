const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        min: 3,
        max: 255,
    },
    email: {
        type: String,
        required: false,
        max: 1024,
    },
    password: {
        type: String,
        required: true,
        min: 6,
    },
    joined: {
        type: Date,
        default: new Date()
    },
    img: {
        type: String,
        required: false,
        default: process.env.PHOTO_DEFAULT
    },
    background: {
        type: String,
        required: false,
        default: ''
    },
    loved: {
        type: Array,
        default: [],
    },
    timestamps: {
        type: Array,
        default: [],
    },
});

module.exports = mongoose.model('user', userSchema);
