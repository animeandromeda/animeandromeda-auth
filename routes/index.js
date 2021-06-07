const express = require('express');
const router = express.Router();
const rateLimit = require("express-rate-limit");

const testerLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 15,
    message: "Rate limited :)"
});

router.get('/', testerLimiter, (req, res, next) => {
    console.log('[req] incoming from:', req.socket.remoteAddress)
    res.render('index');
});

module.exports = router;
