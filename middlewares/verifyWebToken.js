const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const web_token = req.header('x-auth-token');
    if (!web_token) return res.status(401).json('Access denied');

    try {
        const ok_payload = jwt.verify(web_token, process.env.WEB_TOKEN_SECRET);
        req.user = ok_payload;
        next();
    } catch (error) {
        res.status(400).json('expired token');
    }
}