const express = require('express');
const User = require('../schemas/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const checkToken = require('../middlewares/verifyWebToken');
const multer = require('multer');
const upload = multer({})
const router = express.Router();
const rateLimit = require("express-rate-limit");

const createAccountLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    message:
        "Troppe richieste da parte di questo indirizzo ip, cosa stai tentando di fare??? Riprova tra un'ora"
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message:
        "Troppe richieste da parte di questo indirizzo ip, cosa stai tentando di fare??? Riprova tra un quarto d'ora"
});

router.post('/', createAccountLimiter, (req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    const saltRounds = 12;
    const plainPassword = req.body.password;

    if (plainPassword.length < 6) {
        return res.status(400).json();
    }

    bcrypt.hash(plainPassword, saltRounds, (err, hash) => {
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: hash,
        });

        user
            .validate()
            .then(
                () => {
                    user
                        .save()
                        .then(data => {
                            const web_token = jwt.sign({ _id: data._id }, process.env.WEB_TOKEN_SECRET);
                            res.header('x-auth-token', web_token).json(web_token);
                            res.json(data);
                        })
                        .catch((e) => {
                            res.status(400).json(e);
                        });

                    if (err) {
                        console.error(err);
                    }
                }
            )
            .catch((e) => res.status(400).json(e));
    });
});

router.get('/', checkToken, async (req, res) => {
    User.find({ _id: req.user._id })
        .then(response => {
            response.length > 0 ?
                response.map(safe => {
                    res.json({
                        username: safe.username,
                        email: safe.email,
                        img: safe.img,
                        background: safe.background,
                        loved: safe.loved,
                        timestamps: safe.timestamps,
                    })
                }) : res.json(`¯\_(ツ)_/¯`);
        });
});

router.delete('/', checkToken, async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
        return res.status(400).json('wrong username')
    }

    const password = await bcrypt.compare(req.body.password, user.password)
    if (!password) {
        return res.status(400).json('wrong password');
    }

    user
        .deleteOne({ username: user, password: password })
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.json({ message: err });
        });
});

router.post('/login', async (req, res) => {
    const user = await User.findOne({
        $or: [
            { username: req.body.username },
            { email: req.body.username }
        ]
    });

    if (!user) {
        return res.status(400).json()
    }

    const password = await bcrypt.compare(req.body.password, user.password)
    if (!password) {
        return res.status(400).json();
    }

    const web_token = jwt.sign({ _id: user._id }, process.env.WEB_TOKEN_SECRET, { expiresIn: "60d" });
    res.cookie('auth-token', web_token, { httpOnly: true });
    res.header('x-auth-token', web_token)
    res.json(web_token);
});

router.post('/loved', checkToken, async (req, res) => {
    const data = req.body.loved;
    User.
        findOneAndUpdate(
            { _id: req.user._id },
            { $addToSet: { loved: data } },
            {
                upsert: true,
                runValidators: true,
                setDefaultsOnInsert: true,
            }
        )
        .then(res.status(200).json("added"))
        .catch(res.status(401).json())
});

router.delete('/loved', checkToken, async (req, res) => {
    const data = req.body.loved;
    User.
        updateOne(
            { _id: req.user._id },
            { $pull: { loved: data } })
        .then(res.status(200).json("removed"))
        .catch(res.status(401).json())
});

router.post('/timestamps', checkToken, async (req, res) => {
    const data = req.body.timestamp;
    User.
        findOneAndUpdate(
            { _id: req.user._id },
            { $addToSet: { timestamps: data } },
            {
                upsert: true,
                runValidators: true,
                setDefaultsOnInsert: true,
            }
        )
        .then(res.status(200).json("added"))
        .catch(res.status(401).json())
});

router.delete('/timestamps', checkToken, async (req, res) => {
    const data = req.body.timestamp;
    User.
        updateOne(
            { _id: req.user._id },
            { $pull: { $in: { timestamps: data } } })
        .then(res.status(200).json("added"))
        .catch(res.status(401).json())
});

router.post('/pic', checkToken, upload.single('propic'), async (req, res) => {
    if (req.file) {
        const extension = req.file.mimetype;
        const encoded = `data:${extension};base64,${req.file.buffer.toString('base64')}`;
        User.
            findOneAndUpdate(
                { _id: req.user._id },
                { img: encoded },
                {
                    upsert: true,
                    runValidators: true,
                    setDefaultsOnInsert: true,
                }
            )
            .then(res.status(200).json("updated pic"))
            .catch(res.status(401).json())
    }
    return res.status(400).send()
});

router.post('/background', checkToken, upload.single('background'), async (req, res) => {
    if (req.file) {
        const extension = req.file.mimetype;
        const encoded = `data:${extension};base64,${req.file.buffer.toString('base64')}`;
        User.
            findOneAndUpdate(
                { _id: req.user._id },
                { background: encoded },
                {
                    upsert: true,
                    runValidators: true,
                    setDefaultsOnInsert: true,
                }
            )
            .then(res.status(200).json("updated pic"))
            .catch(res.status(400).json())
    }
    return res.status(400).send()
});

router.patch('/changeusername', checkToken, async (req, res) => {
    const data = req.body.username;
    User.
        findOneAndUpdate(
            { _id: req.user._id },
            { username: data },
            {
                upsert: true,
                runValidators: true,
                setDefaultsOnInsert: true,
            }
        )
        .then(res.status(200).json("changed"))
        .catch(res.status(401).json())
});

module.exports = router;