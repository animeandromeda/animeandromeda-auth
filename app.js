require('dotenv').config();
const createError = require('http-errors');
const express = require('express');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const path = require('path');
const mongoose = require('mongoose');
const compression = require('compression');
const cors = require('cors');
const rateLimit = require("express-rate-limit");

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');

const app = express();

const limiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 100
});

app.use(cors({
    origin: [
        'http://localhost:3001',
        'http://192.168.1.101:3001',
        'http://localhost:3000',
        'http://192.168.1.101:3000',
        'http://localhost:5000',
        'http://192.168.1.101:5000',
        'https://www.animeandromeda.net',
        'https://*.animeandromeda.net'
    ],
    exposedHeaders: ['x-auth-token'],
    optionsSuccessStatus: 200
}));

app.options('*', cors())

app.set('trust proxy', 1);
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'uploads')));
app.use(compression());
app.use(limiter);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use('/', indexRouter);
app.use('/api', indexRouter);
app.use('/api/user', usersRouter);

app.use((req, res, next) => {
    next(createError(404));
});

app.use((err, req, res, next) => {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(err.status || 500);
    res.send(err);
});

mongoose.connect(
    encodeURI(process.env.DB_AUTH),
    { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false })
    .then(() => console.log('\x1b[36m%s\x1b[0m', '[info] connetcted to mongodb'))
    .catch((err) => console.error(err));

module.exports = app;
