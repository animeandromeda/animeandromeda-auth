const createError = require('http-errors');
const express = require('express');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv').config();
const compression = require('compression');
const cors = require('cors');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');

const app = express();

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

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'uploads')));
app.use(compression());

app.use('/api', indexRouter);
app.use('/api/user', usersRouter);

app.use((req, res, next) => {
    next(createError(404));
});

app.use((err, req, res, next) => {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};

    res.status(err.status || 500);
    res.send('error');
});

mongoose.connect(
    encodeURI(process.env.DB_AUTH),
    { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false })
    .then(() => console.log('[info] connetcted to mongodb'))
    .catch((err) => console.error(err));

module.exports = app;
