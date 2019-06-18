const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const db = require('./data/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfig = {
    name: 'cheetah', //by default the name is sid
    secret: 'keep it secret, keep it safe',
    resave: false, //if there are no changes to the session, dont save it
    saveUninitialized: true, // for GDPR compliance
    cookie: {
        maxAge: 1000 * 60 * 10, // in milli-seconds
        secure: false, // send cookie only over https, set to true in production
        httpOnly: true, // always set to true, it means client JS cant access the cookie
    },
    store: new KnexSessionStore({
        knex: require('./data/dbConfig.js'),
        tablename: 'sessions',
        sidfieldname: 'sid',
        createtable: true,
        clearInterval: 1000 * 60 * 60,
    }),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
    res.send('At your service');
});

server.post('/api/register', (req, res) => {
    let user = req.body;

    // generating hash from the users password
    const hash = bcrypt.hashSync(user.password, 8)

    // override the user.password with hash
    user.password = hash

    Users.add(user)
    .then(saved => {
        res.status(201).json(saved);
    })
    .catch(error => {
        res.status(500).json(error)
    });
});

server.post('/api/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
    .first()
    .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.username = user.username;
            res.status(200).json({message: `Welcome ${user.username}!`});
        }else{
            res.status(401).json({message: 'Invalid Credentials'});
        }
    })
    .catch(error => {
        res.status(500).json(error);
    });
});

// log out
server.delete('/', (req, res) => {
    if(req.session) {
        req.session.destroy();
        res.status(200).json({message: "See you next time."});
    }
});

server.get('/api/users', restricted, (req, res) => {
    Users.find()
    .then(users => {
        res.json(users);
    })
    .catch(err => {
        res.send(err);
    });
});

// restricted middleware
function restricted(req, res, next) {
    if(req.session && req.session.username) {
        next();

    }else{
        res.status(401).json({message: 'You cannot continue'})
    }
    // const { username, password} = req.headers;

    // if (username && password) {
    //     Users.findBy({username})
    //     .first()
    //     .then(user => {
    //         if (user && bcrypt.compareSync(password, user.password)) {
    //             next();
    //         }else{
    //             res.status(401).json({message: 'Not Authorized!'});
    //         }
    //     })
    //     .catch(error => {
    //         res.status(500).json({message: 'Unexpected Error', error});
    //     });
    // }else{
    //     res.status(400).json({message: 'Missing Credentials'});
    // }
}


const port = process.env.PORT || 5555;
server.listen(port, () => console.log(`\n** Running on ${port} **\n`))