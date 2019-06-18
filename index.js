const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./data/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

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
            res.status(200).json({message: `Welcome ${user.username}!`});
        }else{
            res.status(401).json({message: 'Invalid Credentials'});
        }
    })
    .catch(error => {
        res.status(500).json(error);
    });
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
    const { username, password} = req.headers;

    if (username && password) {
        Users.findBy({username})
        .first()
        .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                next();
            }else{
                res.status(401).json({message: 'Not Authorized!'});
            }
        })
        .catch(error => {
            res.status(500).json({message: 'Unexpected Error', error});
        });
    }else{
        res.status(400).json({message: 'Missing Credentials'});
    }
}


const port = process.env.PORT || 5555;
server.listen(port, () => console.log(`\n** Running on ${port} **\n`))