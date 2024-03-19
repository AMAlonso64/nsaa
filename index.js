const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16)
const cookieParser = require('cookie-parser')
const JwtStrategy = require('passport-jwt').Strategy
const scryptPbkdf = require('scrypt-pbkdf')
const scryptMcf = require('scrypt-mcf')
const fs = require('fs')

async function generateKey() {
	const jsonData = fs.readFileSync('users.json', 'utf8');
    const keyObject = JSON.parse(jsonData);
	const mcfString = await scryptMcf.hash('someone', { derivedKeyLength: 32, scryptParams: { logN: 18, r: 8, p: 2 } })
	console.log(`hashed password: ${mcfString}`)
	// let passwordMatch = await scryptMcf.verify('someone', keyObject.key)
	// console.log(passwordMatch)
}

// generateKey()

const app = express()
const port = 3000

passport.use('username-password', new LocalStrategy(
	{
		usernameField: 'username',
		passwordField: 'password',
		session: false
	}, async function (username, password, done) {
		const jsonData = fs.readFileSync('users.json', 'utf8');
		const userObject = JSON.parse(jsonData);
		let passwordMatch = await scryptMcf.verify(password, userObject.key)
		if (username === 'someone' && passwordMatch) {
			const user = {
				username: 'someone',
				description: 'the only user that deserves to get to this server'
			}
			return done(null, user)
		}
		return done(null, false)
	}
))

passport.use('jwtCookie', new JwtStrategy(
	{
		jwtFromRequest: (req) => {
			if (req && req.cookies) { return req.cookies.jwt }
			return null
		},
		secretOrKey: jwtSecret
	}, function (jwtPayload, done) {
		if (jwtPayload.sub && jwtPayload.sub === 'someone') {
			const user = {
				username: jwtPayload.sub,
				description: 'one of the user that deserver to get to this server',
				role: jwtPayload.role ?? 'user'
			}
			return done(null, user)
		}
		return done(null, false)
	}
))

app.use(express.urlencoded({ extended: true }))
app.use(passport.initialize())
app.use(cookieParser())

app.use(logger('dev'))

app.use(function(err, req, res, next) {
	console.error(err.stack)
	res.status(500).send('Something broke!')
})

app.get('/', passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }), (req, res) => {
  	res.send(`Welcome to your private page, ${req.user.username}!`)
})

app.get('/login', (req, res) => {
	res.sendFile('login.html', { root: __dirname })
})

app.get('/logout', (req, res) => {
	res.cookie('jwt', 'logged out')
	res.redirect('/login')
})

app.post('/login',
	passport.authenticate(
		'username-password',
		{ failureRedirect: '/login', session: false}
	), (req, res) => {
		const jwtClaims = {
			sub: req.user.username,
			iss: 'localhost:3000',
			aud: 'localhost:3000',
			exp: Math.floor(Date.now() / 1000) + 604800,
			role: 'user'
		}
		const token = jwt.sign(jwtClaims, jwtSecret)

		res.cookie('jwt', token, { httpOnly: true, secure: true })
		res.redirect('/')
		// console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
		// console.log(`Token secret: ${jwtSecret.toString('base64')}`)
})

app.listen(port, () => {
	console.log(`Example app listening at http://localhost:${port}`)
})
