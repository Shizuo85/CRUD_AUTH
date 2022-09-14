const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const catchAsync = require('../utils/catchAsync');
const User = require('../models/users');
const AppError = require('../utils/appError');

const sendEmail = (options) => {
	let transporter = nodemailer.createTransport({
		service: 'gmail',
		host: 'smtp.gmail.com',
		secure: false,
		auth: {
			user: process.env.MAIL_USERNAME,
			pass: process.env.MAIL_PASSWORD,
		},
	});
	let mailOptions = {
		from: process.env.MAIL_USERNAME,
		to: options.email,
		subject: options.subject,
		html: options.message,
	};
	transporter.sendMail(mailOptions);
};

const signToken = (id) =>
	jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_EXPIRES_IN,
	});

const createSendToken = catchAsync(async (user, statusCode, res) => {
	const token = signToken(user._id);

	user.password = undefined;
	user.active = undefined;
	user.confirmEmailToken = undefined;
	user.loggedOut = undefined;

	res.status(statusCode).json({
		status: 'success',
		token,
		data: {
			user: user,
		},
	});
});

const signup = catchAsync(async (req, res, next) => {});

const login = catchAsync(async (req, res, next) => {});

const forgotPassword = catchAsync(async (req, res, next) => {
	next();
});

const resetPassword = catchAsync(async (req, res, next) => {
	next();
});
// logic to confirm if email provided exists, to reset password 
const confirmEmail = catchAsync(async (req, res, next) => {
	// get user based on the token 
	const token = crypto
	.createHash('sha256')
	.update(req.params.token)
	.digest('hex');

	const user = await User.findOne({ confirmToken : token,});

	// if user token does not exist
	if(!user){
		return res.status(400).send({ message : "Token is invalid"})
	}
	// else if user token is valid, save new user password
	user.active = true;
	user.confirmToken = undefined;

	await user.save();
	createSendToken(user, 200, res);

	next();
});

const protect = catchAsync(async (req, res, next) => {
	// get token from header
	let token;
	if(
		req.headers.authorization && req.headers.authorization.startsWith('Bearer')
	){
		token = req.headers.authorization.split(' ')[1];

	}
	// if token is not present
	if(!token){
		return res.status(401).send({message : "User is not Authorized, please Log in"})
	}

	// verify token in the header
	const jwtVerifyAsync = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

	// verify if the current still exists in the server
	const currUser = await User.findById(jwtVerifyAsync.id).select('+loggedOut');

	// if user does not exists
	if(!currUser){
		return res.status(401).send({message : "Unauthorized!, user does not exists"})
	}

	// check if user password has changed, check time jwt was issued 
	if(currUser.changedPasswordAfter(jwtVerifyAsync.iat)){
		return res.status(401).send({message : "Password was recently changed, Login again"});
	}

	// check if user is logged out
	if(currUser.loggedOut){
		return res.status(401).send({message : "User is not signed in, Sign in to gain access"});
	}
	req.user = currUser;
	next();
});
// log out function 
const logout = catchAsync(async (req, res, next) => {
	res.cookie('jwt', '', { maxAge: 1 });
	const user = await User.findOne({
		email: req.user.email,
	});
	user.loggedOut = true;
	await user.save({ validateBeforeSave: false });

	res.status(200).json({
		status: 'success',
		message: 'You have successfully logged out',
	});

});

module.exports = {
	signup,
	login,
	forgotPassword,
	resetPassword,
	confirmEmail,
	protect,
	logout
};
