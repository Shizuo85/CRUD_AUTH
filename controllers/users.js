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
		return next(new AppError('Token is invalid', 400));
	}
	// else if user token is valid, save new user password
	user.active = true;
	user.confirmToken = undefined;

	await user.save({ validateBeforeSave: false });
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
		return next(
			new AppError('You are not logged in! Please log in to get access', 401)
		);
	}

	// verify token in the header
	const jwtVerifyAsync = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

	// verify if the current still exists in the server
	const currUser = await User.findById(jwtVerifyAsync.id).select('+loggedOut');

	// if user does not exists
	if(!currUser){
		return next(new AppError('The user no longer exists', 401));
	}

	// check if user password has changed, check time jwt was issued 
	if(currUser.changedPasswordAfter(jwtVerifyAsync.iat)){
		return next(
			new AppError('User recently changed password, please login again', 401)
		);
	}

	// check if user is logged out
	if(currUser.loggedOut){
		return next(
			new AppError('You are not logged in! Please log in to get access', 401)
		);
	}
	req.user = currUser;
	next();
});

const restrictTo = (...roles) => {
	return (req, res, next) => {
		if (!roles.includes(req.user.role)) {
			return next(
				new AppError(`You do not have permission to perform this action`, 403)
			);
		}
		next();
	};
};
// log out function 
const logout = catchAsync(async (req, res, next) => {
	const user = await User.findOne({
		email: req.user.email,
	});
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
	restrictTo,
	logout
};
