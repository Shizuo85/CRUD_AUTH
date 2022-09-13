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

const confirmEmail = catchAsync(async (req, res, next) => {
	next();
});

const protect = catchAsync(async (req, res, next) => {
	next();
});

const logout = catchAsync(async (req, res, next) => {});

module.exports = {
	signup,
	login,
	forgotPassword,
	resetPassword,
	confirmEmail,
	protect,
	restrictTo,
	logout,
};
