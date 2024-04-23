// Komentar Tambahan:

// Import library yang dibutuhkan
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const passwordHash = require('password-hash');
const Joi = require('joi');
require('dotenv').config();

const db = require('../database/models');
const Users = db.Users;

// Joi validation schema untuk registrasi pengguna
const registerSchema = Joi.object({
    username: Joi.string().trim().alphanum().min(3).max(30).required(),
    fullname: Joi.string().trim().min(3).max(255).required(),
    email: Joi.string().trim().email().required(),
    password: Joi.string().min(8).required(),
});

// Joi validation schema untuk login
const loginSchema = Joi.object({
    username: Joi.string().trim().required(),
    password: Joi.string().required(),
});

// Joi validation schema untuk forgot password
const forgotPasswordSchema = Joi.object({
    email: Joi.string().trim().email().required(),
});

// Method untuk melakukan registrasi pengguna
const register = async (input, res) => {
    try {
        const { error } = registerSchema.validate(input);
        if (error) {
            return res.status(422).json({ status: 422, message: error.details[0].message });
        }

        const hashedPassword = passwordHash.generate(input.password);

        const save = await Users.create({
            username: input.username,
            fullname: input.fullname,
            email: input.email,
            password: hashedPassword,
        });

        res.json({ status: 200, message: 'success', data: save });
    } catch (error) {
        res.json({ status: 422, message: error.message });
    }
};

// Method untuk melakukan login pengguna
const login = async (req, res) => {
    try {
        const { error } = loginSchema.validate(req.body);
        if (error) {
            return res.status(422).json({ status: 422, message: error.details[0].message });
        }

        const username = req.body.username.trim();
        const password = req.body.password.trim();

        const user = await Users.findOne({ where: { username: username } });

        if (!user) {
            return res.status(422).json({ status: 422, message: 'Username not found' });
        }

        const isPasswordValid = passwordHash.verify(password, user.password);

        if (!isPasswordValid) {
            return res.status(422).json({ status: 422, message: 'Incorrect password' });
        }

        const userToken = {
            id: user.id,
            username: user.username,
        };

        jwt.sign({ userToken }, process.env.JWT_KEY, {
            expiresIn: '1d',
        }, (err, token) => {
            if (err) {
                return res.status(500).json({ status: 500, message: 'Error generating token' });
            }

            res.json({ status: 200, message: 'success', token: token });
        });
    } catch (error) {
        res.status(422).json({ status: 422, message: `Error: ${error.message}` });
    }
};

// Method untuk melakukan proses forgot password
const forgotPassword = async (req, res) => {
    try {
        const { error } = forgotPasswordSchema.validate(req.body);
        if (error) {
            return res.status(422).json({ status: 422, message: error.details[0].message });
        }

        const email = req.body.email.trim();

        const user = await Users.findOne({ where: { email: email } });

        if (!user) {
            return res.status(422).json({ status: 422, message: 'Email not found' });
        }

        const resetToken = jwt.sign({ userId: user.id }, process.env.RESET_PASSWORD_KEY, { expiresIn: '1h' });

        const transporter = nodemailer.createTransport({
            host: process.env.MAILTRAP_HOST,
            port: process.env.MAILTRAP_PORT,
            auth: {
                user: process.env.MAILTRAP_USER,
                pass: process.env.MAILTRAP_PASS,
            },
        });

        const mailOptions = {
            from: process.env.MAILTRAP_USER,
            to: email,
            subject: 'Reset Password Link',
            text: `Click on the following link to reset your password: ${process.env.APP_URL}/reset-password/${resetToken}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ status: 500, message: 'Error sending email' });
            }

            res.json({ status: 200, message: 'Reset password link sent to your email' });
        });
    } catch (error) {
        res.status(422).json({ status: 422, message: `Error: ${error.message}` });
    }
};

module.exports = {
    register, login, forgotPassword
};