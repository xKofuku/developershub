const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");
const User = require("../../models/User");

// @route POST api/users
// @desc Register user
// @access Public
router.post(
	"/",
	[
		check("name", "Name is required").not().isEmpty(),
		check("email", "Please include a valid email"),
		check(
			"password",
			"Please enter a password with 8 or more characters"
		).isLength({ min: 8 }),
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}

		const { name, email, password } = req.body;
		try {
			//Checks if user exist
			let user = await User.findOne({ email });
			if (user) {
				res.status(400).json({ errors: [{ msg: "User already exist" }] });
			}
			//Gets gravatar from email
			const avatar = gravatar.url(email, {
				s: "200", //size
				r: "pg", //rating
				d: "mm", //default
			});
			//Create User Object
			user = new User({ name, email, avatar, password });
			//Encrypt Password
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);
			await user.save();
			//Payload
			const payload = {
				user: {
					id: user.id,
				},
			};
			jwt.sign(
				payload,
				config.get("jwtSecret"),
				{ expiresIn: 3600 },
				(err, token) => {
					if (err) throw err;
					res.json({ token });
				}
			);
		} catch (err) {
			console.log(err.message);
			res.status(500).send("Server Error");
		}
	}
);

module.exports = router;
