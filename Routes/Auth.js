const express = require('express');
const router = express.Router();
const User = require('../Models/UserSchema')
const errorHandler = require('../Middlewares/errorMiddleware');
const authTokenHandler = require('../Middlewares/checkAuthToken');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');



router.get('/test', async (req, res) => {
    res.json({
        message: "Auth api is working"
    })
})

function createResponse(ok, message, data) {
    return {
        ok,
        message,
        data,
    };
}

router.get('/profile', authTokenHandler, async (req, res, next) => {
    try {
      const userId = req.userId; // Get user ID from auth token
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json(createResponse(false, 'User not found'));
      }
      // Extract only necessary fields for the profile
      const { name, dob, weight, goal, activityLevel } = user;
      res.status(200).json(createResponse(true, 'User profile fetched successfully', {
        name,
        dob,
        weight,
        goal,
        activityLevel
      }));
    } catch (err) {
      next(err);
    }
  });
  
  router.put('/profile', authTokenHandler, async (req, res, next) => {
    try {
      const userId = req.userId; // Get user ID from auth token
      const { weightInKg, goal, activityLevel } = req.body;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json(createResponse(false, 'User not found'));
      }
      // Update only specified fields
      if (weightInKg) {
        user.weight = [{ weight: weightInKg, unit: 'kg', date: Date.now() }];
      }
      if (goal) {
        user.goal = goal;
      }
      if (activityLevel) {
        user.activityLevel = activityLevel;
      }
      await user.save();
      res.status(200).json(createResponse(true, 'User profile updated successfully'));
    } catch (err) {
      next(err);
    }
  });
  
router.post('/register', async (req, res, next) => {
    console.log(req.body);
    try {
        const { name, email, password, weightInKg, heightInCm, gender, dob, goal, activityLevel } = req.body;
        const existingUser = await User.findOne({ email: email });

        if (existingUser) {
            return res.status(409).json(createResponse(false, 'Email already exists'));
        }
        const newUser = new User({
            name,
            password,
            email,
            weight: [
                {
                    weight: weightInKg,
                    unit: "kg",
                    date: Date.now()
                }
            ],
            height: [
                {
                    height: heightInCm,
                    date: Date.now(),
                    unit: "cm"
                }
            ],
            gender,
            dob,
            goal,
            activityLevel
        });
        await newUser.save(); // Await the save operation

        res.status(201).json(createResponse(true, 'User registered successfully'));

    }
    catch (err) {
        next(err);
    }
})

router.post('/login', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json(createResponse(false, 'Invalid credentials'));
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json(createResponse(false, 'Invalid credentials'));
        }

        const authToken = jwt.sign({ userId: user._id }, process.env.JWT_REFRESH_SECRET_KEY, { expiresIn: '50m' });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_REFRESH_SECRET_KEY, { expiresIn: '100m' });

        res.cookie('authToken', authToken, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        res.status(200).json(createResponse(true, 'Login successful', {
            authToken,
            refreshToken
        }));
    }
    catch (err) {
        next(err);
    }
})
router.post('/checklogin', authTokenHandler, async (req, res, next) => {
    res.json({
        ok: true,
        message: 'User authenticated successfully'
    })
})
router.post('/logout', async (req, res, next) => {
    try {
        // Clear cookies containing authentication tokens
        res.clearCookie('authToken');
        res.clearCookie('refreshToken');
        res.clearCookie('adminToken')
        // Send response indicating successful logout
        res.status(200).json(createResponse(true, 'Logout successful'));
    } catch (err) {
        next(err);
    }
});


router.use(errorHandler)        //calls if any problem is with api calls

module.exports = router; 