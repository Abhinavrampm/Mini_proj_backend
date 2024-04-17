const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const adminSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true // Ensure that each admin's email is unique
    },
    password: {
        type: String,
        required: true
    }
},{
    timestamps: true
});

//if password is changed during schema usage then save the password and hash it using bcrypt
adminSchema.pre('save', async function (next) {
    const admin = this;

    if (admin.isModified('password')) {
        admin.password = await bcrypt.hash(admin.password, 8);
    }

    next();
});

const Admin = mongoose.model('Admin', adminSchema);

module.exports = Admin;