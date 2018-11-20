const mongoose = require('mongoose');
const Schema = mongoose.Schema;
mongoose.Promise = global.Promise;
const md5 = require('md5');
const validator = require('validator');
const mongodbErrorHandler = require('mongoose-mongodb-errors');
const passportLocalMongoose = require('passport-local-mongoose');

const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true,
        trim: true,
        validator: [
            validator.isEmail,
            'Invalid E-Mail Address'
        ],
        required: 'Please Supply an email address'
    },
    name: {
        type: String,
        required: 'Please Supplay a name',
        trim: true
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    hearts: [
        { type: mongoose.Schema.ObjectId, ref: 'Store' }
    ]
});

userSchema.virtual('gravatar').get(function() {
    const hash = md5(this.email);
    return `https://secure.gravatar.com/avatar/${hash}?s=50`;
});

userSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
userSchema.plugin(mongodbErrorHandler);

module.exports = mongoose.model('User', userSchema);
