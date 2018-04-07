var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');
var nodemailer = require("nodemailer");
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');

// email
var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'deepika.gupta.test@gmail.com',
    pass: 'Deepika@123'
  }
});

router.post('/register', function(req, res) {
  var hashedPassword = bcrypt.hashSync(req.body.password, 8);
  User.create({
    name : req.body.name,
    email : req.body.email,
    password : hashedPassword
  },
  function (err, user) {
    if (err) return res.status(500).send("There was a problem registering the user.")
    // create a token
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });

    //
    var mailOptions = {
      from: 'deepika.gupta.test@gmail.com',
      to: 'deepika@mailinator.com',
      subject: 'Welcome Mail',
      text: 'You have registered successfully!'
    };

    transporter.sendMail(mailOptions,user, function(error, info){
      if (error) {
         return res.status(500).send("There was a problem registering the user.")
      } else {
        res.status(200).send({ success: true, msg: '!!!!!' });
      }
    });
    res.status(200).send({ auth: true, token: token });
  });
});

router.post('/login', function(req, res) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) return res.status(500).send('Error on the server.');
    if (!user) return res.status(404).send('No user found.');
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });
    var token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 // expires in 24 hours
    });
    res.status(200).send({ auth: true, token: token });
  });
});

router.get('/getRecord', function(req, res) {
  var token = req.headers['x-access-token'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, config.secret, function(err, decoded) {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    res.status(200).send(decoded);
  });
});


router.post('/sendMail',function(req,res){
  nodemailer.createTestAccount((err, account) => {
    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true, // true for 465, false for other ports
        auth: {
          user: 'deepika.gupta.test@gmail.com',
          pass: 'Deepika@123'
        }
    });

    // setup email data with unicode symbols
    let mailOptions = {
        from: 'deepika.gupta.test@gmail.com',
        to: 'deepika@mailinator.com',
        subject: 'Welcome Mail',
        text: 'You have registered successfully!',
        html: '<b>Hello world?</b>' // html body
    };

    // send mail with defined transport object
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.log(error);
        }
        console.log('Message sent: %s', info.messageId);
        // Preview only available when sending through an Ethereal account
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

        // Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
        // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    });
});
})
module.exports = router;
