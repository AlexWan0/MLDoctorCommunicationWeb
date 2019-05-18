const getStream = require('get-stream')
var express = require('express');
var router = express.Router();
var crypto = require('crypto');
const multer  = require('multer')
const upload = multer({ dest: 'uploads/' })
const fs = require("fs")
var request = require('request');

var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017/";

var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
};

function saltHashPassword(userpassword) {
    var salt = genRandomString(16); /** Gives us salt of length 16 */
    var passwordData = sha512(userpassword, salt);
    return passwordData;
}

function base64_encode(file) {
    // read binary data
    var bitmap = fs.readFileSync(file);
    // convert binary data to base64 encoded string
    return new Buffer(bitmap).toString('base64');
}

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});

MongoClient.connect(url, function(err, db) {
	if (err) throw err;
	var dbo = db.db("db");
	var userColl = dbo.collection("users");
	var authCode = dbo.collection("authCodes");
	router.post('/register', function(req, res, next) {
		console.log(req.body.name);
		var passwordData = saltHashPassword(req.body.pass);
		let submitCode = genRandomString(8);
		userColl.find({email: req.body.email}).toArray(function(err, result) {
			if(result.length == 0){
				userColl.insert({name: req.body.name, email: req.body.email, pass: passwordData.passwordHash, passSalt: passwordData.salt, submitCode: submitCode});
			}else{
				console.log("duplicate email");
			}
		});
		res.render("index");
	});
	var diagColl = dbo.collection("diag");
	router.post('/login', function(req, res, next){
		var searchResult = userColl.find({email: req.body.email}).toArray(function(err, result) {
			var foundHash = result[0].pass;
			let foundSalt = result[0].passSalt;
			let pass = req.body.pass.toString();
			console.log(result[0])
			console.log(pass);
			if(sha512(pass, foundSalt).passwordHash === foundHash){
				var sessionToken = genRandomString(16);
				userColl.update({email:req.body.email}, {$set: {sessionToken:sessionToken}},{upsert:true});
				console.log("login success");
				diagColl.find({email:req.body.email}).toArray(function(err, searchResults) {
					res.render("userpage", {name: req.body.name, email:req.body.email, sessionToken:sessionToken, submitCode: result[0].submitCode, searchResults:searchResults});
				});
			}else{
				console.log("login failed");
				res.render("index", {failed: true});
			}
		});
	});

	router.post("/upload", upload.single('pic'), async function(req, res, next){
		const doctorDiag = req.body.doctor;
		const uploaded = req.file;
		console.log(req.file);
		const base64 = base64_encode(uploaded.path);
		console.log(base64);
		request.post({url:'http://127.0.0.1:5000/diagnose', form: {img:base64}}, function(err,httpResponse,body){
			var key = genRandomString(8);
			console.log(doctorDiag);
			diagColl.insert({key:key, img: base64, result: body, doctorDiag: doctorDiag, email: req.body.email});
			res.render("results", {key: key, result: body, doctorDiag: doctorDiag, email: req.body.email});
		});
	});
	router.get('/results', function(req, res, next) {
		var key = req.query.key;
		console.log(key);
		var searchResult = diagColl.find({key:key}).toArray(function(err, result) {
			console.log(result[0]);
			res.render('results', {key:result[0].key, result:result[0].result, img:result[0].body, doctorDiag:result[0].doctorDiag, email:result[0].email});
		});
	});
});
module.exports = router;