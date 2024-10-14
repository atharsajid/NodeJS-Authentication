const express = require("express");
const app = express();
const path = require("path");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("./models/user")

app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")))

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


const secretKey = "asdkfko23h42k34kljlroc2io4ulkawlkjcrl24ojlk";

app.get("/", async (req, res) => {

    let token = req.cookies.token;
    if (token) {
        res.redirect("/home")
        return;
    }



    res.render("login");
})
app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/home", async (req, res) => {

    let data = jwt.verify(req.cookies.token, secretKey);
    if (data) {
        let user = await userModel.findOne({ email: data.email });
        if (user) {
            res.render("home", { user: user });
            return;
        }
    }


    res.redirect("/");
})


app.post("/createAccount", async (req, res) => {

    let { name, email, password } = req.body;

    let user = await userModel.findOne({ email: email });
    if (user) {
        res.status(409).send("Email already exist.");
        return;
    }


    bcrypt.genSalt(10, function (err, salt) {
        bcrypt.hash(password, salt, async function (err, hash) {

            if (err) {
                res.status(500).send("Something went wrong");
            } else {
                await userModel.create({
                    name: name,
                    email: email,
                    password: hash,
                })

                res.redirect("/");

            }
        })
    })

})


app.post("/login", async (req, res) => {
    let { email, password } = req.body;

    let user = await userModel.findOne({ email });
    if (!user) {
        res.status(400).send("User does not exist.");
        return;
    }

    console.log("Password =>" + password)
    console.log("User =>" + user)

    bcrypt.compare(password, user.password, (err, result) => {
        if (result) {

            let token = jwt.sign({ email }, secretKey);

            res.cookie("token", token);
            res.redirect("/home");

        } else {
            res.status(400).send("Wrong password.");
        }
    })
})

app.get("/logout", (req, res) => {
    res.clearCookie("token")
    res.redirect("/");
})


app.get("/delete", async (req, res) => {

    let data = jwt.verify(req.cookies.token, secretKey);
    if (data) {
        let user = await userModel.findOneAndDelete({ email: data.email });
        if (user) {
            res.clearCookie("token");
            res.redirect("/");
        }
    }

})


app.use((err, req, res, next) => {
    console.log(err.stack);
    res.status(500).send("Something went wrong");
})


app.listen(3000)