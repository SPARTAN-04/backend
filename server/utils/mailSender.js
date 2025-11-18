const nodemailer = require("nodemailer");

require("dotenv").config();

const mailSender = async (email, title, body) => {
    try{
            let transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: 587,            
    secure: false,        
    auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.USER_PASS,
    }

});


            let info = await transporter.sendMail({
                from: 'StudyNotion || CodeHelp - by Babbar',
                to:`${email}`,
                subject: `${title}`,
                html: `${body}`,
            })
    
            console.log(info);
            return info;
    }
    catch(error) {
        console.log("error is in mailSender ", error.message);
    }
}


module.exports = mailSender;
