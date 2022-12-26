A Full-Stack web app made with Node.js, Express.js and MongoDB. User can add products to cart and make payment with card (Stripe) and user can download invoices.

Packages Used:
"cross-env"
"nodemon"
"bcryptjs"
"body-parser"
"compression"
"connect-flash"
"connect-mongodb-session"
"csurf"
"ejs"
"express"
"express-handlebars"
"express-session"
"express-validator"
"helmet"
"mongodb"
"mongoose"
"morgan"
"multer"
"mysql2"
"nodemailer"
"nodemailer-sendgrid-transport"
"pdfkit"
"pug"
"sequelize"
"stripe"

Initially Run `npm install`, at the root folder.

To Run DEV with 'nodemon':
npm run start:dev

To Run PRODUCTION Server:
npm start

To Generate Key and Certificate:
openssl req -nodes -new -x509 -keyout server.key -out server.cert

You can configure your own API keys at the 'nodemon.json' file and for production do it in 'package.json'
