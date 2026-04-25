const fs = require('fs');
const pdf = require('pdf-parse');

let dataBuffer = fs.readFileSync('c:/Users/Usuario/Documents/proyectos/blue team/docs/informe/informa malo.pdf');

// Let's just try to parse it first
pdf(dataBuffer).then(function(data) {
    console.log(data.text.substring(0, 5000)); // Print first 5000 chars
}).catch(function(error) {
    console.log('Error parsing PDF:', error.message);
});
