var mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/test', function(err){
    if(err){console.log('Failed connection to database');}
});

module.exports = mongoose;