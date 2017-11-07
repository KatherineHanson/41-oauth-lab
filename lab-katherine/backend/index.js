'use strict';

require('dotenv').config();

require('./lib/assert-env.js');
require('babel-register');

require('./lib/server.js').start();
