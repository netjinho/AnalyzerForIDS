import { Template } from 'meteor/templating';

import { Results } from '../api/hosts.js';

import './body.html';
import './host.js';

Template.body.helpers({
  results() {
    return Results.find({});
  },
});
