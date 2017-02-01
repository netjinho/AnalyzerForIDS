var CronJob = require('cron').CronJob;

scheduleAnalyzer('* * * * * ');

function scheduleAnalyzer(sCronFrequency) {
    var taskmodule = require('./analyzer');
    var i = 0;
    new CronJob('* * * * * ', function() {
        taskmodule.triggerFunction(oConfig, function() {
            console.log('\tRun \t#' + (i++) + '\t of the analyzer finished.')
        });
    }, null, true, 'CET');
}
