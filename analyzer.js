
      //__________________BLACKLIST___________________________________________________

      // Retrieve
      var MongoClient = require('mongodb').MongoClient;

      // Connect to the db networkRecordings
      MongoClient.connect("mongodb://localhost:27017/networkRecordings", function(errRecordings, dbRecordings) {
        if(errRecordings) { return console.dir(errRecordings); }

        var collectionRecordings = dbRecordings.collection('tsharkRuns');
        var aBlacklist = ["192.168.0.2", "192.168.0.255"];
        var aAuxBlacklist = []
        var aBlacklistSource = []
        var aBlacklistDestination = []

        //Query all the source IP that have Blacklist IP as destination
        var cursorBlacklist = collectionRecordings.find({"destination": { $in: aBlacklist }}, {"source":1, "destination":1, _id:0});
        cursorBlacklist.each(function(errBlacklist, docBlacklist) {
          if(errBlacklist) { return console.dir(errBlacklist); }

            aAuxBlacklist.push(docBlacklist);

            if(docBlacklist == null ) {
              if(aAuxBlacklist.length > 1)
                 writeBlackList();
             }
        });

        function writeBlackList(){
            for (i = 0; i<aAuxBlacklist.length-1; i++){
              if(aBlacklistSource.indexOf(aAuxBlacklist[i].source) <= -1 ||
              aBlacklistDestination.indexOf(aAuxBlacklist[i].destination) <= -1){
                aBlacklistSource.push(aAuxBlacklist[i].source)
                aBlacklistDestination.push(aAuxBlacklist[i].destination)
              }
            }
        }

        var aAuxNormal = []
        var aNormalSource = []

        //Query all the other source IP
        var cursorNormal = collectionRecordings.find({"destination": { $nin: aBlacklist }}, {"source":1, _id:0});
        cursorNormal.each(function(errNormal, docNormal) {
          if(errNormal) { return console.dir(errNormal); }

            aAuxNormal.push(docNormal);

            if(docNormal == null ) {
              if(aAuxNormal.length > 1)
                 writeNormal();
             };
        });

        function writeNormal(){
            for (i = 0; i<aAuxNormal.length-1; i++){
              if(aNormalSource.indexOf(aAuxNormal[i].source) <= -1 && aBlacklistSource.indexOf(aAuxNormal[i].source) <= -1){
                aNormalSource.push(aAuxNormal[i].source)
              }
            }

            // Connect to the db analyzer
            MongoClient.connect("mongodb://localhost:27017/analyzer", function(errAnalyzer, dbAnalyzer) {
              if(errAnalyzer) { return console.dir(errAnalyzer); }

              var ip, descrText;
              var collectionAnalyzer = dbAnalyzer.collection('results');
              var typeText = "Blacklist IP";
              var severText = "Dangerous";
              var aDocuments = [];

              for(var idx in aBlacklistSource){
                ip = aBlacklistSource[idx];
                descrText = "Blacklist IP as Destination ("+aBlacklistDestination[idx]+")";
                aDocuments.push({type: typeText, source: ip, description: descrText, severity: severText, timestamp: new Date()});
              }

              typeText = "No Blacklist IP";
              descrText = "No Blacklist IP as Destination";
              severText = "Normal";

              for(var idx in aNormalSource){
                ip = aNormalSource[idx];
                aDocuments.push({type: typeText, source: ip, description: descrText, severity: severText, timestamp: new Date()});
              }

              //Write all the results on the db analyzer
              collectionAnalyzer.insert(aDocuments, function(errInsert, result) {
                if(errInsert) { return console.dir(errInsert); }
              });
              dbAnalyzer.close();
            });
        }
        dbRecordings.close();
      });
      //______________________________________________________________________________


      //__________________OPEN_PORTS__________________________________________________

      // Retrieve
      var MongoClient = require('mongodb').MongoClient;

      // Connect to the db networkRecordings
      MongoClient.connect("mongodb://localhost:27017/networkRecordings", function(errRecordings, dbRecordings) {
        if(errRecordings) { return console.dir(errRecordings); }

        var collectionRecordings = dbRecordings.collection('nmapRuns');

        var nrPortDangerous = "2"
        var nrPortModerate = "1";
        var aAuxDangerous = []
        var aAuxModerate = []
        var aAuxNormal = []
        var aPortDangerous = []
        var aPortModerate = []
        var aPortNormal = []

        //Severity: Dangerous
        var cursorDangerous = collectionRecordings.find({"ports":  {$exists:true}, $where:'this.ports.length >'+nrPortDangerous},{"ip":1,_id:0});
        cursorDangerous.each(function(errDangerous, docDangerous) {
          if(errDangerous) { return console.dir(errDangerous); }

          aAuxDangerous.push(docDangerous);

          if(docDangerous == null ) {
              if(aAuxDangerous.length > 1){
                  writeOpenPortsDangerous();
              }
          };
        });

        function writeOpenPortsDangerous(){
          for (i = 0; i<aAuxDangerous.length-1; i++){
            if(aPortDangerous.indexOf(aAuxDangerous[i].ip) <= -1){
              aPortDangerous.push(aAuxDangerous[i].ip)
            }
          }
        }

        //Severity: Moderate
        var cursorModerate = collectionRecordings.find({"ports":  {$exists:true}, $where:'this.ports.length >'+nrPortModerate},{"ip":1,_id:0});
        cursorModerate.each(function(errModerate, docModerate) {
          if(errModerate) { return console.dir(errModerate); }

          aAuxModerate.push(docModerate);

          if(docModerate == null ) {
              if(aAuxModerate.length > 1){
                 writeOpenPortsModerate();
              }
          };
        });

        function writeOpenPortsModerate(){
          for (i = 0; i<aAuxModerate.length-1; i++){
            if(aPortModerate.indexOf(aAuxModerate[i].ip) <= -1 &&
            aPortDangerous.indexOf(aAuxModerate[i].ip) <= -1){
              aPortModerate.push(aAuxModerate[i].ip)
            }
          }
        }

        //Severity: Normal
        var cursorNormal = collectionRecordings.find({"ports":  {$exists:true}, $where:'this.ports.length <='+nrPortModerate},{"ip":1,_id:0});
        cursorNormal.each(function(errNormal, docNormal) {
          if(errNormal) { return console.dir(errNormal); }

          aAuxNormal.push(docNormal);

          if(docNormal == null ) {
            if(aAuxNormal.length > 1)
               writeOpenPortsNormal();
          };
        });

        function writeOpenPortsNormal(){
          for (i = 0; i<aAuxNormal.length-1; i++){
            if(aPortNormal.indexOf(aAuxNormal[i].ip) <= -1 &&
            aPortModerate.indexOf(aAuxNormal[i].ip) <= -1 &&
            aPortDangerous.indexOf(aAuxNormal[i].ip) <= -1){
              aPortNormal.push(aAuxNormal[i].ip);
            }
          }

          // Connect to the db analyzer
          MongoClient.connect("mongodb://localhost:27017/analyzer", function(errAnalyzer, dbAnalyzer) {
            if(errAnalyzer) { return console.dir(errAnalyzer); }

            var collectionAnalyzer = dbAnalyzer.collection('results');
            var typeText = "Too many open ports";
            var descrText = "More than "+nrPortDangerous+" ports are open!";
            var severText = "Dangerous";
            var aDocuments = [];
            var ip;

            for(var idx in aPortDangerous){
              ip = aPortDangerous[idx];
              aDocuments.push({type: typeText, source: ip, description: descrText, severity: severText, timestamp: new Date()});
            }

            typeText = "Some open ports";
            descrText = "More than "+nrPortModerate+" ports are open!";
            severText = "Moderate";

            for(var idx in aPortModerate){
              ip = aPortModerate[idx];
              aDocuments.push({type: typeText, source: ip, description: descrText, severity: severText, timestamp: new Date()});
            }

            typeText = "Few open ports";
            descrText = "Less than "+nrPortModerate+" ports are open!";
            severText = "Normal";

            for(var idx in aPortNormal){
              ip = aPortNormal[idx];
              aDocuments.push({type: typeText, source: ip, description: descrText, severity: severText, timestamp: new Date()});
            }

            //Write all the results on the db analyzer
            collectionAnalyzer.insert(aDocuments, function(errInsert, result) {
              if(errInsert) { return console.dir(errInsert); }
            });
            dbAnalyzer.close();
          });
        }
        dbRecordings.close();
      });


      //______________________________________________________________________________

      //__________________SYN_FLOODING________________________________________________

      // Retrieve
      var MongoClient = require('mongodb').MongoClient;

      // Connect to the db networkRecordings
      MongoClient.connect("mongodb://localhost:27017/networkRecordings", function(errRecordings, dbRecordings) {
        if(errRecordings) { return console.dir(errRecordings); }

        var collectionRecordings = dbRecordings.collection('tsharkRuns');

        var nrPacketsDangerous = "4";
        var nrPacketsModerate = "2";
        var aSources = [];
        var aAuxSources = [];

        //Query all the sources
        var cursorSources = collectionRecordings.find({},{"source":1,_id:0});
        cursorSources.each(function(errSources, docSources) {
          if(errSources) { return console.dir(errSources); }

            aAuxSources.push(docSources);

            if(docSources == null) {
              if(aAuxSources.length > 1){
                 writeSources();
               }
            }
        });

        function writeSources(){
          //Get all the sources IP
          for (i = 0; i<aAuxSources.length-1; i++){
              if(aSources.indexOf(aAuxSources[i].source) <= -1){
                  aSources.push(aAuxSources[i].source)
              }
          }

          //For each source IP, it checks for the SYN packets rate for each destination
          function doForOne(aIps , idx, fnVeryEnd){
            if(aIps.length === idx){
              fnVeryEnd();
              return;
            }

            var sIpSource = aSources[idx];
            var aDestinations = [];
            var aAuxDestinations = [];

            //Query all the destinations of each source
            var cursorDestinations = collectionRecordings.find({"source": sIpSource},{"destination":1,_id:0});
            cursorDestinations.each(function(errDestinations, docDestinations) {
              if(errDestinations) { return console.dir(errDestinations); }
                aAuxDestinations.push(docDestinations);

                if(docDestinations == null) {
                  if(aAuxDestinations.length > 1){
                     writeDestinations();
                     aAuxDestinations = [];
                   }
                }
            });

            function writeDestinations(){
              aDestinations = [];
              //Get all the destinations IP
              for (i = 0; i<aAuxDestinations.length-1; i++){
                  if(aDestinations.indexOf(aAuxDestinations[i].destination) <= -1){
                      aDestinations.push(aAuxDestinations[i].destination)
                  }
              }

              function doForEachInner(aDestinations , idxInner, fnVeryEndInner){
                if(aDestinations.length === idxInner){
                  fnVeryEndInner();
                  return;
                }
                var sIpDestination = aDestinations[idxInner];
                var aAuxTime = [];
                var timeValue = 0;

                //Query timestamps of sent SYN packets
                var cursorTime = collectionRecordings.find({"source": sIpSource, "destination":sIpDestination, "tcpflag":"0x00000002"},
                {"destination":1,"timestamp":1,_id:0});
                cursorTime.each(function(errTime, docTime) {
                  if(errTime) { return console.dir(errTime); }

                    aAuxTime.push(docTime);

                    if(docTime == null) {
                         writeTime();
                         aAuxTime = [];
                    };
                });

                function writeTime(){
                    timeValue = aAuxTime[aAuxTime.length-2].timestamp;

                    //Check number of SYN packets sent in one second
                    collectionRecordings.count({"source": sIpSource, "destination":sIpDestination, "tcpflag":"0x00000002", "timestamp": {$gte:timeValue-1000, $lte:timeValue} },
                     (function(errPackets, docPackets) {
                       if(errPackets) { return console.dir(errPackets); }

                        // Connect to the db analyzer
                        MongoClient.connect("mongodb://localhost:27017/analyzer", function(errAnalyzer, dbAnalyzer) {
                          if(errAnalyzer) { return console.dir(errAnalyzer); }

                          var collectionAnalyzer = dbAnalyzer.collection('results');

                          if(docPackets > nrPacketsDangerous){
                              var typeText = "SYN Flooding Attack!";
                              var descrText = "More than "+nrPacketsDangerous+" packets were sent per second to "+sIpDestination;
                              var severText = "Dangerous";
                          }
                          else if(docPackets > nrPacketsModerate){
                              var typeText = "Too many SYN packets";
                              var descrText = "More than "+nrPacketsModerate+" packets were sent per second to "+sIpDestination;
                              var severText = "Moderate";
                          }
                          else{
                              var typeText = "Normal SYN packets rate";
                              var descrText = "Less than "+nrPacketsModerate+" packets were sent per second to "+sIpDestination;
                              var severText = "Normal";
                          }

                          var document = {type: typeText, source: sIpSource, description: descrText, severity: severText, timestamp: new Date()};

                          //Write all the results on the db analyzer
                          collectionAnalyzer.insert(document,function(errInsert, result) {
                            if(errInsert) { return console.dir(errInsert); }
                          });

                          dbAnalyzer.close();

                          doForEachInner(aDestinations , idxInner+1, function(){
                            doForOne(aIps , idx+1,fnVeryEnd)
                          })
                        });//connect dbAnalyzer
                    }));
                }//writeTime
              }//doForEachInner

              doForEachInner(aDestinations , 0, function(){
                  //doForEachInner is done!
              })
            }//writeDestinations
          }//doForOne

          doForOne(aSources, 0, function(){
              //doForOne is done!
              dbRecordings.close();
          });
        }//writeSources
      });//connect dbRecordings
      //______________________________________________________________________________
