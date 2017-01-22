

  /*
  if (something)
    var typeText = "Too many open ports"

  if (something)
    var typeText = "Too much latency"

  if (something)
    var typeText = "Blacklist IP as destination"

  if (something)
    var typeText = "Too much SYN Packets per second"
  */




/*
//__________________BLACKLIST___________________________________________________

// Retrieve
var MongoClient = require('mongodb').MongoClient;

// Connect to the db
MongoClient.connect("mongodb://localhost:27017/networkRecordings", function(err, db) {
  if(err) { return console.dir(err); }

  var collection = db.collection('tsharkRuns');

  var blackList = ["192.168.0.2", "192.168.0.3", "192.168.0.255"]  //CONFIG
  var blackSource = []
  var blackSourceIP = []
  var cursor = collection.find({"destination": { $in: blackList }}, {"source":1, _id:0});
  cursor.each(function(err, doc) {

      blackSource.push(doc);



      if(doc == null ) {
           writeBlackList();
       };
  });

  function writeBlackList(){
      for (i = 0; i<blackSource.length-1; i++){
          blackSourceIP.push(blackSource[i].source)
      }
        console.log(blackSourceIP);


      // Connect to the db
      MongoClient.connect("mongodb://localhost:27017/analyzer", function(err, db) {
        if(err) { return console.dir(err); }

        var collection = db.collection('results');
        var typeText = "Blacklist IP";
        var descrText = "Blacklist IP as Destination";
        var severText = "Dangerous";
        var lotsOfDocs = []; //{'hello':'doc3'}, {'hello':'doc4'}

        for(var idx in blackSourceIP){
          var ip = blackSourceIP[idx];
          lotsOfDocs.push({type: typeText, source: ip, description: descrText, severity: severText});
        }

        collection.insert(lotsOfDocs, function(err, result) {console.log(result);});
      });
      db.close();
  }
  db.close();
});
//______________________________________________________________________________
*/
//__________________OPEN_PORTS__________________________________________________

// Retrieve
var MongoClient = require('mongodb').MongoClient;

// Connect to the db
MongoClient.connect("mongodb://localhost:27017/networkRecordings", function(err, db) {
  if(err) { return console.dir(err); }

  var collection = db.collection('nmapRuns');

  var nrPortDangerous = "2" //CONFIG
  var nrPortModerate = "1"  //CONFIG
  var auxPortDangerous = []
  var auxPortModerate = []
  var auxPortNormal = []
  var ipPortDangerous = []
  var ipPortModerate = []
  var ipPortNormal = []

//Severity: Dangerous
  var cursor = collection.find({"ports":  {$exists:true}, $where:'this.ports.length>'+nrPortDangerous},{"ip":1,_id:0});
  cursor.each(function(err, docDangerous) {

      auxPortDangerous.push(docDangerous);


      if(docDangerous == null ) {
           writeOpenPortsDangerous();
      };


  });
  function writeOpenPortsDangerous(){
    for (i = 0; i<auxPortDangerous.length-1; i++){
        ipPortDangerous.push(auxPortDangerous[i].ip)
    }
    console.log(ipPortDangerous);

    // Connect to the db
    MongoClient.connect("mongodb://localhost:27017/analyzer", function(err, db) {
      if(err) { return console.dir(err); }

      var collection = db.collection('results');
      var typeText = "Too many open ports";
      var descrText = "More than "+nrPortDangerous+" ports are open!";
      var severText = "Dangerous";
      var lotsOfDocs = [];

      for(var idx in ipPortDangerous){
        var ip = ipPortDangerous[idx];
        lotsOfDocs.push({type: typeText, source: ip, description: descrText, severity: severText});
      }

      collection.insert(lotsOfDocs, function(err, result) {console.log(result);});
    });
    db.close();

  }


//Severity: Moderate
  var cursor = collection.find({"ports":  {$exists:true}, $where:'this.ports.length>'+nrPortModerate},{"ip":1,_id:0});
  cursor.each(function(err, docModerate) {

      auxPortModerate.push(docModerate);


      if(docModerate == null ) {
           writeOpenPortsModerate();
      };


  });
  function writeOpenPortsModerate(){
    for (i = 0; i<auxPortModerate.length-1; i++){
        ipPortModerate.push(auxPortModerate[i].ip)
    }
    console.log(ipPortModerate);

    // Connect to the db
    MongoClient.connect("mongodb://localhost:27017/analyzer", function(err, db) {
      if(err) { return console.dir(err); }

      var collection = db.collection('results');
      var typeText = "Some open ports";
      var descrText = "More than "+nrPortModerate+" ports are open!";
      var severText = "Moderate";
      var lotsOfDocs = [];

      for(var idx in ipPortModerate){
        var ip = ipPortModerate[idx];
        lotsOfDocs.push({type: typeText, source: ip, description: descrText, severity: severText});
      }

      collection.insert(lotsOfDocs, function(err, result) {console.log(result);});
    });
    db.close();

  }

//Severity: Normal
  var cursor = collection.find({"ports":  {$exists:true}, $where:'this.ports.length<='+nrPortModerate},{"ip":1,_id:0});
  cursor.each(function(err, docNormal) {

      auxPortNormal.push(docNormal);


      if(docNormal == null ) {
           writeOpenPortsNormal();
      };


  });
  function writeOpenPortsNormal(){
    for (i = 0; i<auxPortNormal.length-1; i++){
        ipPortNormal.push(auxPortNormal[i].ip)
    }
    console.log(ipPortNormal);

    // Connect to the db
    MongoClient.connect("mongodb://localhost:27017/analyzer", function(err, db) {
      if(err) { return console.dir(err); }

      var collection = db.collection('results');
      var typeText = "Few open ports";
      var descrText = "Less than "+nrPortModerate+" ports are open!";
      var severText = "Normal";
      var lotsOfDocs = [];

      for(var idx in ipPortNormal){
        var ip = ipPortNormal[idx];
        lotsOfDocs.push({type: typeText, source: ip, description: descrText, severity: severText});
      }

      collection.insert(lotsOfDocs, function(err, result) {console.log(result);});
    });
    db.close();

  }

  db.close();
});


//______________________________________________________________________________
