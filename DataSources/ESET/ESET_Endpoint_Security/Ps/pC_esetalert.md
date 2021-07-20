#### Parser Content
```Java
{
Name = eset-alert
  Vendor = ESET
  Product = ESET Endpoint Security
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "dd-MMM-yyyy HH:mm:ss"
  Conditions = [ """event_type":"""", """occured":"""", """source_uuid":""""   ]
  Fields = [ """occured":"({time}[^,"]{1,2000})""",
             """exabeam_host=(\w+\s@ )?({host}[^\s]{1,2000})""",
             """({host}[^\s]{1,2000})\sERAServer\s""",
             """(?:,|")(threat_name|event)":"({alert_name}[^",]{1,2000})""",
             """(threat_type|protocol)":"({alert_type}[^,"]{1,2000})""",
             """severity":"({alert_severity}[^,"]{1,2000})""",
             """event_type":"({additional_info}[^,"]{1,2000})""",
             """scanner_id":"({additional_info}[^,"]{1,2000})""",
             """object_uri":".+?(?i)(users|documents and settings)\/({user}[^\/]{1,2000})[\\/]""",
             """username":"(?:({domain}[^"\\]{0,2000}?)\\+)?({user}[^,"]{1,2000})""",
             """object_uri":"\w+:(\/)+({malware_url}[^,"]{1,2000})""",
             """ipv4":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """source_address":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """target_address":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """"processname":"({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))"""", 
	]
   DupFields = ["host->dest_host"]
   }
```