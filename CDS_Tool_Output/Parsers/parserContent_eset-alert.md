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
  Fields = [ """occured":"({time}[^,"]+)""",
             """exabeam_host=(\w+\s@ )?({host}[^\s]+)""",
             """({host}[^\s]+)\sERAServer\s""",
             """(?:,|")(threat_name|event)":"({alert_name}[^",]+)""",
             """(threat_type|protocol)":"({alert_type}[^,"]+)""",
             """severity":"({alert_severity}[^,"]+)""",
             """event_type":"({additional_info}[^,"]+)""",
             """scanner_id":"({additional_info}[^,"]+)""",
             """object_uri":".+?(?i)(users|documents and settings)\/({user}[^\/]+)[\\/]""",
             """username":"(?:({domain}[^"\\]*?)\\+)?({user}[^,"]+)""",
             """object_uri":"\w+:(\/)+({malware_url}[^,"]+)""",
             """ipv4":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """source_address":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """target_address":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
	]
   }
```