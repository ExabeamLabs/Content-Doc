#### Parser Content
```Java
{
Name = crowdstrike-security-alert-5
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"scenario":"""", """"detection_id":""", """"tactic":"""", """"technique":""""]
    Fields = [
      """"scenario":"({alert_name}[^"]{1,2000})""",
      """"technique":"({alert_type}[^"]{1,2000})""",
      """"severity":({alert_severity}\d{1,100})""",
      """"detection_id":"({alert_id}[^"]{1,2000})""",
      """"user_name":"({user}[^"]{1,2000})""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"md5":"(N\/A|({md5}\w+))""",
      """"local_ip":"({src_ip}[a-fA-F\d.:]{1,2000})""",
      """"machine_domain":"({domain}[^"]{1,2000})""",
      """"filename":"({process_name}[^"]{1,2000})""",
      """"hostname":"({src_host}[^"]{1,2000})""",
      """"show_in_ui":.*?"status":"({outcome}[^"]{1,2000})""",
      """"cmdline":"({additional_info}.+?)\s{0,100}","""",
      """"tactic":"({category}[^"]{1,2000})""",
      """"((?i)SHA256|SHA256String|SHA256HashData)\\*"{1,20}:\s{0,100}\\*"{1,20}({sha256}[^,]{1,2000}?)\\*"{1,20},""",
      """"(?i)Quarantine_File"{1,20}:\s{0,100}({quarantine_file}true|false)""",
      """"(?i)Quarantine_Machine"{1,20}:\s{0,100}({quarantine_machine}true|false)""",
      """"(?i)Detect"{1,20}:\s{0,100}({detect}true|false)""",
      """"(?i)Registry_Operation_Blocked"{1,20}:\s{0,100}({registry_operation_blocked}true|false)""",
      """"(?i)Kill_Parent"{1,20}:\s{0,100}({kill_parent}true|false)""",
      """"(?i)Operation_Blocked"{1,20}:\s{0,100}({operation_blocked}true|false)""",
      """"(?i)Kill_Process"{1,20}:\s{0,100}({kill_process}true|false)""",
      """"(?i)Process_Blocked"{1,20}:\s{0,100}({process_blocked}true|false)""",
      """"(?i)Policy_Disabled"{1,20}:\s{0,100}({policy_disabled}true|false)""",
      """"(?i)Sensor_Only"{1,20}:\s{0,100}({sensor_only}true|false)""",
      """"(?i)Kill_SubProcess"{1,20}:\s{0,100}({kill_sub_process}true|false)""",
      """"(?i)Rooting"{1,20}:\s{0,100}({rooting}true|false)""",
      """"(?i)Inddet_Mask"{1,20}:\s{0,100}({inddet_mask}true|false)""",
      """"(?i)Indicator"{1,20}:\s{0,100}({indicator}true|false)"""
    ]
    DupFields = [ "src_host->host" ]
  }
```