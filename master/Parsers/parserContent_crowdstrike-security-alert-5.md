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
      """"scenario":"({alert_name}[^"]+)""",
      """"technique":"({alert_type}[^"]+)""",
      """"severity":({alert_severity}\d+)""",
      """"detection_id":"({alert_id}[^"]+)""",
      """"user_name":"({user}[^"]+)""",
      """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """"md5":"(N\/A|({md5}\w+))""",
      """"local_ip":"({src_ip}[a-fA-F\d.:]+)""",
      """"machine_domain":"({domain}[^"]+)""",
      """"filename":"({process_name}[^"]+)""",
      """"hostname":"({src_host}[^"]+)""",
      """"show_in_ui":.*?"status":"({outcome}[^"]+)""",
      """"cmdline":"({additional_info}.+?)\s*","""",
      """"tactic":"({category}[^"]+)""",
    ]
    DupFields = [ "src_host->host" ]
  }
```