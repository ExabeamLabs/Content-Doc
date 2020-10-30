#### Parser Content
```Java
{
Name = crowdstrike-security-alert-3
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"RansomwareOpenFile"""", """"timestamp":"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """\s({host}[\w\-.]+)\sSkyformation"""
      """\Whostname=(|({host}.+?)),?(\s+\w+=|\s*\})""",
      """"TargetFileName":"({malware_file_name}[^"]+)""",
      """"event_simpleName":"({alert_name}[^"]+)""",
      """"id":"({alert_id}[^"]+)""",
      """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)\|""",
      """"aip":"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "alert_name->alert_type" ]
  }
```