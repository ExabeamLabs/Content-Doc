#### Parser Content
```Java
{
Name = crowdstrike-security-alert-4
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"DllInjection"""", """"timestamp":"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """\Whostname=(|({host}.+?)),?(\s+\w+=|\s*\})""",
      """"InjectedDll":"({malware_file_name}[^"]+)""",
      """"event_simpleName":"({alert_name}[^"]+)""",
      """"id":"({alert_id}[^"]+)""",
    ]
  }
```