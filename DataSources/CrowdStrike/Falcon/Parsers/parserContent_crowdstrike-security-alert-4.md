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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d{1,100})""",
      """\Whostname=(|({host}.+?)),?(\s{1,100}\w+=|\s{0,100}\})""",
      """"InjectedDll":"({malware_file_name}[^"]+)""",
      """"event_simpleName":"({alert_name}[^"]+)""",
      """"id":"({alert_id}[^"]+)""",
    ]
    DupFields = [ "alert_name->alert_type" ]
  }
```