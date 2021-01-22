#### Parser Content
```Java
{
Name = cylance-security-alert-1
  Vendor = Cylance
  Product = Cylance
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Event xmlns=""", """<Provider Name='CylanceSvc'""", """>32</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<Computer>({host}.+?)<\/Computer>""",
    """({alert_name}A potentially malicious Active script was Detected)""",
    """Device:\s*({src_host}[\w\-.]+)""",
    """MAC:\s*({src_mac}[^\s,;<]+)""",
    """File path:\s*(|({malware_url}.+?))\s+Process Id:""",
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```