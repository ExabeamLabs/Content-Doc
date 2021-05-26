#### Parser Content
```Java
{
Name = cylance-security-alert-1
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<Event xmlns=""", """<Provider Name='CylanceSvc'""", """>32</EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}.+?)<\/Computer>""",
    """({alert_name}A potentially malicious Active script was Detected)""",
    """Device:\s{0,100}({src_host}[\w\-.]{1,2000})""",
    """MAC:\s{0,100}({src_mac}[^\s,;<]{1,2000})""",
    """File path:\s{0,100}(|({malware_url}.+?))\s{1,100}Process Id:""",
    """IP:\s({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""", 
  ]
  DupFields = [ "alert_name->alert_type" ]
}
```