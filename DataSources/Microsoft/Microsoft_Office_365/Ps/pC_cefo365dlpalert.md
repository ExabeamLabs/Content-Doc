#### Parser Content
```Java
{
Name = cef-o365-dlp-alert
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|security-threat-detected|""", """flexString1=DlpRuleMatch""" , """destinationServiceName =Office 365"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """ext_CreationTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """suser=({user_email}.*?)\s\w+=""", 
    """suid=({user_id}.*?)\s\w+=""", 
    """dpriv=({alert_type}.*?)\s\w+=""",
    """proto=({alert_name}.*?)\s\w+=""",
    """duser=({recipients}({recipient}[^"\s@;,]{1,2000}@[^"\s@;,]{1,2000})[^=\s]{0,2000}?)\s{1,20}\w+=""",
    """message=({additional_info}.*?)\s\w+=""", 
    """filePath=<*({file_path}.*?)>*\s\w+=""",
    """fname=({file_name}.*?)\s\w+=""",
    """dpid=({alert_id}.*?)\s\w+=""",
    """ext_PolicyDetails_0__Rules_0__Severity=({alert_severity}.*?)\s\w+=""",
  ]
  DupFields = [ "recipient->target", "alert_name->event_name" ]


}
```