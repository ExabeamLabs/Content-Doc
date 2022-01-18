#### Parser Content
```Java
{
Name = s-xml-7045
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """>7045</EventID>""", """<Data Name ='AccountName'"""]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """ProcessID='({process_id}[^']{1,2000})""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """>({event_code}\d{1,100})</EventID>""",
    """<Security UserID='({user_sid}[^']{1,2000})""",
    """<Data Name ='ServiceName'>({service_name}[^<]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='ServiceType'>({service_type}[^<]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='ImagePath'>({process}({directory}[^<>"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"<>\\\/]{0,2000}))</Data>""",
    """<Data Name ='ImagePath'>({command_line}"({process}({directory}[^<>"]{0,2000}?[\\\/]{1,2000})?({process_name}[^"<>\\\/]{0,2000}))"(\s{0,100}({arg}[^<>]{1,2000}))?)</Data>""",
    """<Data Name ='AccountName'>(({account_domain}[^<>\\\/]{1,2000})[\\\/]{1,2000})?({account_name}[^<]{1,2000}?)</Data>""",
    """({event_name}A service was installed in the system)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]


}
```