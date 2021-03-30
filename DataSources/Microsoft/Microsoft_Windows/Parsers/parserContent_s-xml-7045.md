#### Parser Content
```Java
{
Name = s-xml-7045
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-service-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ ">7045</EventID>", "<Data Name='AccountName'>"]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """ProcessID='({process_id}[^']+)""",
    """<Computer>({host}[^<]+)</Computer>""",
    """>({event_code}\d+)</EventID>""",
    """<Security UserID='({user_sid}[^']+)""",
    """<Data Name='ServiceName'>({service_name}[^<]+?)\s*</Data>""",
    """<Data Name='ServiceType'>({service_type}[^<]+?)\s*</Data>""",
    """<Data Name='ImagePath'>({process}({directory}[^<>"]*?[\\\/]+)?({process_name}[^"<>\\\/]*))</Data>""",
    """<Data Name='ImagePath'>({command_line}"({process}({directory}[^<>"]*?[\\\/]+)?({process_name}[^"<>\\\/]*))"(\s*({arg}[^<>]+))?)</Data>""",
    """<Data Name='AccountName'>(({account_domain}[^<>\\\/]+)[\\\/]+)?({account_name}[^<]+?)</Data>""",
    """({event_name}A service was installed in the system)""",
  ]
  DupFields = [ "host->dest_host", "directory->process_directory" ]
}
```