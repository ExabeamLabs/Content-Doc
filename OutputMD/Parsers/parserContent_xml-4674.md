#### Parser Content
```Java
{
Name = xml-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Data Name='""", "<EventID>4674</EventID>", """<Event xmlns='""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Keywords>({outcome}.+?)</Keywords>""",
    """<Computer>({host}[\w.\-]+)</Computer>""",
    """({event_code}4674)""",
    """<Data Name='SubjectUserSid'>\s*(({domain}[^\\]+)\\)?({user}[^<]+)</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]+?)</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+?)</Data>""",
    """<Data Name='SubjectLogonId'>({login_id}[^<]+?)</Data>""",
    """<Data Name='ObjectServer'>(-|({object_server}[^<]+?))</Data>""",
    """<Data Name='PrivilegeList'>({privileges}[^<]+?)</Data>""",
    """<Data Name='ProcessName'>({process}({directory}[^<]*?)({process_name}[^\\<]+?))</Data>""", 
  ]
  DupFields = ["host->dest_host","directory->process_directory"]
}
```