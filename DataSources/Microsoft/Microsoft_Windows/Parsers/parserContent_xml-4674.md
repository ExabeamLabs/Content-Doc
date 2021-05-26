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
    """<Computer>({host}[\w.\-]{1,2000})</Computer>""",
    """({event_code}4674)""",
    """<Data Name='SubjectUserSid'>\s{0,100}(({domain}[^\\]{1,2000})\\)?({user}[^<]{1,2000})</Data>""",
    """<Data Name='SubjectUserName'>({user}[^<]{1,2000}?)</Data>""",
    """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000}?)</Data>""",
    """<Data Name='SubjectLogonId'>({login_id}[^<]{1,2000}?)</Data>""",
    """<Data Name='ObjectServer'>(-|({object_server}[^<]{1,2000}?))</Data>""",
    """<Data Name='PrivilegeList'>({privileges}[^<]{1,2000}?)</Data>""",
    """<Data Name='ProcessName'>({process}({directory}[^<]{0,2000}?)({process_name}[^\\<]{1,2000}?))</Data>""", 
  ]
  DupFields = ["host->dest_host","directory->process_directory"]
}
```