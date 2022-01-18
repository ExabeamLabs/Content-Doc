#### Parser Content
```Java
{
Name = windows-xml-4674
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4674</EventID>""", """<Data Name ='SubjectUserName'>""", """<Message>An operation was attempted on a privileged object""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Keywords>({outcome}[^<]{1,2000})<""",
    """<Computer>({host}[\w.\-]{1,2000})<""",
    """({event_code}4674)""",
    """<Data Name ='SubjectUserSid'>\s{0,100}(({domain}[^\\<]{1,2000})\\)?({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000}?)<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000}?)<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000}?)<""",
    """<Data Name ='ObjectServer'>(-|({object_server}[^<]{1,2000}?))<""",
    """<Data Name ='PrivilegeList'>({privileges}[^<]{1,2000}?)<""",
    """<Data Name ='ProcessName'>({process}({directory}[^<]{0,2000}?)({process_name}[^\\<]{1,2000}?))<""",
    """({event_name}An operation was attempted on a privileged object)"""
  ]
  DupFields = ["host->dest_host","directory->process_directory"]


}
```