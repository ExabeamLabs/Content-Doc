#### Parser Content
```Java
{
Name = xml-4674-1
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-privileged-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Data Name""", """"EventID":4674""" , """xmlns""", """"Activity":"4674 - An operation was attempted on a privileged object."""" ]
  Fields = [
    """TimeGenerated"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Keywords>({outcome}.+?)</Keywords>""",
    """Computer"{1,20}:"{1,20}({host}[^"]+)""",
    """({event_code}4674)""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserSid(\\)?"{1,20}>(?:NONE_MAPPED|({user_sid}[^<]+))""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectUserName(\\)?"{1,20}>(LOCAL SERVICE|({user}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectDomainName(\\)?"{1,20}>(NT AUTHORITY|({domain}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}SubjectLogonId(\\)?"{1,20}>({logon_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectServer(\\)?"{1,20}>(-|({object_server}[^<]+))""",
    """<Data Name(\\)?=(\\)?"{1,20}PrivilegeList(\\)?"{1,20}>({privileges}[^<]+)""",
    """<Data Name(\\)?=(\\)?"{1,20}ProcessName(\\)?"{1,20}>({process}({directory}[^<]*?)({process_name}[^\\<]+?))<\/Data>""",
    """"Activity".+?({event_name}An operation was attempted on a privileged object)""", 
    """<Data Name(\\)?=(\\)?"{1,20}ProcessId(\\)?"{1,20}>({process_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectType(\\)?"{1,20}>(-|({object_type}[^<]+))""",
    """<Data Name(\\)?=(\\)?"{1,20}ObjectName(\\)?"{1,20}>(-|({object}[^<]+))"""
  ]
  DupFields = ["host->dest_host","directory->process_directory"]
}
```