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
    """TimeGenerated"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Keywords>({outcome}.+?)</Keywords>""",
    """Computer"+:"+({host}[^"]+)""",
    """({event_code}4674)""",
    """<Data Name(\\)?=(\\)?"+SubjectUserSid(\\)?"+>(?:NONE_MAPPED|({user_sid}[^<]+))""",
    """<Data Name(\\)?=(\\)?"+SubjectUserName(\\)?"+>(LOCAL SERVICE|({user}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+SubjectDomainName(\\)?"+>(NT AUTHORITY|({domain}[^<]+))<\/Data>""",
    """<Data Name(\\)?=(\\)?"+SubjectLogonId(\\)?"+>({logon_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"+ObjectServer(\\)?"+>(-|({object_server}[^<]+))""",
    """<Data Name(\\)?=(\\)?"+PrivilegeList(\\)?"+>({privileges}[^<]+)""",
    """<Data Name(\\)?=(\\)?"+ProcessName(\\)?"+>({process}({directory}[^<]*?)({process_name}[^\\<]+?))<\/Data>""",
    """"Activity".+?({event_name}An operation was attempted on a privileged object)""", 
    """<Data Name(\\)?=(\\)?"+ProcessId(\\)?"+>({process_id}[^<]+)<\/Data>""",
    """<Data Name(\\)?=(\\)?"+ObjectType(\\)?"+>(-|({object_type}[^<]+))""",
    """<Data Name(\\)?=(\\)?"+ObjectName(\\)?"+>(-|({object}[^<]+))"""
  ]
  DupFields = ["host->dest_host","directory->process_directory"]
}
```