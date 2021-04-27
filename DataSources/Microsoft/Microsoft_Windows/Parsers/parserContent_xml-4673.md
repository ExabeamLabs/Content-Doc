#### Parser Content
```Java
{
Name = xml-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ "<EventID>4673</EventID>", """<Data Name""", """<Event xmlns""" ]
    Fields = [
      """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Keywords>({outcome}.+?)</Keywords>""",
      """<Computer>({host}[^<]+)</Computer>""",
      """<EventID>({event_code}[^<]+)</EventID>""",
      """<Data Name(\\)?='SubjectUserSid'>\s*(({domain}[^\\]+)\\)?({user}[^<]+)</Data>""",
      """<Data Name(\\)?='SubjectUserName'>({user}[^<]+?)</Data>""",
      """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+?)</Data>""",
      """<Data Name(\\)?='ObjectServer'>({object_server}[^<]+?)</Data>""",
      """<Data Name(\\)?='PrivilegeList'>({privileges}[^<]+?)</Data>""",
      """<Data Name(\\)?='ProcessName'>({process}({directory}[^<]*?)({process_name}[^\\<]+?))</Data>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<>\s=]+)"""
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```