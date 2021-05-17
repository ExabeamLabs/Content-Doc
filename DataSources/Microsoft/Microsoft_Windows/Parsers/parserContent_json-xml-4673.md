#### Parser Content
```Java
{
Name = json-xml-4673
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-privileged-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"4673"""", """<Data Name='""" ]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Computer":"({host}[^"]{1,2000})""",
      """"EventID":"({event_code}\d{1,100})""",
      """<Data Name='SubjectUserSid'>\s{0,100}(({domain}[^\\]{1,2000})\\)?({user}[^<]{1,2000})</Data>""",
      """<Data Name='SubjectUserName'>({user}[^<]{1,2000}?)</Data>""",
      """<Data Name='SubjectDomainName'>({domain}[^<]{1,2000}?)</Data>""",
      """<Data Name='SubjectLogonId'>({login_id}[^<]{1,2000}?)</Data>""",
      """<Data Name='ObjectServer'>({object_server}[^<]{1,2000}?)</Data>""",
      """<Data Name='PrivilegeList'>({privileges}[^<]{1,2000}?)</Data>""",
      """<Data Name='ProcessName'>({process}({directory}[^<]{0,2000}?)({process_name}[^\\<]{1,2000}?))</Data>""",
    ]
    DupFields = ["host->dest_host","directory->process_directory"]
  }
```