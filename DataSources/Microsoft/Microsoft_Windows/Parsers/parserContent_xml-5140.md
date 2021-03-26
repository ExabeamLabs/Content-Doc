#### Parser Content
```Java
{
Name = xml-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = ["""<EventID>5140</EventID>""", """<Data Name""","""'ShareName'>"""]
    Fields = [
      """<EventID>({event_code}5140)""",
      """<Computer>({host}({dest_host}[\w-]+)[^<]*)</Computer>""",
      """<TimeCreated SystemTime(\\)?='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d*Z'/>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]+?)</Data>""",
      """<Data Name(\\)?='SubjectUserName'>(-|({user}[^<]+?))</Data>""",
      """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]+?)</Data>""",
      """<Data Name(\\)?='ObjectType'>({file_type}[^<]+?)</Data>""",
      """<Data Name(\\)?='IpAddress'>({src_ip}[A-Fa-f\d:.]+)</Data>""",
      """<Data Name(\\)?='ShareName'>(?:\\\\\*\\)?({share_name}[^<]+?)</Data>""",
      """<Data Name(\\)?='ShareLocalPath'>(?:[\\\?]+)?(|({share_path}({d_parent}[^<]+?\\)?({d_name}[^\\\/<]+?)?\\?))</Data>""", 
      """({accesses_code}4416)""",
      """<Data Name(\\)?='AccessList'>(%%)?({accesses}[\d\w]+)"""
    ]
    DupFields = ["accesses_code->accesses"]
  }
```