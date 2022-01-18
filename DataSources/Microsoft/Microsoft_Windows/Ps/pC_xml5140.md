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
      """<Computer>({host}({dest_host}[\w-]{1,2000})[^<]{0,2000})</Computer>""",
      """<TimeCreated SystemTime(\\)?='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{0,100}Z'/>""",
      """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000}?)</Data>""",
      """<Data Name(\\)?='SubjectUserName'>(-|({user}[^<]{1,2000}?))</Data>""",
      """<Data Name(\\)?='SubjectDomainName'>({domain}[^<]{1,2000}?)</Data>""",
      """<Data Name(\\)?='ObjectType'>({file_type}[^<]{1,2000}?)</Data>""",
      """<Data Name(\\)?='IpAddress'>({src_ip}[A-Fa-f\d:.]{1,2000})</Data>""",
      """<Data Name(\\)?='ShareName'>(?:\\\\\*\\)?({share_name}[^<]{1,2000}?)</Data>""",
      """<Data Name(\\)?='ShareLocalPath'>(?:[\\\?]{1,2000})?(|({share_path}({d_parent}[^<]{1,2000}?\\)?({d_name}[^\\\/<]{1,2000}?)?\\?))</Data>""", 
      """({accesses_code}4416)""",
      """<Data Name(\\)?='AccessList'>(%%)?({accesses}[\d\w]{1,2000})"""
    ]
    DupFields = ["accesses_code->accesses"]
  

}
```