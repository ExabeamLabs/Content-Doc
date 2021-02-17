#### Parser Content
```Java
{
Name = json-xml-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"EventID":"5140"""", """<Data Name='""" ]
    Fields = [
      """({event_code}5140)""",
      """"Computer":"({host}[^"]+)""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """<Data Name='SubjectLogonId'>({logon_id}.+?)</Data>""",
      """<Data Name='SubjectUserName'>({user}.+?)</Data>""",
      """<Data Name='SubjectDomainName'>({domain}.+?)</Data>""",
      """<Data Name='ObjectType'>({file_type}.+?)</Data>""",
      """<Data Name='IpAddress'>({src_ip}.+?)</Data>""",
      """<Data Name='ShareName'>(?:\\\\\*\\)?({share_name}.+?)</Data>""",
      """<Data Name='ShareLocalPath'>(?:[\\\?]+)?(?:\s*|({share_path}(({d_parent}.+)\\)?({d_name}\s*\S[^\\<]+?))\\?)</Data>""",
      """({accesses_code}4416)""",
    ]
    DupFields = ["host->dest_host", "accesses_code->accesses"]
  }
```