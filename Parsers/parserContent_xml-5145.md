#### Parser Content
```Java
{
Name = xml-5145
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """<EventID>5145</EventID>""", """A network share object was checked to see whether client can be granted desired access""", """<Data Name='ShareName'>""" ]
    Fields = [
      """({event_code}5145)""",
      """({event_name}A network share object was checked to see whether client can be granted desired access)""",
      """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """ProcessID='({process_id}\d+)'""",
      """<Computer>({host}.+?)</Computer>""",
      """<Computer>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}.+?)</Computer>)""",
      """<Data Name='SubjectUserSid'>(|({user_sid}.+?))</Data>""",
      """<Data Name='SubjectUserName'>(|({user}[^\s]+))</Data>""",
      """<Data Name='SubjectDomainName'>(|({domain}.+?))</Data>""",
      """<Data Name='SubjectLogonId'>(|({logon_id}.+?))</Data>""",
      """<Data Name='ObjectType'>(|({file_type}.+?))</Data>""",
      """<Data Name='IpAddress'>({src_ip}[a-fA-F\d.:]+)""",
      """<Data Name='IpPort'>({src_port}\d+)""",
      """<Data Name='ShareName'>(|({share_name}.+?))</Data>""",
      """<Data Name='RelativeTargetName'>({f_parent}.*?\\+)?(?:|({file_name}[^\\:<]*?(\.\s*({file_ext}[^\\.]+?))?))?\?</Data>"""
      """<Data Name='AccessList'>\s*(|({accesses}.+?))\s*</Data>""",
      """Accesses:.*({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete).*Access Check Results:""",
      """<Data Name='ShareLocalPath'>(?:[\\\?]+)?(?:\s*|({share_path}(({d_parent}[^<>]+)\\)?({d_name}\s*\S[^\\<>]+?)?)\\?)<\/Data>"""
      """<Data Name='AccessReason'>\s*(|({outcome}.+?))\s*</Data>""",
    ]
  }
```