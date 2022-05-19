#### Parser Content
```Java
{
Name = xml-5145
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """<EventID>5145</EventID>""", """A network share object was checked to see whether client can be granted desired access""", """<Data Name ='ShareName'>""" ]
    Fields = [
      """({event_code}5145)""",
      """({event_name}A network share object was checked to see whether client can be granted desired access)""",
      """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """ProcessID='({process_id}\d{1,100})'""",
      """<Computer>({host}[^<]{1,2000})</Computer>""",
      """<Computer>(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|({dest_host}[^<]{1,2000})</Computer>)""",
      """<Data Name ='SubjectUserSid'>({user_sid}[^<]{1,2000})</Data>""",
      """<Data Name ='SubjectUserName'>({user}[^\s<]{1,2000})</Data>""",
      """<Data Name ='SubjectDomainName'>(|NT AUTHORITY|({domain}[^<]{1,2000}))</Data>""",
      """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})</Data>""",
      """<Data Name ='ObjectType'>({file_type}[^<]{1,2000})</Data>""",
      """<Data Name ='IpAddress'>({src_ip}[a-fA-F\d.:]{1,2000})""",
      """<Data Name ='IpPort'>({src_port}\d{1,100})""",
      """<Data Name ='ShareName'>({share_name}[^<]{1,2000})</Data>""",
      """<Data Name ='RelativeTargetName'>({f_parent}[^<]{1,2000}?\\+)?(?:|({file_name}[^\\:<]{0,2000}?(\.\s{0,100}({file_ext}[^\W_\\.]{1,2000}?))?))?\?</Data>""",
      """<Data Name ='AccessList'>\s{0,100}({accesses}[^<]{1,2000})\s{0,100}</Data>""",
      """Accesses:[^:]{0,2000}?({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete)[^:]{0,2000}?Access Check Results:""",
      """<Data Name ='ShareLocalPath'>(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}(({d_parent}[^<>]{1,2000})\\)?({d_name}\s{0,100}\S[^\\<>]{1,2000}?)?)\\?)<\/Data>""",
      """<Data Name ='AccessReason'>\s{0,100}(-|({access_reason}[^<]{1,2000}?))\s{0,100}</Data>""",
      """<Keywords><Keyword>({outcome}[^<]{1,2000})</Keyword>"""
    ]
  

}
```