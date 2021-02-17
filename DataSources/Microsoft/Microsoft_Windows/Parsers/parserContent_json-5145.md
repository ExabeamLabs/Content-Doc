#### Parser Content
```Java
{
Name = json-5145
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [""""message":"A network share object was checked to see whether client can be granted desired access""", """"event_id":5145""", """Microsoft-Windows-Security-Auditing"""]
    Fields = [
      """({event_name}A network share object was checked to see whether client can be granted desired access)""",
      """({event_code}5145)""",
      """"hostname":"({host}[^"]+)""",      
      """@timestamp"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """SubjectLogonId"+:"+({logon_id}[^"]+)""",
      """SubjectUserName"+:"+({user}[^"]+)""",
      """SubjectDomainName"+:"+({domain}[^"]+)""",
      """IpAddress"+:"+({src_ip}[A-Fa-f:\d.]+)""",
      """IpPort"+:"+({src_port}\d+)""",
      """SubjectUserSid"+:"+({user_sid}[^"<]+)""",
      """ObjectType"+:"+({file_type}[^"]+)""",
      """ShareName"+:"+[\\\*]*({share_name}[^"]+)""",
      """ShareLocalPath"+:"+(?:[\\\?]+)?(|({share_path}(({d_parent}.+?)\\\\)?(|({d_name}[^\\]*?)))\\?)"""",
      """RelativeTargetName"+:"+({f_parent}(?:[^"]+)?[\\\/])?({file_name}[^\\:"]+?(\.\s*({file_ext}[^"\\.]+?))?)"""", 
      """AccessList"+:"+({accesses}[^"]+)""",
      """Accesses:.*({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete).*Access Check Results:""",
      """Access Check Results:\s*({outcome}-)\s""",
      """Access Check Results:.*({outcome}Granted|Denied)\s+by""",
      ]
    DupFields = ["host->dest_host"]
  }
```