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
      """"hostname":"({host}[^"]{1,2000})""",      
      """@timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """SubjectLogonId"{1,20}:"{1,20}({logon_id}[^"]{1,2000})""",
      """SubjectUserName"{1,20}:"{1,20}({user}[^"]{1,2000})""",
      """SubjectDomainName"{1,20}:"{1,20}({domain}[^"]{1,2000})""",
      """IpAddress"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
      """IpPort"{1,20}:"{1,20}({src_port}\d{1,100})""",
      """SubjectUserSid"{1,20}:"{1,20}({user_sid}[^"<]{1,2000})""",
      """ObjectType"{1,20}:"{1,20}({file_type}[^"]{1,2000})""",
      """ShareName"{1,20}:"{1,20}[\\\*]{0,2000}({share_name}[^"]{1,2000})""",
      """ShareLocalPath"{1,20}:"{1,20}(?:[\\\?]{1,2000})?(|({share_path}(({d_parent}.+?)\\\\)?(|({d_name}[^\\]{0,2000}?)))\\?)"""",
      """RelativeTargetName"{1,20}:"{1,20}({f_parent}(?:[^"]{1,2000})?[\\\/])?({file_name}[^\\:"]{1,2000}?(\.\s{0,100}({file_ext}[^"\\.]{1,2000}?))?)"""", 
      """AccessList"{1,20}:"{1,20}({accesses}[^"]{1,2000})""",
      """Accesses:.*({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ|WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA|WriteData|AppendData|delete|Delete).*Access Check Results:""",
      """Access Check Results:\s{0,100}({outcome}-)\s""",
      """Access Check Results:.*({outcome}Granted|Denied)\s{1,100}by""",
      ]
    DupFields = ["host->dest_host"]
  

}
```