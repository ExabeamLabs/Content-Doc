#### Parser Content
```Java
{
Name = jsonar-database-login-1
  Vendor = jSONAR
  Product = SonarG
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ sonarw """, """|jSonar|sonarw|""", """LEEF:""", """DB User Name =""", """Session Activity Type=""" ]
  Fields = [
    """({host}[\w.\-]{1,2000}) sonarw """,
    """Start=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """DB User Name =(({user_email}[^@\s]{1,2000}@[^\s]{1,2000}?)|(({db_domain}[^\\=]{1,2000}?)\\)?({db_user}[^=]{1,2000}?))\s{1,10}OS""",
    """Server IP=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Server Host Name =({service_name}[^\s]{1,2000})""",
    """Client IP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """OS User=(null|((({domain}[^\\=]{1,2000}?)\\)?({user}[^=]{1,2000}?)))\s{1,10}Server""",
    """Session Activity Type=({event_name}[^=]{1,2000}?)\s{1,10}Server IP="""
  ]
  DupFields = [ "user_email->db_user" ]


}
```