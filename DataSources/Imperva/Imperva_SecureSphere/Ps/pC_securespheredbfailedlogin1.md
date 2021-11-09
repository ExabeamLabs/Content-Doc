#### Parser Content
```Java
{
Name = securesphere-db-failed-login-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-failed-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssz"
  Conditions = [ """"product":""",  """"SecureSphere"""", """"server-group-name":""", """"description":""", """"violation-type":""", """"sql"""", """"sql-failed-login"""" ]
  Fields = [
    """:\d\d:\d\d\s{1,100}({host}[\w.-]{1,100})\s""",
    """"create-time":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\w{3})""",
    """"description":\s{0,100}"({reason}[^"]{1,2000})""",
    """"user-name":\s{0,100}"({user}[^"]{1,2000})""",
    """"source-ip":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"source-port":\s{0,100}"({src_port}\d{1,100})""",
    """"dest-ip":\s{0,100}"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"dest-port":\s{0,100}"({dest_port}\d{1,100})""",
    """"protocol":\s{0,100}"({protocol}[^"]{1,2000})""",
    """"server-group-name":\s{0,100}"({server_group}[^"]{1,2000})""",
    """"service-name":\s{0,100}"({service_name}[^"]{1,2000})"""
  ]
  DupFields = [ "user->db_user" ]
}
}
```