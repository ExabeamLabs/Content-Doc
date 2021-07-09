#### Parser Content
```Java
{
Name = apache-failed-app-login-2
  Vendor = Apache
  Product = Apache Guacamole
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """] ERROR """, """ - Binding with the LDAP server at """,""" failed: Too many failed logins."""]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Binding with the LDAP server at\s"({dest_ip}[A-Fa-f\d:.]{1,2000})"""",
    """user\s"({user_ou}[^"]{1,2000})"""",
    """uid=({user_id}[^,]{1,2000})""",
    """({outcome}failed):\s({failure_reason}Too many failed logins)"""
    ]
}
```