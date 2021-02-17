#### Parser Content
```Java
{
Name = cef-syslog-microsoft-db-impersonate
  Vendor = Microsoft
  Product = SQL Server
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|SQL Server|""", """|IMPERSONATE|""", """EXECUTE AS LOGIN""" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sduser=({user}.+?)\s+\w+=""",
    """\sdntdom=({domain}.+?)\s+\w+=""",
    """\sfname=(?:({domain}[^\\]+)\\+)?({account}.+?)\s+\w+=""",
    """\ssourceServiceName=(?: |({service_name}.+?))\s+\w+=""",
    """\scs3=(?: |({database_name}.+?))\s+\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^\s]+)"""
  ]
}
```