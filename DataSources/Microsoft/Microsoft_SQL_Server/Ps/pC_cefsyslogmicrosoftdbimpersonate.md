#### Parser Content
```Java
{
Name = cef-syslog-microsoft-db-impersonate
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Microsoft|SQL Server|""", """|IMPERSONATE|""", """EXECUTE AS LOGIN""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdntdom=({domain}.+?)\s{1,100}\w+=""",
    """\sfname=(?:({domain}[^\\]{1,2000})\\+)?({account}.+?)\s{1,100}\w+=""",
    """\ssourceServiceName =(?: |({service_name}.+?))\s{1,100}\w+=""",
    """\scs3=(?: |({database_name}.+?))\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^\s]{1,2000})"""
  ]


}
```