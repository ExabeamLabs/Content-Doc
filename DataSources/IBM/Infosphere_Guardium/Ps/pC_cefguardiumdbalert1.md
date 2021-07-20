#### Parser Content
```Java
{
Name = cef-guardium-db-alert-1
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Syslog
  DataType = "database-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|IBM|Guardium|""", """DatabaseName=""", """DBUser="""  ]
  Fields=[
     """exabeam_host=({host}[^\s]{1,2000})""",
     """\|IBM\|Guardium\|[^|]{1,2000}\|({alert_name}[^|]{1,2000})""",
     """Severity=({alert_severity}[^=]{1,2000}?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """Category=({alert_type}[^=]{1,2000}?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """DatabaseName=({database_name}[^=]{1,2000}?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """DBUser=\s{0,100}(?:|(({domain}[^\\=]{1,2000})\\+)?({db_user}[^=\\\/]{1,2000}?))(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ServerIP=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """ServerHostname=({host}[^=]{1,2000}?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ServerType=({server_group}[^=]{1,2000}?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ClientIP=({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """rt=({time}\d{1,100})""",
     """OSUser=\s{0,100}(?:|(({domain}[^\\=]{1,2000})\\+)?({user}[^=\\\/]{1,2000}?))(?:\s{0,100}\w+=|\s{0,100}$)""",
     """AlertDetails=(\s{1,100}|({db_query}[^$]{1,2000}?))(?:\s{0,100}\w+=|\s{0,100}$)"""
  ]
}
```