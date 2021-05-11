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
     """exabeam_host=({host}[^\s]+)""",
     """\|IBM\|Guardium\|[^|]+\|({alert_name}[^|]+)""",
     """Severity=({alert_severity}[^=]+?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """Category=({alert_type}[^=]+?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """DatabaseName=({database_name}[^=]+?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """DBUser=\s{0,100}(?:|(({domain}[^\\=]+)\\+)?({db_user}[^=\\\/]+?))(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ServerIP=({dest_ip}[A-Fa-f:\d.]+)""",
     """ServerHostname=({host}[^=]+?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ServerType=({server_group}[^=]+?)(?:\s{0,100}\w+=|\s{0,100}$)""",
     """ClientIP=({src_ip}[A-Fa-f:\d.]+)""",
     """rt=({time}\d{1,100})""",
     """OSUser=\s{0,100}(?:|(({domain}[^\\=]+)\\+)?({user}[^=\\\/]+?))(?:\s{0,100}\w+=|\s{0,100}$)""",
     """AlertDetails=(\s{1,100}|({db_query}[^$]+?))(?:\s{0,100}\w+=|\s{0,100}$)"""
  ]
}
```