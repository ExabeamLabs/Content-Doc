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
     """Severity=({alert_severity}[^=]+?)(?:\s*\w+=|\s*$)""",
     """Category=({alert_type}[^=]+?)(?:\s*\w+=|\s*$)""",
     """DatabaseName=({database_name}[^=]+?)(?:\s*\w+=|\s*$)""",
     """DBUser=\s*(({domain}[^\\]+)\\)?({db_user}[^=]+?)(?:\s*\w+=|\s*$)""",
     """ServerIP=({dest_ip}[A-Fa-f:\d.]+)""",
     """ServerHostname=({host}[^=]+?)(?:\s*\w+=|\s*$)""",
     """ServerType=({server_group}[^=]+?)(?:\s*\w+=|\s*$)""",
     """ClientIP=({src_ip}[A-Fa-f:\d.]+)""",
     """rt=({time}\d+)""",
     """OSUser=\s*(({domain}[^\\]+)\\)?({user}[^=]+?)(?:\s*\w+=|\s*$)""",
     """AlertDetails=(\s+|({db_query}[^$]+?))(?:\s*\w+=|\s*$)"""
  ]
}
```