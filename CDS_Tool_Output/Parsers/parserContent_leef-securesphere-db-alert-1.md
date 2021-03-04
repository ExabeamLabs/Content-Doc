#### Parser Content
```Java
{
Name = leef-securesphere-db-alert-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """|Imperva|SecureSphere|""", """AlertNumber=""", """AlertType=""", """Description=""" ]
  Fields = [
    """(\s|\||\\t)CreateTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\s|\||\\t)SourceIP=({src_ip}[a-fA-F:\d\.]+)""",
    """(\s|\||\\t)SourcePort=({src_port}\d+)""",
    """(\s|\||\\t)ServerIP=({dest_ip}[a-fA-F:\d\.]+)""",
    """(\s|\||\\t)ServerPort=({dest_port}\d+)""",
    """(\s|\||\\t)Username=(|({user}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)AlertType=(|({alert_type}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)ServerGroup=(|({server_group}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)Severity=(|({alert_severity}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)Service=(|({service_name}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)Application=(|({app}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)Description=(|({additional_info}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)Protocol=(|({protocol}.+?))(\\t\w+=|\s*$)""",
    """(\s|\||\\t)RuleName=(|({alert_name}.+?))(\\t\w+=|\s*$)"""
  ]
}
```