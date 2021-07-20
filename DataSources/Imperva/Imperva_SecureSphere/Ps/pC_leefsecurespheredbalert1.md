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
    """(\s|\||\\t)SourceIP=({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """(\s|\||\\t)SourcePort=({src_port}\d{1,100})""",
    """(\s|\||\\t)ServerIP=({dest_ip}[a-fA-F:\d\.]{1,2000})""",
    """(\s|\||\\t)ServerPort=({dest_port}\d{1,100})""",
    """(\s|\||\\t)Username=(|({user}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)AlertType=(|({alert_type}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)ServerGroup=(|({server_group}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)Severity=(|({alert_severity}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)Service=(|({service_name}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)Application=(|({app}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)Description=(|({additional_info}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)Protocol=(|({protocol}.+?))(\\t\w+=|\s{0,100}$)""",
    """(\s|\||\\t)RuleName=(|({alert_name}.+?))(\\t\w+=|\s{0,100}$)"""
  ]
}
```