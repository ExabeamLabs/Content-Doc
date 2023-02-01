#### Parser Content
```Java
{
Name = airlock-appwhitelisting-app-activity
  Vendor = Airlock
  Product = Application Whitelisting
  Lms = Syslog
  DataType = "app-activity"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """ airlock """, """Airlock[""", """]: FileActivityMessage|""" ]
  Fields = [
    """FileActivityMessage\|({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\w{2})\|""",
    """FileActivityMessage\|[^\|]{0,2000}\|({host}[\w\-\.]{1,2000})\|""",
    """FileActivityMessage\|([^\|]{0,2000}\|){2}(SYSTEM|({user}[^\|]{1,2000}))\|""",
    """FileActivityMessage\|([^\|]{0,2000}\|){3}({file_parent}[^\|]{1,2000})\|""",
    """FileActivityMessage\|([^\|]{0,2000}\|){4}({file_name}[^\|]{1,2000}?(\.(\d{1,5}|({file_ext}[^\.\|]{1,2000})))?)\|""",
    """({event_name}FileActivityMessage)""",
    """({app}Airlock)""",
    """FileActivityMessage\|([^\|]{0,2000}\|){11}({activity}[^\|]{1,2000})\|""",
    """FileActivityMessage\|([^\|]{0,2000}\|){12}(System|({process_name}[^\|]{1,2000}))\|"""
  ]


}
```