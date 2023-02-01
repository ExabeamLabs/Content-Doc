#### Parser Content
```Java
{
Name = airlock-appwhitelisting-app-activity-1
  Vendor = Airlock
  Product = Application Whitelisting
  Lms = Syslog
  DataType = "app-activity"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """ airlock """, """Airlock[""", """]: ServerActivityMessage|""" ]
  Fields = [
    """ServerActivityMessage\|({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\w{2})\|""",
    """ServerActivityMessage\|[^\|]{0,2000}\|({activity}[^\|]{1,2000})\|""",
    """ServerActivityMessage\|([^\|]{0,2000}\|){2}(SYSTEM|({user}[^\|]{1,2000}))\|""",
    """ServerActivityMessage\|([^\|]{0,2000}\|){3}({additional_info}[^\|$]{1,2000}?)\s{0,20}$""",
    """({event_name}ServerActivityMessage)""",
    """({app}Airlock)"""
  ]


}
```