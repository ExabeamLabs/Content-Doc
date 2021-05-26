#### Parser Content
```Java
{
Name = citrix-activesync-app-activity-failed
  Vendor = Citrix
  Product = Citrix Gateway ActiveSync Connector
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "app-activity"
  Conditions = [ """Original Address=""", """devicetype=""", """agent=""", """cmd=""", """action=deny"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Original Address=({host}[^\s]{1,2000})\s""",
    """action=({outcome}[^\s]{1,2000})\s""",
    """deviceid=({device_id}[^\s]{1,2000})\s""",
    """group=({group}[^\s]{1,2000})\s""",
    """user=({domain}[^\/]{1,2000})\\({user}[^\s]{1,2000})\s""",
    """devicetype=({device_type}[^\s]{1,2000})\s""",
    """cmd=({activity}[^\s]{1,2000})\s""",
    """agent=({user_agent}[^\s]{1,2000})\s""",
    """ip=({src_ip}[^\s]{1,2000})(?:\s|$)""",
    """user=({user_email}({user}[^@\s]{1,2000})@[^@\s]{1,2000})\s""",
  ]
}
```