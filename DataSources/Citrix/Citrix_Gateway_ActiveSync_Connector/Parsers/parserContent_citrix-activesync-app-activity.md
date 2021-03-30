#### Parser Content
```Java
{
Name = citrix-activesync-app-activity
  Vendor = Citrix
  Product = Citrix Gateway ActiveSync Connector
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "app-activity"
  Conditions = [ """Original Address=""", """devicetype=""", """agent=""", """cmd=""", """action=allow"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """Original Address=({host}[^\s]+)\s""",
    """action=({outcome}[^\s]+)\s""",
    """deviceid=({device_id}[^\s]+)\s""",
    """group=({group}[^\s]+)\s""",
    """user=({domain}[^\/]+)\\({user}[^\s]+)\s""",
    """devicetype=({device_type}[^\s]+)\s""",
    """cmd=({activity}[^\s]+)\s""",
    """agent=({user_agent}[^\s]+)\s""",
    """ip=({src_ip}[^\s]+)(?:\s|$)""",
    """user=({user_email}({user}[^@\s]+)@[^@\s]+)\s""",
  ]
}
```