#### Parser Content
```Java
{
Name = vmware-horizon-logon
  Vendor = VMware Horizon
  Product = VMware Horizon
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ View """ , """ Severity""" , """ Module""" , """EventType=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d+\s+\d+:\d+:\d+\s+({host}[\w\-.]+)""",
    """({app}View)""",
    """EventType="*({event_name}[^"]+)"""
    """UserDisplayName="*(({domain}[^\\"]+)\\+)?({user}[^\\"]+)"""",
    """SessionType="*({activity}[^"]+)""",
    """UserSID="*({user_sid}[^"]+)""",
    """Module="*({resource}[^"]+)""",
    """ApplicationId="*({object}[^"]+)"""
  ]
}
```