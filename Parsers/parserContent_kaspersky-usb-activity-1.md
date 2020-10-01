#### Parser Content
```Java
{
Name = kaspersky-usb-activity-1
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ KES|""", """ tdn="""", """ hdn="""", """Device VID and PID:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]+) KES\|""",
    """hip="({dest_ip}[A-Fa-f:\d.]+)""",
    """hdn="({dest_host}[^"]+)""",
    """Device type\/Bus type:\s*({device_type}[^"\\]+)""",
    """Device ID:\s*({device_id}.+)&\d+""",
    """User:\s*(({domain}[^"\\]+)\\+)?({user}[^\\\s"]+)""",
    """Result\\Decision:\s*({action}[^"\\]+)""",
    """Operation:\s*({activity}[^\\"]+)""",
    """etdn="({activity_details}[^"]+)""",
  ]
  DupFields = [ "activity_details->alert_name","action->alert_type","activity->outcome" ]
}
```