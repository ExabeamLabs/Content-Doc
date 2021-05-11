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
    """Device type\/Bus type:\s{0,100}({device_type}[^"\\]+)""",
    """Device ID:\s{0,100}({device_id}.+)&\d{1,100}""",
    """User:\s{0,100}(({domain}[^"\\]+)\\+)?({user}[^\\\s"]+)""",
    """Result\\Decision:\s{0,100}({action}[^"\\]+)""",
    """Operation:\s{0,100}({activity}[^\\"]+)""",
    """etdn="({activity_details}[^"]+)""",
  ]
  DupFields = [ "activity_details->alert_name","action->alert_type","activity->outcome" ]
}
```