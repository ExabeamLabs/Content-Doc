#### Parser Content
```Java
{
Name = kaspersky-usb-activity-2
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat =  "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ KES|""", """ tdn="""", """ hdn="""", """VID y PID de dispositivo:""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]+) KES\|""",
    """hip="({dest_ip}[A-Fa-f:\d.]+)""",
    """hdn="({dest_host}[^"]+)""",
    """Tipo de dispositivo\/Tipo de bus:\s{0,100}({device_type}[^"\\]+)""",
    """Id. de dispositivo:\s{0,100}({device_id}.+)&\d{1,100}""",
    """Usuario:\s{0,100}(({domain}[^"\\]+)\\+)?({user}[^\\\s"]+)""",
    """Resultado\\Decisión:\s{0,100}({action}[^"\\]+)""",
    """Operación:\s{0,100}({activity}[^\\"]+)""",
    """etdn="({activity_details}[^"]+)""",
  ]
  DupFields = [ "activity_details->alert_name","action->alert_type","activity->outcome" ]
}
```