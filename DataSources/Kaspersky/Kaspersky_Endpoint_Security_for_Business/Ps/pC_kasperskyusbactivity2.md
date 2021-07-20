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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}[\w\-.]{1,2000}) KES\|""",
    """hip="({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """hdn="({dest_host}[^"]{1,2000})""",
    """Tipo de dispositivo\/Tipo de bus:\s{0,100}({device_type}[^"\\]{1,2000})""",
    """Id. de dispositivo:\s{0,100}({device_id}.+)&\d{1,100}""",
    """Usuario:\s{0,100}(({domain}[^"\\]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
    """Resultado\\Decisión:\s{0,100}({action}[^"\\]{1,2000})""",
    """Operación:\s{0,100}({activity}[^\\"]{1,2000})""",
    """etdn="({activity_details}[^"]{1,2000})""",
  ]
  DupFields = [ "activity_details->alert_name","action->alert_type","activity->outcome" ]
}
```