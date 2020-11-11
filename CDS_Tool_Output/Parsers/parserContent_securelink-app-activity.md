#### Parser Content
```Java
{
Name = securelink-app-activity
    Vendor = SecureLink
    Product = SecureLink
    Lms = QRadar
    DataType = "app-activity"
    TimeFormat = "epoch"
    Conditions = [ "SecureLink:","AUDIT:","""accessed service:"""]
    Fields = [
      """exabeam_endTime=({time}\d+)""",
      """exabeam_host=({host}[^\s]+)""",
      """Application:\s*({app}[^,]+)""",
      """AUDIT:.+?\(({user_email}[^)]+)\)""",
      """({activity}accessed service):\s*({object}[^,]+)""",
      """port ({dest_port}\d+)""",
      """duration: ({duration}\w+)""",
    ]
  }
```