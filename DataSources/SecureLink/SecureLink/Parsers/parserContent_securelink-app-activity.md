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
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_host=({host}[^\s]+)""",
      """Application:\s{0,100}({app}[^,]+)""",
      """AUDIT:.+?\(({user_email}[^)]+)\)""",
      """({activity}accessed service):\s{0,100}({object}[^,]+)""",
      """port ({dest_port}\d{1,100})""",
      """duration: ({duration}\w+)""",
    ]
  }
```