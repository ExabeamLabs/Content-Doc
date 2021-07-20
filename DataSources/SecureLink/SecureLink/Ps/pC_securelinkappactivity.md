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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """Application:\s{0,100}({app}[^,]{1,2000})""",
      """AUDIT:.+?\(({user_email}[^)]{1,2000})\)""",
      """({activity}accessed service):\s{0,100}({object}[^,]{1,2000})""",
      """port ({dest_port}\d{1,100})""",
      """duration: ({duration}\w+)""",
    ]
  }
```