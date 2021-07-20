#### Parser Content
```Java
{
Name = pan-config-change
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = QRadar
  DataType = "config-change"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",CONFIG," ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """\d\d:\d\d:\d\d\s(?:-|({host}[^:\s]{1,2000}))\s\d{1,100}
```