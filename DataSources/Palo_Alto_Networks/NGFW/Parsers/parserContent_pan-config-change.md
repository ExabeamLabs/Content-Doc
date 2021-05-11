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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """\d\d:\d\d:\d\d\s(?:-|({host}[^:\s]+))\s\d{1,100}
```