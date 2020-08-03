#### Parser Content
```Java
{
Name = q-qip-dhcp
    Vendor = Nokia VitalQIP
  Product = Nokia VitalQIP
    Lms = QRadar
    DataType = "dhcp"
    TimeFormat = "epoch"
    Conditions = [ "qip", "DHCP", " Host=", " Domain=" ]
    Fields = [
      """exabeam_endTime=({time}\d+)""",
      """exabeam_host=({host}[\w\-.]+)""",
      """: Host=({dest_host}[^\s]+)""",
      """ IP=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Domain=({domain}[^\s]+)"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```