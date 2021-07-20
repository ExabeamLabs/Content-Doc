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
      """exabeam_endTime=({time}\d{1,100})""",
      """exabeam_host=({host}[\w\-.]{1,2000})""",
      """: Host=({dest_host}[^\s]{1,2000})""",
      """ IP=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Domain=({domain}[^\s]{1,2000})"""
    ]
    DupFields = [ "dest_host->user" ]
  }
```