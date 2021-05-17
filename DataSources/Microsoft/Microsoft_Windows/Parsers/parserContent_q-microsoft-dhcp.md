#### Parser Content
```Java
{
Name = q-microsoft-dhcp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "dhcp"
  TimeFormat = "epoch"
  Conditions = [ "WindowsDHCP", "Description=Assign" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_endTime=({time}\d{1,100})""",
    """IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Host Name=({dest_host}[^\s]{1,2000})"""
  ]
  DupFields = [ "dest_host->user" ]
}
```