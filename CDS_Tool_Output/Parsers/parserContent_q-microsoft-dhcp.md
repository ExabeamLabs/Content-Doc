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
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """exabeam_endTime=({time}\d+)""",
    """IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Host Name=({dest_host}[^\s]+)"""
  ]
  DupFields = [ "dest_host->user" ]
}
```