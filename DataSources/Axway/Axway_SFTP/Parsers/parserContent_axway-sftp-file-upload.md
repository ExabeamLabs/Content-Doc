#### Parser Content
```Java
{
Name = axway-sftp-file-upload
  Vendor = Axway
  Product = Axway SFTP
  Lms = Splunk
  DataType = "file-upload"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""TransferStatus.Id:""", """message=Transfer start logged""", """user=""", """Client Hostname=""", """Transferred File="""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d\s({src_ip}[\dA-Fa-f.:]+)""",
    """Transferred File=({file_name}[^\=]+\.({file_ext}\w+)),""",
    """user=({user}[^,]+)""",
    """Client Hostname=({dest_ip}[\da-fA-F.:]+)""",
    """message=({event_name}[^\.]+)"""
  ]
}
```