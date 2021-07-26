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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\d\d:\d\d:\d\d\s({src_ip}[\dA-Fa-f.:]{1,2000})""",
    """Transferred File=({file_name}[^\=]{1,2000}\.({file_ext}\w+)),""",
    """user=({user}[^,]{1,2000})""",
    """Client Hostname=({dest_ip}[\da-fA-F.:]{1,2000})""",
    """message=({event_name}[^\.]{1,2000})"""
  ]
}
```