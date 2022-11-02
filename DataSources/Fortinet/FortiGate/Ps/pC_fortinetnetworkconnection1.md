#### Parser Content
```Java
{
Name = fortinet-network-connection-1
  Vendor = Fortinet
  Product = FortiGate
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """|Fortinet|FortiGate""", """|forward traffic dns|""" ]
  Fields = [
    """\w{3}\s{1,100}\d{1,2}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})\sCEF""",
    """start=({time}\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """spt=({src_port}\d{1,100})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """dpt=({dest_port}\d{1,100})""",
    """act=({action}[^=]{1,2000})\s[\w\.]{1,100}=""",
    """CEF:([^|]{1,2000}\|){5}({event_name}[^|]{1,2000})\|""",
    """deviceSeverity=({additional_info}[^=]{1,2000}?)\s{1,100}([\w.]{1,2000}=|$)"""
   ]


}
```