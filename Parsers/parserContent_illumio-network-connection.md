#### Parser Content
```Java
{
Name = illumio-network-connection
  Vendor = Illumio
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """LEEF""","""[meta sequenceId=""", """|Illumio|""" ]
  Fields = [
    """pid=({pid}\d+)""",
    """\|({action}[^\|]+)\|cat=({category}.+?)\s*\w+=""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\s+({host}[^\s]+)\s+illumio_pce""",
    """proto=({protocol}.+?)\s+\w+=""",
    """src=({src_ip}.+?)\s+\w+=""",
    """dst=({dest_ip}.+?)\s+\w+=""",
    """sev=({alert_severity}\d+)""",
    """dstPort=({dest_port}\d+)""",
    """dstHostname=({dest_host}.+?)\s+\w+=""",
    """dstHref=({uri_path}.+?)\s+\w+=""",
    """"+app"+:"+({app}[^"]+)"+""",
    """"+loc"+:"+({location}[^"]+)"+""",
  ]
}
```