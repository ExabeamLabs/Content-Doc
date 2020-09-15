#### Parser Content
```Java
{
Name = illumio-network-connection
  Vendor = Illumio
  Product = Illumio
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

{
  Name = secureauth-system-session-start
  Vendor = SecureAuth
  Product = SecureAuth Login
  Lms = QRadar
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS"
  Conditions = [ """LEEF:""", """|SecureAuth|""", """resource=Session - Start""" ]
  Fields = [
    """devTime=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d.\d\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """cat=({category}[^\s]+)""",
    """usrName=({user}[^\s]+)""",
    """processId=({pid}\d+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """url=({domain}[^\s]+)""",
    """sev=({severity}\d+)""",
    """resource=({event_name}.+?)(\s+\w+=|\s*$)""",
  ]
}
```