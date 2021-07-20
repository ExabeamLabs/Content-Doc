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
    """pid=({pid}\d{1,100})""",
    """\|({action}[^\|]{1,2000})\|cat=({category}.+?)\s{0,100}\w+=""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}illumio_pce""",
    """proto=({protocol}.+?)\s{1,100}\w+=""",
    """src=({src_ip}.+?)\s{1,100}\w+=""",
    """dst=({dest_ip}.+?)\s{1,100}\w+=""",
    """sev=({alert_severity}\d{1,100})""",
    """dstPort=({dest_port}\d{1,100})""",
    """dstHostname=({dest_host}.+?)\s{1,100}\w+=""",
    """dstHref=({uri_path}.+?)\s{1,100}\w+=""",
    """"{1,20}app"{1,20}:"{1,20}({app}[^"]{1,2000})"{1,20}""",
    """"{1,20}loc"{1,20}:"{1,20}({location}[^"]{1,2000})"{1,20}""",
  ]
}
```