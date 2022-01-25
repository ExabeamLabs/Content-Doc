#### Parser Content
```Java
{
Name = proofpoint-m1
  Vendor = Proofpoint
  Product = Proofpoint DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ" 
  Conditions = [ """mod=mail cmd=env_from""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"{1,20}host"{1,20}:"{1,20}({host}[^"]{1,2000})""",
    """"@timestamp"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"{1,20}"""
    """\sx=({xid}.+?)\s{1,100}(\w+=|$)""",
    """\svalue=({sender}.+?@[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\shost=({src_host}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\sip=({src_ip}[a-fA-F\d.:]{1,2000})"""
  ]


}
```