#### Parser Content
```Java
{
Name = s-panngwf-spyware-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,spyware,""" ]
  Fields = [ 
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"host":\{.*?"name":"({host}[^"]{1,2000})".*?\}""",
    """,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d),({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s""",
    """THREAT,({alert_type}\w+),""",
    """,THREAT,[^"]{1,2000}?,({action}[^,]{1,2000}),\\?"[^"]{0,2000}"""",
    """,THREAT,.+?,\\?"{1,20}([^\(]{1,2000}\()?(|({malware_url}[^"\)]{1,2000}?))\)?[\\\/]{0,2000}"{1,20}
```