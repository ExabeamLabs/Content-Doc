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
    """exabeam_host=({host}[^\s]+)""",
    """"host":\{.*?"name":"({host}[^"]+)".*?\}""",
    """,THREAT,spyware,[^,]+,({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """,THREAT,spyware,[^,]+,({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """,THREAT,spyware,([^,]+,){2}({dest_ip}[a-fA-F\d:.]+),({src_ip}[a-fA-F\d:.]+),""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s""",
    """THREAT,({alert_type}\w+),""",
    """,THREAT,[^"]+?,({action}[^,]+),\\?"[^"]*"""",
    """,THREAT,.+?,\\?"{1,20}([^\(]+\()?(|({malware_url}[^"\)]+?))\)?[\\\/]*"{1,20}
```