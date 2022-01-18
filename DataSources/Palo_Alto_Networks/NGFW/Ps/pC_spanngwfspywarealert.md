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
    """,THREAT,spyware,[^,]{1,2000

}
```