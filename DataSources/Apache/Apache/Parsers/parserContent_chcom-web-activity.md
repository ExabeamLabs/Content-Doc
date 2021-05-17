#### Parser Content
```Java
{
Name = chcom-web-activity
  Vendor = Apache
  Product = Apache
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """chcom_access_log""", """apache_access_log""", """"request":"""", """"response":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """host"{0,20}:"{0,20}\{"{0,20}name"{0,20}:"{0,20}({host}[^"]{1,2000})"""",
    """remote_addr":"(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}\S+))"{0,20}""",
    """verb":"({method}[^"]{1,2000})"""",
    """request":"({uri_path}[^"\?\s]{1,2000})(?:\?({uri_query}[^?\s"]{1,2000}))?"""",
    """response":"({result_code}\d{1,100})""",
    """bytes":"(-|({bytes_out}\d{1,100}))""",
    """referrer":"(-|({referrer}[^"]{1,2000}))"""",
    """user_agent":"(-|({user_agent}[^"]{1,2000}))"""",
    """Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """location":"(-|({full_url}[^"]))""""
  ]
}
```