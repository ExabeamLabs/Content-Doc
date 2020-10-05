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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """host"*:"*\{"*name"*:"*({host}[^"]+)"""",
    """remote_addr":"(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}\S+))"*""",
    """verb":"({method}[^"]+)"""",
    """request":"({uri_path}[^"\?\s]+)(?:\?({uri_query}[^?\s"]+))?"""",
    """response":"({result_code}\d+)""",
    """bytes":"(-|({bytes_out}\d+))""",
    """referrer":"(-|({referrer}[^"]+))"""",
    """user_agent":"(-|({user_agent}[^"]+))"""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """location":"(-|({full_url}[^"]))""""
  ]
}
```