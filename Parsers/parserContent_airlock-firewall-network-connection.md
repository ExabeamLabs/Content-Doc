#### Parser Content
```Java
{
Name = airlock-firewall-network-connection
  Vendor = Airlock Web Application Firewall
  Product = Airlock Web Application Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"vhost_proto":"""", """"entry_url":"""", """"entry_query":"""", """"entry_path":"""", """"http_status":"""", """"vhost":"""" ]
  Fields = [
    """({time}\d+\-\d+\-\d+T\d+:\d+:\d+)\.\d+[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s+\{""",
    """"action":"({action}[^"]+)""",
    """"vhost_proto":"({protocol}[^"]+)""",
    """"vhost_port":"({dest_port}\d+)""",
    """"vhost_ip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"vhost":"({dest_host}[\w\-.]+)""",
    """"vhost":"({web_domain}[\w\-.]+)""",
    """"message":"({additional_info}[^"]+)""",
    """"(http_)?status":"({result_code}[^"]+)""",
    """"http_referrer":"(<n\/a>|({referrer}[^"]+))""",
    """"http_method":"({method}[^"]+)""",
    """"host":"({host}[^"]+)""",
    """"entry_url":"({full_url}[^"]+)""",
    """"entry_path":"({uri_path}[^"]+)""",
    """"entry_query":"(<n\/a>|({uri_query}[^"]+))""",
    """"client_ip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"req_size":"({bytes_in}\d+)""",
    """"resp_size":"({bytes_out}\d+)""",
    """"vhost":"[^\s"]*?(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^"\s]*\.)?({top_domain}[^\s\/."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|by|mx|pro|online|ch))+)""",
  ]
  DupFields = [ "action->outcome" ]
}
```