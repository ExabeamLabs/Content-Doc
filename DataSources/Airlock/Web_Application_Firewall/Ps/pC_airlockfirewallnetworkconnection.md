#### Parser Content
```Java
{
Name = airlock-firewall-network-connection
  Vendor = Airlock
  Product = Web Application Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"vhost_proto":"""", """"entry_url":"""", """"entry_query":"""", """"entry_path":"""", """"http_status":"""", """"vhost":"""" ]
  Fields = [
    """({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})\.\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\{""",
    """"action":"({action}[^"]{1,2000})""",
    """"vhost_proto":"({protocol}[^"]{1,2000})""",
    """"vhost_port":"({dest_port}\d{1,100})""",
    """"vhost_ip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"vhost":"({dest_host}[\w\-.]{1,2000})""",
    """"vhost":"({web_domain}[\w\-.]{1,2000})""",
    """"message":"({additional_info}[^"]{1,2000})""",
    """"(http_)?status":"({result_code}[^"]{1,2000})""",
    """"http_referrer":"(<n\/a>|({referrer}[^"]{1,2000}))""",
    """"http_method":"({method}[^"]{1,2000})""",
    """"host":"({host}[^"]{1,2000})""",
    """"entry_url":"({full_url}[^"]{1,2000})""",
    """"entry_path":"({uri_path}[^"]{1,2000})""",
    """"entry_query":"(<n\/a>|({uri_query}[^"]{1,2000}))""",
    """"client_ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"req_size":"({bytes_in}\d{1,100})""",
    """"resp_size":"({bytes_out}\d{1,100})""",
  ]
  DupFields = [ "action->outcome" ]


}
```