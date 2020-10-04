#### Parser Content
```Java
{
Name = s-sailpointsiq-sponpremise-file-delete
  Vendor = Sailpoint
  Lms = Splunk
  Product = SecurityIQ
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = ["""| applicationtype : Sharepoint |""", """actiontype : Delete"""]
  
  Fields = [
    """creation_timestamp\s:\s({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3})""",
    """ipaddress\s:\s({host}[^|]+)\s\|""",
    """userfullname\s:\s({user_sid}(?=[^\\]+\\)({domain}[^\\]+)\\({user}.+?)|(?:.+?))\s\|""",
    """objectname\s:\s({file_name}[^|]+)\s\|""",
    """domain\s:\s({domain}[^|]+)\s\|""",
    """applicationtype\s:\s({app}[^|]+)\s\|""",
    """\spath\s:\s({file_parent}[^|]+)\s\|""",
    """fileextension\s:\s({file_ext}[^|]+)\s\|""",
    """actiontype\s:\s({activity}[^\ ]+)(\s|\s\([^\)]+\)\s)\|"""
  ]
  DupFields = [ "host->dest_ip", "activity->accesses" ]
}
{
  Name = airlock-firewall-network-connection
  Vendor = Airlock
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