#### Parser Content
```Java
{
Name = s-microsoft-isa-proxy-1
  Vendor = Microsoft
  Product = Web Application Proxy-TLS Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd\tHH:mm:ss"
  Conditions = [ """\tInet\t""", """\tReq ID:""" ]
  Fields = [
    """exabeam_raw=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\t\,]{1,2000}(?:anonymous|({user}[\w\\]{1,2000}))[\t\,]{1,2000}(?:-|({user_agent}.+?))[\t\,]{1,2000}({time}\d{4}-\d{2}-\d{2}[\s]{1,2000}\d{2}:\d{2}:\d{2})(?:[\t\,]{1,2000}(?:Y|N))?[\t\,]{1,2000}({host}[\w-_]{1,2000})[\t\,]{1,2000}[^\t\,]{1,2000}[\s\,]{1,2000}(?:-|({dest_host}[\w-_]{1,2000}))[\t\,]{1,2000}(?:-|({dest_ip}[^\t\,]{1,2000}))[\t\,]{1,2000}({dest_port}\d{1,100})[\t\,]{1,2000}\d{1,100}[\t\,]{1,2000}(?:-|({bytes_out}\d{1,100}))[\t\,]{1,2000}(?:-|({bytes_in}\d{1,100}))[\t\,]{1,2000}({protocol}[\w-]{1,2000})[\t\,]{1,2000}(?:-|({method}\w+))[\t\,]{1,2000}(?:\w+:\/{2}[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})?({uri_query}\?[^\t\s\,]{1,2000})?)[\t\,]{1,2000}(?:-|({mime}[^\t\,]{1,2000}))[\t\,]{1,2000}(?:Inet|VFInet|0)[\t\,]{1,2000}(?:-|({response_code}\d{1,100})).+[\t\,]{1,2000}Req ID.+\s({error_id}0x\d{1,100})[\t\,]{1,2000}({action}\w+)""",
    """(?:-|({dest_ip}[\d\.]{1,2000}))[\s\,]{1,2000}[\w\s]{1,2000}[\t\,]{1,2000}(?:None|Web Proxy)[\t\,]{1,2000}({web_domain}[^\t\,]{1,2000})""",
  ]


}
```