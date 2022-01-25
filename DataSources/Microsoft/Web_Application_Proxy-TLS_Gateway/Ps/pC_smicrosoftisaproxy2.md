#### Parser Content
```Java
{
Name = s-microsoft-isa-proxy-2
  Vendor = Microsoft
  Product = Web Application Proxy-TLS Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd\tHH:mm:ss"
  Conditions = [ """Compression: client=""", """\thttp\tGET\thttp""" ]
  Fields = [
    """exabeam_raw=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\t\,]{1,2000}(?:anonymous|({user}[\w\\]{1,2000}))[\t\,]{1,2000}(?:-|({user_agent}.+?))[\t\,]{1,2000}({time}\d{4}-\d{2}-\d{2}[\s]{1,2000}\d{2}:\d{2}:\d{2})(?:[\t\,]{1,2000}(?:Y|N))?[\t\,]{1,2000}({host}[\w-_]{1,2000})[\t\,]{1,2000}[^\t\,]{1,2000}[\s\,]{1,2000}(?:-|({dest_host}[\w-_]{1,2000}))[\t\,]{1,2000}(?:-|({dest_ip}[^\t\,]{1,2000}))[\t\,]{1,2000}({dest_port}\d{1,100})[\t\,]{1,2000}\d{1,100}[\t\,]{1,2000}(?:-|({bytes_out}\d{1,100}))[\t\,]{1,2000}(?:-|({bytes_in}\d{1,100}))[\t\,]{1,2000}({protocol}[\w-]{1,2000})[\t\,]{1,2000}(?:-|({method}\w+))[\t\,]{1,2000}(?:\w+:\/{2}[^\/]{1,2000}({uri_path}\/[^?\s]{1,2000})?({uri_query}\?[^\t\s\,]{1,2000})?)[\t\,]{1,2000}(?:-|({mime}[^\t\,]{1,2000}))[\t\,]{1,2000}(?:Inet|VFInet|0)[\t\,]{1,2000}(?:-|({response_code}\d{1,100})).+[\t\,]{1,2000}Req ID.+\s({error_id}0x\d{1,100})[\t\,]{1,2000}({action}\w+)""",
    """(?:-|({dest_ip}[\d\.]{1,2000}))[\s\,]{1,2000}[\w\s]{1,2000}[\t\,]{1,2000}(?:None|Web Proxy)[\t\,]{1,2000}({web_domain}[^\t\,]{1,2000})""",
    """(?:[^\t\,]{1,2000}[\s\,]{1,2000}){2}.*({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
    """(?:[^\t\,]{1,2000}[\s\,]{1,2000}){2}.*({browser}[^\/]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|Windows|Linux|Macintosh|Darwin)""",
    """(?:[^\t\,]{1,2000}[\s\,]{1,2000}){2}.*Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|X11|Linux|Windows|Macintosh).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """(?:[^\t\,]{1,2000}[\s\,]{1,2000}){2}.*Mozilla\/.+\((?:BeOS|X11|Linux|Windows|Macintosh).+Gecko\/\d{1,100}\s{1,100}({browser}\w+)""",
    """(?:[^,]{1,2000

}
```