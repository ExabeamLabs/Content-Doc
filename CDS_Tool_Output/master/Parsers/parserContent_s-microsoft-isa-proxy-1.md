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
    """exabeam_raw=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\t\,]+(?:anonymous|({user}[\w\\]+))[\t\,]+(?:-|({user_agent}.+?))[\t\,]+({time}\d{4}-\d{2}-\d{2}[\s]+\d{2}:\d{2}:\d{2})(?:[\t\,]+(?:Y|N))?[\t\,]+({host}[\w-_]+)[\t\,]+[^\t\,]+[\s\,]+(?:-|({dest_host}[\w-_]+))[\t\,]+(?:-|({dest_ip}[^\t\,]+))[\t\,]+({dest_port}\d+)[\t\,]+\d+[\t\,]+(?:-|({bytes_out}\d+))[\t\,]+(?:-|({bytes_in}\d+))[\t\,]+({protocol}[\w-]+)[\t\,]+(?:-|({method}\w+))[\t\,]+(?:\w+:\/{2}[^\/]+({uri_path}\/[^?\s]+)?({uri_query}\?[^\t\s\,]+)?)[\t\,]+(?:-|({mime}[^\t\,]+))[\t\,]+(?:Inet|VFInet|0)[\t\,]+(?:-|({response_code}\d+)).+[\t\,]+Req ID.+\s({error_id}0x\d+)[\t\,]+({action}\w+)""",
    """(?:-|({dest_ip}[\d\.]+))[\s\,]+[\w\s]+[\t\,]+(?:None|Web Proxy)[\t\,]+({web_domain}[^\t\,]+)""",
    """(?:[^\t\,]+[\s\,]+){2}.*({browser}[\w\-]+)\/[\d\._]+""",
    """(?:[^\t\,]+[\s\,]+){2}.*({browser}[^\/]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|Windows|Linux|Macintosh|Darwin)""",
    """(?:[^\t\,]+[\s\,]+){2}.*Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|X11|Linux|Windows|Macintosh).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """(?:[^\t\,]+[\s\,]+){2}.*Mozilla\/.+\((?:BeOS|X11|Linux|Windows|Macintosh).+Gecko\/\d+\s+({browser}\w+)""",
    """(?:[^,]+,){11}(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+?(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)[^\/\,]+)(?:\/[^,]+)?,"""
  ]
}
```