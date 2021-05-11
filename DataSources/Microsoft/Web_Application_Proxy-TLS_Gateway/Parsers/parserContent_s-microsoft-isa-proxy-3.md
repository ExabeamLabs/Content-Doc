#### Parser Content
```Java
{
Name = s-microsoft-isa-proxy-3
  Vendor = Microsoft
  Product = Web Application Proxy-TLS Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd\tHH:mm:ss"
  Conditions = [ """Web Proxy""", """Req ID:""" ]
  Fields = [
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\t\,]+(?:anonymous|({user}[\w\\]+))[\t\,]+(?:-|({user_agent}.+?))[\t\,]+({time}\d{4}-\d{2}-\d{2}[\s]+\d{2}:\d{2}:\d{2})(?:[\t\,]+(?:Y|N))?[\t\,]+({host}[\w\-_]+)[\t\,]+[^\t\,]+[\s\,]+(?:-|({dest_host}[\w\-_.]+))[\t\,]+(?:-|({dest_ip}[^\t\,]+))[\t\,]+({dest_port}\d{1,100})[\t\,]+\d{1,100}[\t\,]+(?:-|({bytes_out}\d{1,100}))[\t\,]+(?:-|({bytes_in}\d{1,100}))[\t\,]+({protocol}[\w-]+)[\t\,]+(?:-|({method}\w+))[\t\,]+(?:({full_url}(\w+:\/{2})?(({=dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\t\/]*?({top_domain}[^\.\/\t]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|mx|fmx))+)?))(:({=dest_port}\d{1,100}))?({uri_path}\/[^?\s]*)?({uri_query}\?[^\t\s\,]*)?))[\t\,]+(?:(?:-|({mime}[^\t\,]+))[\t\,]+(?:-|Inet|VFInet|0)[\t\,]+(?:-|({response_code}\d{1,100})).+[\t\,]+Req ID.+\s({error_id}0x\d{1,100})[\t\,]+({action}\w+))?""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|X11|Linux|Windows|Macintosh)[^\t]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```