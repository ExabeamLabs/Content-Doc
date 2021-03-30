#### Parser Content
```Java
{
Name = cef-netskope-web-activity
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"page"""", """destinationServiceName=Netskope""", """"traffic_type":"Web"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields}[
    """"domain":"({web_domain}[^"\s]+)""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"url":"(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))"""",
    """"appcategory":"({categories}({category}[^";,]+)[^"]*)""",
    """"domain":"([^"]*?)({top_domain}[^.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).*?)"""",
  ]
}
cef-netskope-activity = {
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = ArcSight
  TimeFormat = "epoch_sec"
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """"hostname":\s*"({host}[^"]+)""",
    """"timestamp":\s*({time}\d+)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """"app":\s*"\[?({app}[^"\]]+)""",
    """"(login)?url":\s*"({resource}[^"]+)""",
    """"category\s*":"({additional_info}[^"]+)""",
    """"User Name\s*":"({user_fullname}[^"]+)""",
    """"srcip":\s*"({src_translated_ip}[A-Fa-f:\d.]+)"""",
    """"userip":\s*"({src_ip}[A-Fa-f:\d.]+)"""",
    """"object":\s*"(\s+"|(\s*(Unknown Unknown|unknown|Unknown|null|({object}[^"]+?))\s*"))""",
    """"user":\s*"(unknown|(({user_email}[^@"]+@[^@"]+)|(({domain}[^"@\\\/]+)[\\\/]+)?({user}[^"@\\\/]+)))"""",
    """"traffic_type":\s*"({app_type}[^"]+)""",
    """"access_method":\s*"({auth_method}[^"]+)""",
    """"logintype":\s*"({auth_method}[^"]+)""",
    """"activity":\s*"({activity}[^"]+)""",
    """"os":\s*"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s*"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s*"({web_domain}[^"]+)""",
    """"url":\s*"({full_url}[^"]+)""",
    """"url":\s*"(?!\w+:/+)({file_path}(({file_parent}[^"]*?)[\\\/]+)?({file_name}[^"\\\/]+?))\s*"""",
    """"dst_location":\s*"(N/A|({domain}[^"]+))""",
    """"file_size":\s*({bytes}\d+)""",
    """"file_type":\s*"({file_type}[^"]+)""",
    """"page_site":\s*"({app}[^"]+)""",
  ]

```