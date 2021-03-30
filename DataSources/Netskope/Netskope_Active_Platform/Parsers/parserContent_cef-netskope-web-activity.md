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
    """"hostname":"({host}[^"]+)""",
    """"timestamp":({time}\d+)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """"app":"\[?({app}[^"\]]+)""",
    """"(login)?url":"({resource}[^"]+)""",
    """"category":"({additional_info}[^"]+)""",
    """"User Name":"({user_fullname}[^"]+)""",
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]+)"""",
    """"userip":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"object":"(\s+"|(\s*(Unknown Unknown|unknown|Unknown|null|({object}[^"]+?))\s*"))""",
    """"user":"(unknown|(({user_email}[^@"]+@[^@"]+)|(({domain}[^"@\\\/]+)[\\\/]+)?({user}[^"@\\\/]+)))"""",
    """"traffic_type":"({app_type}[^"]+)""",
    """"access_method":"({auth_method}[^"]+)""",
    """"logintype":"({auth_method}[^"]+)""",
    """"activity":"({activity}[^"]+)""",
    """"os":"((U|u)nknown|({os}[^"]+))""",
    """"browser":"((U|u)nknown|({browser}[^"]+))""",
    """"page":"({web_domain}[^"]+)""",
    """"url":"({full_url}[^"]+)""",
    """"url":"(?!\w+:/+)({file_path}(({file_parent}[^"]*?)[\\\/]+)?({file_name}[^"\\\/]+?))\s*"""",
    """"dst_location":"(N/A|({domain}[^"]+))""",
    """"file_size":({bytes}\d+)""",
    """"file_type":"({file_type}[^"]+)""",
  ]

```