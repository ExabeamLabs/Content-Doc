#### Parser Content
```Java
{
Name = cef-netskope-web-activity
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"page"""", """destinationServiceName=Netskope""", """"traffic_type":"Web"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields}[
    """"domain":"({web_domain}[^"\s]{1,2000})""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"url":"(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?(({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))?(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?"]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))"""",
    """"appcategory":"({categories}({category}[^";,]{1,2000})[^"]{0,2000})""",
    """"domain":"([^"]{0,2000}?)({top_domain}[^.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+).*?)"""",
  ]
}
cef-netskope-activity = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = ArcSight
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"hostname":\s{0,100}"({host}[^"]{1,2000})""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """requestClientApplication=({app}.+?)\s{1,100}(\w+=|$)""",
    """"app":\s{0,100}"\[?({app}[^"\]]{1,2000})""",
    """"category\s{0,100}":"({additional_info}[^"]{1,2000})""",
    """"User Name\s{0,100}":"({user_fullname}[^"]{1,2000})""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"object":\s{0,100}"(\s{1,100}"|(\s{0,100}(Unknown Unknown|unknown|Unknown|null|({object}[^"]{1,2000}?))\s{0,100}"))""",
    """"user":\s{0,100}"(unknown|(({user_email}[^@"]{1,2000}@[^@"]{1,2000})|(({domain}[^"@\\\/]{1,2000})[\\\/]{1,2000})?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"@\\\/]{1,2000}))))"""",
    """"traffic_type":\s{0,100}"({app_type}[^"]{1,2000})""",
    """"access_method":\s{0,100}"({auth_method}[^"]{1,2000})""",
    """"logintype":\s{0,100}"({auth_method}[^"]{1,2000})""",
    """"activity":\s{0,100}"({activity}[^"]{1,2000})""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]{1,2000}))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]{1,2000}))""",
    """"page":\s{0,100}"({web_domain}[^"//]{1,2000})""",
    """"url":\s{0,100}"({full_url}[^"]{1,2000})""",
    """"url":\s{0,100}"(?!\w+:/+)({file_path}(({file_parent}[^"]{0,2000}?)[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?))\s{0,100}"""",
    """"dst_location":\s{0,100}"(N/A|({location}[^"]{1,2000}))""",
    """"file_size":\s{0,100}({bytes}\d{1,100})""",
    """"file_type":\s{0,100}"({file_type}[^"]{1,2000})""",
    """"page_site":\s{0,100}"({app}[^"]{1,2000})""",
    """"dstport":"\s{0,100}({dest_port}\d{1,100})"""
  ]

```