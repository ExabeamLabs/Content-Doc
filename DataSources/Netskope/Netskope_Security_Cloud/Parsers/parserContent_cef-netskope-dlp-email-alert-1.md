#### Parser Content
```Java
{
Name = cef-netskope-dlp-email-alert-1
  DataType = "dlp-email-alert"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"object_type":"Mail"""", """"activity":"Send"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields} [
    """"from_user":"({sender}[^"\s@]+@[^"\s@]+)""",
    """"to_user":"({recipients}({recipient}[^"\s@;,]+@({external_domain}[^"\s@,]+))[^"]*)""",
    """"site":"({site_at}[^"]+)""""
  ]
  DupFields = [ "object->file_name", "recipient->external_address", "sender->from_user_at" ]
}
cef-netskope-activity = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = ArcSight
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"hostname":\s*"({host}[^"]+)""",
    """"timestamp":\s*({time}\d+)""",
    """requestClientApplication=({app}.+?)\s+(\w+=|$)""",
    """"app":\s*"\[?({app}[^"\]]+)""",
    """"category\s*":"({additional_info}[^"]+)""",
    """"User Name\s*":"({user_fullname}[^"]+)""",
    """"srcip":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"object":\s*"(\s+"|(\s*(Unknown Unknown|unknown|Unknown|null|({object}[^"]+?))\s*"))""",
    """"user":\s*"(unknown|(({user_email}[^@"]+@[^@"]+)|(({domain}[^"@\\\/]+)[\\\/]+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"@\\\/]+))))"""",
    """"traffic_type":\s*"({app_type}[^"]+)""",
    """"access_method":\s*"({auth_method}[^"]+)""",
    """"logintype":\s*"({auth_method}[^"]+)""",
    """"activity":\s*"({activity}[^"]+)""",
    """"os":\s*"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s*"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s*"({web_domain}[^"//]+)""",
    """"url":\s*"({full_url}[^"]+)""",
    """"url":\s*"(?!\w+:/+)({file_path}(({file_parent}[^"]*?)[\\\/]+)?({file_name}[^"\\\/]+?))\s*"""",
    """"dst_location":\s*"(N/A|({location}[^"]+))""",
    """"file_size":\s*({bytes}\d+)""",
    """"file_type":\s*"({file_type}[^"]+)""",
    """"page_site":\s*"({app}[^"]+)""",
    """"dstport":"\s*({dest_port}\d+)"""
  ]

```