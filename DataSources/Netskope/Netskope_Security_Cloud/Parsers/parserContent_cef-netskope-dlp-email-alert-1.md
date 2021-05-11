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
    """"hostname":\s{0,100}"({src_host}[^"]+)""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """requestClientApplication=({app}.+?)\s{1,100}(\w+=|$)""",
    """"app":\s{0,100}"\[?({app}[^"\]]+)""",
    """"User Name\s{0,100}":"({user_fullname}[^"]+)""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"object":\s{0,100}"(\s{1,100}"|(\s{0,100}(Unknown Unknown|unknown|Unknown|null|({object}[^"]+?))\s{0,100}"))""",
    """"user":\s{0,100}"(unknown|(({user_email}[\s^@"]+@[\s^@"]+\.[\s^@"]+)|(({domain}[^\s"@\\\/]+)[\\\/]+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^\s"@\\\/]+))))"""",
    """"access_method":\s{0,100}"({auth_method}[^"]+)""",
    """"logintype":\s{0,100}"({auth_method}[^"]+)""",
    """"activity":\s{0,100}"({activity}[^"]+)""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s{0,100}"({web_domain}[^"//]+)""",
    """"url":\s{0,100}"({full_url}[^"]+)""",
    """"dst_location":\s{0,100}"(N/A|({location}[^"]+))""",
    """"file_size":\s{0,100}({bytes}\d{1,100})""",
    """"file_type":\s{0,100}"({file_type}[^"]+)""",
    """"page_site":\s{0,100}"({app}[^"]+)""",
    """"dstport":"\s{0,100}({dest_port}\d{1,100})"""
  ]

```