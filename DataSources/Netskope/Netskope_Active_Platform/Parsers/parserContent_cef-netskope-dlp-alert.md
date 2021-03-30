#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"alert_type":"DLP"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields}[
    """"policy":"({alert_name}[^"]+)""",
    """"dlp_rule_severity":"({alert_severity}[^"]+)""",
    """"dlp_incident_id":({alert_id}\d+)""",
  ]
  DupFields = [ "activity->alert_type", "object->file_name" ]
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