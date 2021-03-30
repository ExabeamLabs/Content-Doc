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