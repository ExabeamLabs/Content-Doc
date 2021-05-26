#### Parser Content
```Java
{
Name = cef-netskope-dlp-alert
  DataType = "dlp-alert"
  Conditions = [ """CEF:""", """|Skyformation|""", """"type":"""", """destinationServiceName=Netskope""", """"alert_type":"DLP"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-activity.Fields}[
    """"policy":"({alert_name}[^"]{1,2000})""",
    """"dlp_rule_severity":"({alert_severity}[^"]{1,2000})""",
    """"dlp_incident_id":({alert_id}\d{1,100})""",
    """"from_user":"({from_user_at}[^",]{1,2000})"""",
    """"sha256":"({sha256_at}[^",]{1,2000})"""",
    """"site":"({site_at}[^",]{1,2000})"""",
    """"shared_with":"({shared_with_at}[^"]{1,2000})""""
  ]
  DupFields = [ "activity->alert_type", "object->file_name" ]
}
cef-netskope-activity = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = ArcSight
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"hostname":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """requestClientApplication=({app}.+?)\s{1,100}(\w+=|$)""",
    """"app":\s{0,100}"\[?({app}[^"\]]{1,2000})""",
    """"User Name\s{0,100}":"({user_fullname}[^"]{1,2000})""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"object":\s{0,100}"(\s{1,100}"|(\s{0,100}(Unknown Unknown|unknown|Unknown|null|({object}[^"]{1,2000}?))\s{0,100}"))""",
    """"user":\s{0,100}"(unknown|(({user_email}[\s^@"]{1,2000}@[\s^@"]{1,2000}\.[\s^@"]{1,2000})|(({domain}[^\s"@\\\/]{1,2000})[\\\/]{1,2000})?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^\s"@\\\/]{1,2000}))))"""",
    """"access_method":\s{0,100}"({auth_method}[^"]{1,2000})""",
    """"logintype":\s{0,100}"({auth_method}[^"]{1,2000})""",
    """"activity":\s{0,100}"({activity}[^"]{1,2000})""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]{1,2000}))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]{1,2000}))""",
    """"page":\s{0,100}"({web_domain}[^"//]{1,2000})""",
    """"url":\s{0,100}"({full_url}[^"]{1,2000})""",
    """"dst_location":\s{0,100}"(N/A|({location}[^"]{1,2000}))""",
    """"file_size":\s{0,100}({bytes}\d{1,100})""",
    """"file_type":\s{0,100}"({file_type}[^"]{1,2000})""",
    """"page_site":\s{0,100}"({app}[^"]{1,2000})""",
    """"dstport":"\s{0,100}({dest_port}\d{1,100})"""
  ]

```