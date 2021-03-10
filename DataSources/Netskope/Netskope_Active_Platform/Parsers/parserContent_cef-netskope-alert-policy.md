#### Parser Content
```Java
{
Name = cef-netskope-alert-policy
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"alert":"yes"""" ]
  Fields = ${NetskopeParserTemplates.cef-netskope-alert.Fields}[
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """"malsite_category":\["({threat_category}[^"]+)"[^\]]*?\]""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"action":"({outcome}[^"]+)""",
    """"hostname":"({src_host}[^"]+)""",
    """"referer":"({referrer}[^"]+)""",
    """"policy":"({additional_info}[^"]+)""",
    """"page":"({web_domain}[^\\\/"]+)""",
    """"app":"({process_name}[^"]+)"""",
    """CEF:([^\|]*\|){6}({alert_severity}[^\|]+)\|""",
    """"_id":"({alert_id}[^"]+)""",
    """"owner":"({file_owner_at}[^"]+)"""",
    """"user":"({from_user_at}[^"]+)"""",
    """"object":"({file_path_at}[^"]+)"""",
    """"file_path":"({file_path_at}[^"]+)"""",
    """"site":"({site_at}[^"]+)""""
  ]
}
```