#### Parser Content
```Java
{
Name = cef-symantec-sep-alert-4
  Conditions = [ """CEF:""", """|Symantec|""", """|sep_proxy_ips_event|""" ]
  Fields = ${SymantecParserTemplates.cef-symantec-sep-alert.Fields}[
    """({host}[\w.\-]+)\s+sep_proxy_ips_event:""",
    """"file":.*?"name":"({malware_file_name}[^"]+)""",
    """"data_source_url_domain":"({additional_info}[^"]+)""",
  ]
}
```