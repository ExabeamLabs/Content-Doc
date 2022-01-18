#### Parser Content
```Java
{
Name = microsoft-npc-failed-logon-1
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Splunk
  DataType = "nac-failed-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss.SSS"
  Conditions = ["""<Packet-Type data_type="0">3</Packet-Type>""", """<Client-IP-Address""", """<Authentication-Type"""]
  Fields = [
    """<Timestamp[^>]{1,2000}>({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})<""",
    """<Computer-Name[^>]{1,2000}>({host}[^<]{1,2000})<""",
    """Fully-Qualifed-User-Name[^>]{1,2000}>[^>]{0,2000}?[\\\/]{1,2000}?({user}[^\\\/]{0,2000}?)<""",
    """<Client-IP-Address[^>]{1,2000}>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """<Authentication-Type[^>]{1,2000}>({auth_type}[^<]{1,2000})<""",
    """Proxy-Policy-Name[^>]{1,2000}>({additional_info}[^<]{1,2000})<""",
    """<Packet-Type.+?>({outcome}\d{1,100})""",
    """<SAM-Account-Name[^>]{1,2000}>(({domain}[^<\\]{1,2000})\\)?({account}[^<]{1,2000})""",
    """<NAS-IP-Address data_type=[^>]{1,2000}>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<""",
    """<NP-Policy-Name[^>]{1,2000}>({network}[^<]{1,2000})<""",
    """<Reason-Code[^>]{1,2000}>({failure_reason}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host","outcome->event_code" ]


}
```