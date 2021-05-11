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
    """<Timestamp[^>]+>({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100})<""",
    """<Computer-Name[^>]+>({host}[^<]+)<""",
    """Fully-Qualifed-User-Name[^>]+>[^>]*?[\\\/]+?({user}[^\\\/]*?)<""",
    """<Client-IP-Address[^>]+>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """<Authentication-Type[^>]+>({auth_type}[^<]+)<""",
    """Proxy-Policy-Name[^>]+>({additional_info}[^<]+)<""",
    """<Packet-Type.+?>({outcome}\d{1,100})""",
    """<SAM-Account-Name[^>]+>(({domain}[^<\\]+)\\)?({account}[^<]+)""",
    """<NAS-IP-Address data_type=[^>]+>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<""",
    """<NP-Policy-Name[^>]+>({network}[^<]+)<""",
    """<Reason-Code[^>]+>({failure_reason}\d{1,100})"""
  ]
  DupFields = [ "host->dest_host","outcome->event_code" ]
}
```