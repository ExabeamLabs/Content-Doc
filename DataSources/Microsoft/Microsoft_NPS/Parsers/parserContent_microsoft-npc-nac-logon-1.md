#### Parser Content
```Java
{
Name = microsoft-npc-nac-logon-1
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Splunk
  DataType = "nac-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss.SSS"
  Conditions = ["""<Packet-Type data_type="0">2</Packet-Type>""", """<Client-IP-Address""", """<Authentication-Type"""]
  Fields = [
    """<Timestamp[^>]+>({time}\d+\/\d+\/\d+\s\d+:\d+:\d+\.\d+)<""",
    """<Computer-Name[^>]+>({host}[^<]+)<""",
    """Fully-Qualifed-User-Name[^>]+>[^>]*?[\\\/]+?({user}[^\\\/]*?)<""",
    """<Client-IP-Address[^>]+>({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """<Authentication-Type[^>]+>({auth_type}[^<]+)<""",
    """Proxy-Policy-Name[^>]+>({additional_info}[^<]+)<""",
    """<Packet-Type.+?>({outcome}\d+)""",
    """<SAM-Account-Name[^>]+>(({domain}[^<\\]+)\\)?({account}[^<]+)""",
    """<NAS-IP-Address data_type=[^>]+>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})<""",
    """<NP-Policy-Name[^>]+>({network}[^<]+)<""",
  ]
  DupFields = [ "host->dest_host","outcome->event_code" ]
}
```