#### Parser Content
```Java
{
Name = netskope-security-alert
  Vendor = Netskope
  Product = Netskope Active Platform
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"alert_type": """, """"alert": "yes"""", """"alert_name":"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":\s*({time}\d+)""",
    """"hostname":\s*"({dest_host}[^"]+)""",
    """"policy":\s*"({alert_name}[^"]+)"""",
    """"alert_type":\s*"({alert_type}[^"]+)"""",
    """"dstip":\s*"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url":\s*"({malware_url}[^"]+)"""",
    """"alert_name":\s*"({alert_name}[^"]+)"""",
    """"internal_id":\s*"({alert_id}[^"]+)"""",
    """"category\s*":"({additional_info}[^"]+)""",
    """"srcip":\s*"({src_translated_ip}[A-Fa-f:\d.]+)"""",
    """"userip":\s*"({src_ip}[A-Fa-f:\d.]+)"""",
    """"user"+:\s*"+(unknown|(({user_email}[^"@\\\/\s]+@({domain}[^.]+)[^"]+)))"""",
    """"activity":\s*"({activity}[^"]+)""",
    """"src_country":\s*"({country}[^"]+)""",
    """"os":\s*"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s*"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s*"({web_domain}[^"]+)""",
    """"dst_location":\s*"(N/A|({domain}[^"]+))""",
    """"app":\s*"({app}[^"]+)""",
  ]
}
```