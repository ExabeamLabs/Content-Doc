#### Parser Content
```Java
{
Name = netskope-app-activity
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [""""app": """, """"userkey": """, """"category": """, """"browser_session_id": """]
  Fields = [
    """"hostname":\s{0,100}"({dest_host}[^"]+)""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """"app":\s{0,100}"\[?({app}[^"\]]+)""",
    """"url":\s{0,100}"({resource}[^"]+)""",
    """"category\s{0,100}":"({additional_info}[^"]+)""",
    """"srcip":\s{0,100}"({src_translated_ip}[A-Fa-f:\d.]+)"""",
    """"userip":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)"""",
    """"user":\s{0,100}"(unknown|(({user_email}({user}[^"@\\\/\s]+)@({domain}[^.]+)[^"]+)))"""",
    """"traffic_type":\s{0,100}"({app_type}[^"]+)""",
    """"access_method":\s{0,100}"({auth_method}[^"]+)""",
    """"activity":\s{0,100}"({activity}[^"]+)""",
    """"src_country":\s{0,100}"({country}[^"]+)""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s{0,100}"({web_domain}[^"]+)""",
    """"url":\s{0,100}"({full_url}[^"]+)""",
    """"dst_location":\s{0,100}"(N/A|({domain}[^"]+))""",
    """"app":\s{0,100}"({app}[^"]+)""",
  ]
}
```