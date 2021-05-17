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
    """"hostname":\s{0,100}"({dest_host}[^"]{1,2000})""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """"app":\s{0,100}"\[?({app}[^"\]]{1,2000})""",
    """"url":\s{0,100}"({resource}[^"]{1,2000})""",
    """"category\s{0,100}":"({additional_info}[^"]{1,2000})""",
    """"srcip":\s{0,100}"({src_translated_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"userip":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"user":\s{0,100}"(unknown|(({user_email}({user}[^"@\\\/\s]{1,2000})@({domain}[^.]{1,2000})[^"]{1,2000})))"""",
    """"traffic_type":\s{0,100}"({app_type}[^"]{1,2000})""",
    """"access_method":\s{0,100}"({auth_method}[^"]{1,2000})""",
    """"activity":\s{0,100}"({activity}[^"]{1,2000})""",
    """"src_country":\s{0,100}"({country}[^"]{1,2000})""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]{1,2000}))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]{1,2000}))""",
    """"page":\s{0,100}"({web_domain}[^"]{1,2000})""",
    """"url":\s{0,100}"({full_url}[^"]{1,2000})""",
    """"dst_location":\s{0,100}"(N/A|({domain}[^"]{1,2000}))""",
    """"app":\s{0,100}"({app}[^"]{1,2000})""",
  ]
}
```