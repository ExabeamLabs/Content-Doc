#### Parser Content
```Java
{
Name = netskope-security-alert
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"alert_type": """, """"alert": "yes"""", """"alert_name":"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """"hostname":\s{0,100}"({dest_host}[^"]{1,2000})""",
    """"policy":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"alert_type":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"dstip":\s{0,100}"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url":\s{0,100}"({malware_url}[^"]{1,2000})"""",
    """"alert_name":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"internal_id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"category\s{0,100}":"({additional_info}[^"]{1,2000})""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"user"{1,20}:\s{0,100}"{1,20}(unknown|(({user_email}[^"@\\\/\s]{1,2000}@({domain}[^.]{1,2000})[^"]{1,2000})))"""",
    """"activity":\s{0,100}"({activity}[^"]{1,2000})""",
    """"src_country":\s{0,100}"({country}[^"]{1,2000})""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]{1,2000}))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]{1,2000}))""",
    """"page":\s{0,100}"({web_domain}[^"//]{1,2000})""",
    """"dst_location":\s{0,100}"(N/A|({location}[^"]{1,2000}))""",
    """"app":\s{0,100}"({app}[^"]{1,2000})""",
    """"md5":\s{0,100}"({md5}[^"]{1,2000})"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]{1,2000})"""",
    """"file_path":\s{0,100}"({file_path_at}[^"]{1,2000})"""",
    """"shared_with":\s{0,100}"({shared_with_at}[^"]{1,2000})"""",
    """"site":\s{0,100}"({site_at}[^"]{1,2000})""""
  ]
}
```