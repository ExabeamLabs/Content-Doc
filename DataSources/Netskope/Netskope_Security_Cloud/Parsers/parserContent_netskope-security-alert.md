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
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp":\s{0,100}({time}\d{1,100})""",
    """"hostname":\s{0,100}"({dest_host}[^"]+)""",
    """"policy":\s{0,100}"({alert_name}[^"]+)"""",
    """"alert_type":\s{0,100}"({alert_type}[^"]+)"""",
    """"dstip":\s{0,100}"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url":\s{0,100}"({malware_url}[^"]+)"""",
    """"alert_name":\s{0,100}"({alert_name}[^"]+)"""",
    """"internal_id":\s{0,100}"({alert_id}[^"]+)"""",
    """"category\s{0,100}":"({additional_info}[^"]+)""",
    """"srcip":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"user"{1,20}:\s{0,100}"{1,20}(unknown|(({user_email}[^"@\\\/\s]+@({domain}[^.]+)[^"]+)))"""",
    """"activity":\s{0,100}"({activity}[^"]+)""",
    """"src_country":\s{0,100}"({country}[^"]+)""",
    """"os":\s{0,100}"((U|u)nknown|({os}[^"]+))""",
    """"browser":\s{0,100}"((U|u)nknown|({browser}[^"]+))""",
    """"page":\s{0,100}"({web_domain}[^"//]+)""",
    """"dst_location":\s{0,100}"(N/A|({location}[^"]+))""",
    """"app":\s{0,100}"({app}[^"]+)""",
    """"md5":\s{0,100}"({md5}[^"]+)"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]+)"""",
    """"file_path":\s{0,100}"({file_path_at}[^"]+)"""",
    """"shared_with":\s{0,100}"({shared_with_at}[^"]+)"""",
    """"site":\s{0,100}"({site_at}[^"]+)""""
  ]
}
```