#### Parser Content
```Java
{
Name = netskope-alert
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """session_begin""",""""alert": "yes"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"dstip": "({host}[^"]+)",""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"policy": "({alert_name}[^"]+).*({alert_type}policy)""",
    """"alert_name": "({alert_name}[^"]+)"""",
    """"alert_type": "({alert_type}[^"]+)"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url": "({additional_info}[^"]+)"""",
    """"app":\s{0,100}"({process_name}[^"]+)"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]+)"""",
    """"shared_with":\s{0,100}"({shared_with_at}[^"]+)"""",
    """"site":\s{0,100}"({site_at}[^"]+)""""
  ]
}
```