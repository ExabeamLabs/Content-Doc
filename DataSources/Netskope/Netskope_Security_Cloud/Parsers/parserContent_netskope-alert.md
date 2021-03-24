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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"dstip": "({host}[^"]+)",""",
    """"timestamp": ({time}\d+)""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"policy": "({alert_name}[^"]+).*({alert_type}policy)""",
    """"alert_name": "({alert_name}[^"]+)"""",
    """"alert_type": "({alert_type}[^"]+)"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url": "({additional_info}[^"]+)"""",
    """"app":\s*"({process_name}[^"]+)"""",
    """"from_user":\s*"({from_user_at}[^"]+)"""",
    """"shared_with":\s*"({shared_with_at}[^"]+)"""",
    """"site":\s*"({site_at}[^"]+)""""
  ]
}
```