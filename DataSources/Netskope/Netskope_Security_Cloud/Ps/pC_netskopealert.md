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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"dstip": "({host}[^"]{1,2000})",""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^"\s]{1,2000})"""",
    """"user": "(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"policy": "({alert_name}[^"]{1,2000}).*({alert_type}policy)""",
    """"alert_name": "({alert_name}[^"]{1,2000})"""",
    """"alert_type": "({alert_type}[^"]{1,2000})"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url": "({additional_info}[^"]{1,2000})"""",
    """"app":\s{0,100}"({process_name}[^"]{1,2000})"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]{1,2000})"""",
    """"shared_with":\s{0,100}"({shared_with_at}[^"]{1,2000})"""",
    """"site":\s{0,100}"({site_at}[^"]{1,2000})""""
  ]


}
```