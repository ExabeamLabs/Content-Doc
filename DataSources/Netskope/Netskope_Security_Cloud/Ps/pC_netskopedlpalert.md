#### Parser Content
```Java
{
Name = netskope-dlp-alert
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"alert_type": "DLP"""", """"alert": "yes""""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^"\s]{1,2000})"""",
    """"user": "(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000})"""",
    """"policy": "({alert_name}[^"]{1,2000})"""",
    """"alert_type": "({alert_type}[^"]{1,2000})"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url": "({target}[^"]{1,2000})"""",
    """"shared_with": "({additional_info}[^"]{1,2000})"""",
    """"alert_name": "({alert_name}[^"]{1,2000})"""",
    """"internal_id": "({alert_id}[^"]{1,2000})"""",
    """"dlp_rule_severity": "({alert_severity}[^"]{1,2000})"""",
    """"dlp_file": "({file_name}[^"]{1,2000})"""",
    """"file_path": "({file_path}[^"]{1,2000})"""",
    """"file_size": ({bytes}\d{1,100}),""",
    """"md5":\s{0,100}"({md5}[^"]{1,2000})"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]{1,2000})"""",
    """"site":\s{0,100}"({site_at}[^"]{1,2000})""""
  ]
  DupFields = [ "file_path->file_path_at", "additional_info->shared_with_at" ]
}
```