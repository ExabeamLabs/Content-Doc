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
    """exabeam_host=({host}[^\s]+)""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@[^"\s@]+)"""",
    """"policy": "({alert_name}[^"]+)"""",
    """"alert_type": "({alert_type}[^"]+)"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"url": "({target}[^"]+)"""",
    """"shared_with": "({additional_info}[^"]+)"""",
    """"alert_name": "({alert_name}[^"]+)"""",
    """"internal_id": "({alert_id}[^"]+)"""",
    """"dlp_rule_severity": "({alert_severity}[^"]+)"""",
    """"dlp_file": "({file_name}[^"]+)"""",
    """"file_path": "({file_path}[^"]+)"""",
    """"file_size": ({bytes}\d{1,100}),""",
    """"md5":\s{0,100}"({md5}[^"]+)"""",
    """"from_user":\s{0,100}"({from_user_at}[^"]+)"""",
    """"site":\s{0,100}"({site_at}[^"]+)""""
  ]
  DupFields = [ "file_path->file_path_at", "additional_info->shared_with_at" ]
}
```