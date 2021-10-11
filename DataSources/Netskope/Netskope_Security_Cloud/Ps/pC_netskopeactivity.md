#### Parser Content
```Java
{
Name = netskope-activity
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch_sec"
  Conditions = [  """"session_begin"""",""""activity"""",""""object_id"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"dstip": "({host}[^"]{1,2000})"""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "({account}[^"]{1,2000})"""",
    """"app": "({app}[^"]{1,2000})"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"browser": "(unknown|({browser}[^"]{1,2000}))"""",
    """"os"{1,20}: "(unknown|({os}[^"]{1,2000}))"""",
    """"activity": "({activity}[^"]{1,2000})"""",
    """"from_user": "(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^"\s]{1,2000})"""",
    """"from_user": "(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"object": ["\\:, ]{1,2000}({file_name}.+?)["\\:, ]{1,2000}
```