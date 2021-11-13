#### Parser Content
```Java
{
Name = netskope-login
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """session_begin""","""activity": "Login Successful""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"dstip": "({host}[^"]{1,2000})"""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]{1,2000}@[^\s]{1,2000})({user}[^"\s]{1,2000})"""",
    """"user": "(?=[^\s]{1,2000}@[^\s]{1,2000})({user_email}[^"\s@]{1,2000}@({email_domain}[^"\s@]{1,2000}))"""",
    """"app": "({app}[^"]{1,2000})"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"browser": "(unknown|({browser}[^"]{1,2000}))"""",
    """"os": "(unknown|({os}[^"]{1,2000}))""""
  ]


}
```