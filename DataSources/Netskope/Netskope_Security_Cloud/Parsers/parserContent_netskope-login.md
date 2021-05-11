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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"dstip": "({host}[^"]+)"""",
    """"timestamp": ({time}\d{1,100})""",
    """"user": "(?![^\s]+@[^\s]+)({user}[^"\s]+)"""",
    """"user": "(?=[^\s]+@[^\s]+)({user_email}[^"\s@]+@({email_domain}[^"\s@]+))"""",
    """"app": "({app}[^"]+)"""",
    """"dstip": "({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"srcip": "({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"browser": "(unknown|({browser}[^"]+))"""",
    """"os": "(unknown|({os}[^"]+))""""
  ]
}
```