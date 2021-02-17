#### Parser Content
```Java
{
Name = json-bro-email-in
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = [ """bro_smtp""", """"id.orig_h""", """"id.resp_h""" ]
  Fields = [
    """"to\\"+:\[\\"+({user_email}[^"\\]+)""",
    """"id.orig_h\\"+:\\"+({src_ip}[a-fA-F\d.:]+)""",
    """"id.resp_h\\"+:\\"+({dest_ip}[a-fA-F\d.:]+)""",
    """"from\\"+:\\"+({sender}[^"\\@]+@({external_domain}[^"\\@]+))""",
    """"to\\"+:\[({recipients}\\"+({recipient}[^"\\]+)[^\]]+)\]""",
    """"subject\\"+:\\"+({subject}[^"\\]+)""",
    """"rawmsghostname":"({host}[^"]+)""",
    """"meta_ts"+:({time}\d+)""",
  ]
  DupFields = [ "sender->external_address" ]
}
```