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
    """"to\\"{1,20}:\[\\"{1,20}({user_email}[^"\\]+)""",
    """"id.orig_h\\"{1,20}:\\"{1,20}({src_ip}[a-fA-F\d.:]+)""",
    """"id.resp_h\\"{1,20}:\\"{1,20}({dest_ip}[a-fA-F\d.:]+)""",
    """"from\\"{1,20}:\\"{1,20}({sender}[^"\\@]+@({external_domain}[^"\\@]+))""",
    """"to\\"{1,20}:\[({recipients}\\"{1,20}({recipient}[^"\\]+)[^\]]+)\]""",
    """"subject\\"{1,20}:\\"{1,20}({subject}[^"\\]+)""",
    """"rawmsghostname":"({host}[^"]+)""",
    """"meta_ts"{1,20}:({time}\d{1,100})""",
  ]
  DupFields = [ "sender->external_address" ]
}
```