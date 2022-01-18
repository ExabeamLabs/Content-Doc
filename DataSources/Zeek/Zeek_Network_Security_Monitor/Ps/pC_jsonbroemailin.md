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
    """"to\\"{1,20}:\[\\"{1,20}({user_email}[^"\\]{1,2000})""",
    """"id.orig_h\\"{1,20}:\\"{1,20}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id.resp_h\\"{1,20}:\\"{1,20}({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"from\\"{1,20}:\\"{1,20}({sender}[^"\\@]{1,2000}@({external_domain}[^"\\@]{1,2000}))""",
    """"to\\"{1,20}:\[({recipients}\\"{1,20}({recipient}[^"\\]{1,2000})[^\]]{1,2000})\]""",
    """"subject\\"{1,20}:\\"{1,20}({subject}[^"\\]{1,2000})""",
    """"rawmsghostname":"({host}[^"]{1,2000})""",
    """"meta_ts"{1,20}:({time}\d{1,100})""",
  ]
  DupFields = [ "sender->external_address" ]


}
```