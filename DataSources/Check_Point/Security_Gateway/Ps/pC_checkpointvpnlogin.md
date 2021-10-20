#### Parser Content
```Java
{
Name = checkpoint-vpn-login
  Vendor = Check Point 
  Product = Security Gateway
  Lms = Direct
  TimeFormat = "ddMMMyyyy,HH:mm:ss"
  DataType = "vpn-start"
  Conditions = [ """log,authorize,""", """Sign On""", """Authenticated by RADIUS""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100})(\s{1,100}(\+|\-)\d{1,100})?,(|({host}[^,]{1,2000})),log,authorize,([^,]{0,2000},){8}(|({src_ip}[^,]{1,2000})),(|({dest_ip}[^,]{1,2000})),([^,]{0,2000},){14}(|({user}[^,]{1,2000})),""",
  ]
  DupFields = ["user->account"]
}
```