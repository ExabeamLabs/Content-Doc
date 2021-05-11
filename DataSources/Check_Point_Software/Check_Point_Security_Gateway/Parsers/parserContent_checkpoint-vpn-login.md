#### Parser Content
```Java
{
Name = checkpoint-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  TimeFormat = "ddMMMyyyy,HH:mm:ss"
  DataType = "vpn-start"
  Conditions = [ """log,authorize,""", """Sign On""", """Authenticated by RADIUS""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100})(\s{1,100}(\+|\-)\d{1,100})?,(|({host}[^,]+)),log,authorize,([^,]*,){8}(|({src_ip}[^,]+)),(|({dest_ip}[^,]+)),([^,]*,){14}(|({user}[^,]+)),""",
  ]
  DupFields = ["user->account"]
}
```