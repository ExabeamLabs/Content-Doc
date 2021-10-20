#### Parser Content
```Java
{
Name = checkpoint-failed-vpn-login
  Vendor = Check Point 
  Product = Security Gateway
  Lms = Direct
  TimeFormat = "ddMMMyyyy,HH:mm:ss"
  DataType = "failed-vpn-login"
  Conditions = [ """,alert,reject,""" ]
  Fields = [
    """({time}\d{1,100}\w+\d\d\d\d,\d{1,100}:\d{1,100}:\d{1,100})(\s{1,100}(\+|\-)\d{1,100})?,(|({host}[^,]{1,2000})),alert,reject,([^,]{0,2000},){8}(|({src_ip}[^,]{1,2000})),(|({dest_ip}[^,]{1,2000})),([^,]{0,2000},){14}(|({user}[^,]{1,2000})),(|({failure_reason}[^,]{1,2000}?))\s{0,100},""",
  ]
}
```