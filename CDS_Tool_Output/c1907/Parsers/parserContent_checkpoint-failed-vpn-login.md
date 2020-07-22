#### Parser Content
```Java
{
Name = checkpoint-failed-vpn-login
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  TimeFormat = "ddMMMyyyy,HH:mm:ss"
  DataType = "failed-vpn-login"
  Conditions = [ """,alert,reject,""" ]
  Fields = [
    """({time}\d+\w+\d\d\d\d,\d+:\d+:\d+)(\s+(\+|\-)\d+)?,(|({host}[^,]+)),alert,reject,([^,]*,){8}(|({src_ip}[^,]+)),(|({dest_ip}[^,]+)),([^,]*,){14}(|({user}[^,]+)),(|({failure_reason}[^,]+?))\s*,""",
  ]
}
```