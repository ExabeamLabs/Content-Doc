#### Parser Content
```Java
{
Name = zscaler-vpn-user
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-user"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """ User Activity zpa-lss:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\w+ ({time}\w+ \d{1,100} \d\d:\d\d:\d\d \d\d\d\d) User Activity zpa-lss:([^,]{0,2000

}
```