#### Parser Content
```Java
{
Name = zscaler-vpn-end-1
  Vendor = Zscaler
  Product = Zscaler Private Access
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MMM  dd HH:mm:ss yyyy"
  Conditions = [ """"ZPN_STATUS_DISCONNECTED"""", """"Username":""" ]
  Fields = [
    """({time}\w{3}\s{1,100}\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"Hostname":\s{0,100}"({host}[^"]{1,2000})"""",
    """"PublicIP":\s{0,100}"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"Username":\s{0,100}"(({user_email}[^@"\s]{1,2000}@[^\s"]{0,2000})|((({domain}[^@"]{1,2000})@)?({user}[^\s"@]{1,2000}))|({user_fullname}[^"@]{1,2000}))"""",
    """"TotalBytesRx":\s{0,100}({bytes_in}\d{1,100}),""",
    """"TotalBytesTx":\s{0,100}({bytes_out}\d{1,100}),""",
    """"SessionStatus":\s{0,100}"({event_name}[^"]{1,2000})""""
  ]


}
```