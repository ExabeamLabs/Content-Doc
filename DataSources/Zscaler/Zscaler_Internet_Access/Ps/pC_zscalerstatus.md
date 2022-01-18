#### Parser Content
```Java
{
Name = zscaler-status
  Vendor = Zscaler
  Product = Zscaler Internet Access
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = ["""SessionStatus""" , """TimestampAuthentication""" , """CertificateCN"""]
  Fields = [
     """({time}\w{3}\s\d{1,100}\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """"SessionStatus":\s{0,100}"({outcome}[^"]{1,2000})"""
     """Username":\s{0,100}"(({user_email}[^@]{1,2000}@[^\s]{0,2000})"|({user}[^\s]{1,2000}))(\s|,!?)"""
     """TotalBytesRx":\s{0,100}({bytes_in}[^,]{1,2000}),""",
     """TotalBytesTx":\s{0,100}({bytes_out}[^,]{1,2000}),""",
     """"PublicIP":\s{0,100}"({src_ip}[^"]{1,2000})""",
     """Hostname"{1,20}:\s{0,100}"{1,20}({host}[^,"]{1,2000})"{0,20

}
```