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
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """"SessionStatus":\s{0,100}"({outcome}[^"]+)"""
     """Username":\s{0,100}"(({user_email}[^@]+@[^\s]*)"|({user}[^\s]+))(\s|,!?)"""
     """TotalBytesRx":\s{0,100}({bytes_in}[^,]+),""",
     """TotalBytesTx":\s{0,100}({bytes_out}[^,]+),""",
     """"PublicIP":\s{0,100}"({src_ip}[^"]+)""",
     """Hostname"{1,20}:\s{0,100}"{1,20}({host}[^,"]+)"{0,20}
```