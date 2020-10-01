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
     """({time}\w{3}\s\d+\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """"SessionStatus":\s*"({outcome}[^"]+)"""
     """Username":\s*"(({user_email}[^@]+@[^\s]*)"|({user}[^\s]+))(\s|,!?)"""
     """TotalBytesRx":\s*({bytes_in}[^,]+),""",
     """TotalBytesTx":\s*({bytes_out}[^,]+),""",
     """"PublicIP":\s*"({src_ip}[^"]+)""",
     """Hostname"+:\s*"+({host}[^,"]+)"*,""",
     """Platform"+:\s*"+({platform}[^,"]+)"*,""",
     """ClientType"+:\s*"+({client_type}[^,"]+)"*,""",
  ]
}
```