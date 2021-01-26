#### Parser Content
```Java
{
Name = kerberos-as
    Vendor = Unix
  Product = Unix
    Lms = Splunk
    DataType = "kerberos-kdc"
    TimeFormat = "epoch_sec"
    Conditions = [ "krb5kdc", "AS_REQ" ]
    Fields = [
      """authtime ({time}\d+),""",
      """\w+ \d+ \d+:\d+:\d+ ({host}[^\s]+)""",
      """AS_REQ .+? ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\s+({outcome}[^:]+)""",
      """AS_REQ.+?(,|:)\s+({user}[^\s]+)@({domain}[^\s]+) for ({kerberos_service}[^/]+)"""
    ]
 }
```