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
      """authtime ({time}\d{1,100}),""",
      """\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[^\s]{1,2000})""",
      """AS_REQ .+? ({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\s{1,100}({outcome}[^:]{1,2000})""",
      """AS_REQ.+?(,|:)\s{1,100}({user}[^\s]{1,2000})@({domain}[^\s]{1,2000}) for ({kerberos_service}[^/]{1,2000})"""
    ]
 

}
```