#### Parser Content
```Java
{
Name = kerberos-tgs
    Vendor = Unix
  Product = Unix
    Lms = Splunk
    DataType = "kerberos-kdc"
    TimeFormat = "epoch_sec"
    Conditions = [ "krb5kdc", "TGS_REQ", ": ISSUE:" ]
    Fields = [
      """\sauthtime ({time}\d{1,100})""",
      """\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} ({host}[^\s]{1,2000})""",
      """TGS_REQ .+? ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """

}
```