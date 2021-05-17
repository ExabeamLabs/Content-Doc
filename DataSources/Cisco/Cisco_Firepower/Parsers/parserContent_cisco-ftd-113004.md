#### Parser Content
```Java
{
Name = cisco-ftd-113004
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """-113004""", """%FTD-""" , """AAA user authentication Successful"""]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s({host}[^\s]{1,2000})""",
    """%FTD-({priority}\d{1,100})-({event_code}\d{1,100})""",
    """server\s{0,100}=\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """-113004:\s{0,100}({event_name}AAA user authentication Successful)"""
    """user\s{0,100}=\s{0,100}(({user_email}[^@]{1,2000}@[^\s]{1,2000})|({user}[^\s]{1,2000}))"""
  ]
}
```