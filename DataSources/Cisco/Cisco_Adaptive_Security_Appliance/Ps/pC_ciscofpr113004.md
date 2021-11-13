#### Parser Content
```Java
{
Name = cisco-fpr-113004
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ """%FTD-auth-6-113004:""", """AAA user authentication Successful""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100} \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """%FTD-\w+?-?({priority}\d{1,100})-({event_code}\d{1,100})""",
    """-113004:\s{1,100}({event_name}AAA user authentication Successful)""",
    """ user\s{0,100}=? ({user}[^\s]{1,2000})""",
    """server =\s{1,100}({dest_ip}[A-Za-z\d.:]{1,2000})"""
    ]


}
```