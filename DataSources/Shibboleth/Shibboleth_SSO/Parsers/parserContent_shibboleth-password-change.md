#### Parser Content
```Java
{
Name = shibboleth-password-change
    Vendor = Shibboleth
    Product = Shibboleth SSO
    Lms = Splunk
    DataType = "password-change"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ """password change from""", """SUCCESS""",  "exabeam_raw" ]
    Fields = [ """exabeam_raw=.*?({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d\d\d\d)\]""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\] ({user}.+?)\s{1,100}password change from ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
  }
```