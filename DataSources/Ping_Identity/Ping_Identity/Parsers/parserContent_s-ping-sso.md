#### Parser Content
```Java
{
Name = s-ping-sso
    Vendor = Ping Identity
    Product = Ping Identity
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """event=SSO""", "status=success"," pfhost=" ]
    Fields = [
    """\sip=(|({src_ip}[a-fA-F\d.:]{1,2000}))\s\w+=""",
    """exabeam_raw=.*?({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\spfhost=(|({host}[^=\s]{1,2000}?))\s\w+=""",
    """\ssubject="(|(({user_email}[^"@\s]{1,2000}@[^"@\s]{1,2000})|({user}[^"]{1,2000})))"""",
    """\sapp=(|({app}[^=]{1,2000}?))\s\w+="""
    ]
  }
```