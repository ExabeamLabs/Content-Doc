#### Parser Content
```Java
{
Name = osx-local-logon
  Vendor = Apple
  Product = macOS
  Lms = Splunk
  DataType = "osx-local-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["pam_sm_setcred: storing credential", "exabeam_raw"]
  Fields = ["""exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
            """exabeam_host=({host}[^\s]{1,2000})""",
            """_raw=.+\s({dest_host}[^\s]{1,2000})\s{1,100}(?:-|({process}[^\s]{1,2000}?))\[({logon_id}\d{1,100}).+?\sfor:\s{1,100}({user}[^@]{1,2000})(?:@({domain}[^\s.]{1,2000}))?""",
        """_raw=.+\d\d:\d\d:\d\d\s{1,100}({dest_ip}\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100})"""
           ]
}
}
```