#### Parser Content
```Java
{
Name = aruba-nac-logon
    Vendor = HP
  Product = Aruba Wireless controller
    Lms = Splunk
    DataType = "nac-logon"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = ["User Authentication Successful: username=", "AAA profile=", "exabeam_raw"]
    Fields = [
      """exabeam_raw=({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d\d\d\d)\s{1,100}({host}[^\s]{1,2000})\s{1,100}authmgr\[""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\+[^\s]{1,2000}\s[^\s]{1,2000}\s{1,100}\d{1,100}\s({host}[^\s]{1,2000})\sauthmgr\[({event_code}[^\]]{1,2000})\]""",
      """username=(({domain}[^\\\s\@]{1,2000})\\|({user_type}host)\/)?({user_email}[^\s\@]{1,2000}\@({email_domain}[^\s]{1,2000}))?({src_mac}([0-9a-fA-F]{1,2}[.:-]){5}([0-9a-fA-F]{1,2}))?({user}[^\s]{1,2000})?""",      
      """IP=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """SSID=(N\/A|({network}[^\s]{1,2000}))""",
      """\sauth server=({auth_server}[^\s]{1,2000})""",
   ]
  }
```