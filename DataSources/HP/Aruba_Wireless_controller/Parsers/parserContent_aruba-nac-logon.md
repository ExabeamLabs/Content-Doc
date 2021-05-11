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
      """exabeam_raw=({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d\d\d\d)\s{1,100}({host}[^\s]+)\s{1,100}authmgr\[""",
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\+[^\s]+\s[^\s]+\s{1,100}\d{1,100}\s({host}[^\s]+)\sauthmgr\[({event_code}[^\]]+)\]""",
      """username=(({domain}[^\\\s\@]+)\\|({user_type}host)\/)?({user_email}[^\s\@]+\@({email_domain}[^\s]+))?({src_mac}([0-9a-fA-F]{1,2}[.:-]){5}([0-9a-fA-F]{1,2}))?({user}[^\s]+)?""",      
      """IP=({dest_ip}[a-fA-F\d.:]+)""",
      """SSID=(N\/A|({network}[^\s]+))""",
      """\sauth server=({auth_server}[^\s]+)""",
   ]
  }
```