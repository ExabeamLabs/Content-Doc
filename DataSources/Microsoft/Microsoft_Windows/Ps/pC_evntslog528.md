#### Parser Content
```Java
{
Name = evntslog-528
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  DataType = "windows-528"
  TimeFormat = "E MMM dd HH:mm:ss yyyy"
  Conditions = [ "EvntSLog", "(528)" ]
  Fields = [
    """({event_name}Successful Logon)""",
    """\s{1,100}({time}\w+ \w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}):.+?/Security\s{1,100}\(({event_code}\d{1,100})\)""",
    """Successful Logon:\s{1,100}User Name:\s{1,100}({user}.+?)\s{1,100}Domain:\s{1,100}({domain}[\w.\-]{1,2000})\s{1,100}Logon ID:\s{1,100}\([^,]{1,2000

}
```