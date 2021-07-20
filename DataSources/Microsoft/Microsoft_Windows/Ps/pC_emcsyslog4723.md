#### Parser Content
```Java
{
Name = emc-syslog-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "__li_source_path=", "An attempt was made to change","""eventid="4723"""" ]
  Fields = [
    """({event_name}An attempt was made to change an account's password)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """__li_source_path="({host}[^"]{1,2000})"""",
    """({event_code}4723)""",
    """Subject.+?Security ID:\s{1,100}({user_sid}.+?)\s{1,100}Account Name""",
    """Subject.+?Account Name:\s{1,100}({user}.+?)\s{1,100}Account Domain""",
    """Account Domain:\s{1,100}({domain}.+?)\s{1,100}Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})""",
    """Target Account.+?Account Name:\s{1,100}({target_user}.+?)\s{1,100}Account Domain:\s{1,100}({target_domain}.+?)\s{1,100}Additional""",
    """keywords="({outcome}[^"]{1,2000})""""]
  DupFields = [ "host->dest_ip" ]
}
```