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
    """__li_source_path="({host}[^"]+)"""",
    """({event_code}4723)""",
    """Subject.+?Security ID:\s+({user_sid}.+?)\s+Account Name""",
    """Subject.+?Account Name:\s+({user}.+?)\s+Account Domain""",
    """Account Domain:\s+({domain}.+?)\s+Logon ID:\s+({logon_id}[^\s]+)""",
    """Target Account.+?Account Name:\s+({target_user}.+?)\s+Account Domain:\s+({target_domain}.+?)\s+Additional""",
    """keywords="({outcome}[^"]+)""""]
  DupFields = [ "host->dest_ip" ]
}
```