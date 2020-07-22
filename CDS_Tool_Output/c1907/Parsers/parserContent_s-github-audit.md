#### Parser Content
```Java
{
Name = s-github-audit
  Vendor = GitHub
  Product = GitHub
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "repo_name", "github_audit" ]
  Fields = [
    """"+@timestamp"+:"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"+hostname"+:"+({host}[^"]+)""",
    """"+repo_name"+:"+({object}[^"]+)""",
    """"+program"+:"+({activity}[^"]+)""",
    """"+user_login"+:"+({user}[^"]+)""",
    """"+real_ip"+:"+({src_ip}[^"]+)""",
    """"+pubkey_fingerprint"+:"+({fingerprint}[^"]+)""",
    """({app}github)"""
  ]
}
```