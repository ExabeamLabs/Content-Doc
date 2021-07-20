#### Parser Content
```Java
{
Name = crowdstrike-config-change
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "config-change"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"Firewall""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":"({time}\d{1,100})""",
      """"event_simpleName":"({activity}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"FirewallRule":"({object}[^"]{1,2000})""",
      """ext_UserName=({user}[^\s"]{1,2000})\s{1,100}(\w+=|$)""",
      """src-account-name":"({account_name}[^"]{1,2000})""",
    ]
    DupFields = ["activity->event_code"]
  }
```